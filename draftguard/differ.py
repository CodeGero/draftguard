"""Configuration differ — compare parsed configs across environments.

The Differ orchestrates the comparison of config key-value pairs from two
or more environments, running the drift detection rules engine and producing
findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .parser import ConfigParser, ParsedConfig
from .rules import DriftRules, Finding, RuleCategory, Severity
from .scanner import ConfigScanner


@dataclass
class EnvironmentConfig:
    """Aggregated configuration for a single environment."""

    name: str
    configs: List[ParsedConfig] = field(default_factory=list)
    merged: Optional[Dict[str, str]] = None
    merged_raw: Optional[Dict[str, object]] = None
    merged_comments: Optional[Dict[str, str]] = None

    def merge(self) -> Dict[str, str]:
        """Merge all configs in this environment into a single flat dict."""
        merged: Dict[str, str] = {}
        merged_raw: Dict[str, object] = {}
        merged_comments: Dict[str, str] = {}

        for cfg in self.configs:
            merged.update(cfg.values)
            merged_raw.update(cfg.raw)
            merged_comments.update(cfg.comments)

        self.merged = merged
        self.merged_raw = merged_raw
        self.merged_comments = merged_comments

        return merged


@dataclass
class ComparisonResult:
    """Result of comparing two environments."""

    env_source: str
    env_target: str
    findings: List[Finding] = field(default_factory=list)
    configs_source: List[ParsedConfig] = field(default_factory=list)
    configs_target: List[ParsedConfig] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    @property
    def has_critical(self) -> bool:
        return self.summary.get("CRITICAL", 0) > 0

    @property
    def has_high(self) -> bool:
        return self.summary.get("HIGH", 0) > 0

    @property
    def total_findings(self) -> int:
        return sum(self.summary.values())


class Differ:
    """Compare configuration between environments and detect drift."""

    def __init__(
        self,
        rules: Optional[DriftRules] = None,
        parser: Optional[ConfigParser] = None,
        scanner: Optional[ConfigScanner] = None,
    ):
        self.rules = rules or DriftRules()
        self.parser = parser or ConfigParser()
        self.scanner = scanner or ConfigScanner(parser=self.parser)

    def compare_environments(
        self,
        source: str,
        target: str,
        source_configs: List[ParsedConfig],
        target_configs: List[ParsedConfig],
    ) -> ComparisonResult:
        """Compare two environments' configurations.

        Args:
            source: Source environment name (e.g., 'dev').
            target: Target environment name (e.g., 'prod').
            source_configs: Parsed configs from source.
            target_configs: Parsed configs from target.

        Returns:
            ComparisonResult with all findings.
        """
        # Merge configs within each env
        source_env = EnvironmentConfig(name=source, configs=source_configs)
        target_env = EnvironmentConfig(name=target, configs=target_configs)
        source_merged = source_env.merge()
        target_merged = target_env.merge()

        # File paths for context
        file_source = self._file_list_str(source_configs)
        file_target = self._file_list_str(target_configs)

        # Run rules
        findings = self.rules.detect(
            source=source_merged,
            target=target_merged,
            env_source=source,
            env_target=target,
            source_comments=source_env.merged_comments,
            target_comments=target_env.merged_comments,
            file_source=file_source,
            file_target=file_target,
        )

        # Build summary
        summary: Dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            summary[sev] = summary.get(sev, 0) + 1

        return ComparisonResult(
            env_source=source,
            env_target=target,
            findings=findings,
            configs_source=source_configs,
            configs_target=target_configs,
            summary=summary,
        )

    def audit_environment(
        self,
        env_name: str,
        configs: List[ParsedConfig],
    ) -> List[Finding]:
        """Audit a single environment for issues without comparison.

        Checks for:
        - Empty values
        - Default/placeholder values
        - Secret keys with suspicious values
        """
        env = EnvironmentConfig(name=env_name, configs=configs)
        merged = env.merge()

        findings: List[Finding] = []
        file_str = self._file_list_str(configs)

        for key, value in sorted(merged.items()):
            # Empty values
            if not value or value.strip() == "":
                findings.append(Finding(
                    category=RuleCategory.MISSING_KEY,
                    severity=Severity.WARNING,
                    key=key,
                    message=f"Key '{key}' has empty value in {env_name}",
                    env_source=env_name,
                    env_target=env_name,
                    value_source=value,
                    file_source=file_str,
                    suggestion=f"Set a value for '{key}' in {env_name}",
                ))
                continue

            # Default/placeholder values
            if self.rules._is_default_value(value):
                findings.append(Finding(
                    category=RuleCategory.DEFAULT_LEAKAGE,
                    severity=Severity.HIGH,
                    key=key,
                    message=f"Key '{key}' uses a default/placeholder value in {env_name}: "
                            f"'{self._truncate(value)}'",
                    env_source=env_name,
                    env_target=env_name,
                    value_source=value,
                    file_source=file_str,
                    suggestion=f"Replace default value for '{key}' with a proper value",
                ))

            # Secret keys with potentially exposed values
            if self.rules._is_secret_key(key):
                if len(value) < 10 and not value.startswith("$"):
                    findings.append(Finding(
                        category=RuleCategory.SECRET_EXPOSURE,
                        severity=Severity.CRITICAL,
                        key=key,
                        message=f"Secret key '{key}' has a short/weak value in {env_name}",
                        env_source=env_name,
                        env_target=env_name,
                        value_source=self._mask_secret(value),
                        file_source=file_str,
                        suggestion=f"Use a strong secret for '{key}' or reference a secret manager",
                    ))

        return findings

    def diff_values(
        self,
        source: Dict[str, str],
        target: Dict[str, str],
        env_source: str = "source",
        env_target: str = "target",
    ) -> List[Tuple[str, str, Optional[str], Optional[str]]]:
        """Show detailed diff between two config maps.

        Returns:
            List of (status, key, source_value, target_value) where status is
            'added', 'removed', or 'changed'.
        """
        results: List[Tuple[str, str, Optional[str], Optional[str]]] = []
        all_keys = sorted(set(source.keys()) | set(target.keys()))

        for key in all_keys:
            sv = source.get(key)
            tv = target.get(key)
            if key in source and key not in target:
                results.append(("removed", key, sv, None))
            elif key in target and key not in source:
                results.append(("added", key, None, tv))
            elif sv != tv:
                results.append(("changed", key, sv, tv))

        return results

    @staticmethod
    def _file_list_str(configs: List[ParsedConfig]) -> str:
        """Format a list of config file paths for display."""
        return ", ".join(str(c.filepath) for c in configs[:3])

    @staticmethod
    def _truncate(value: str, max_len: int = 50) -> str:
        """Truncate a value for display."""
        if len(value) <= max_len:
            return value
        return value[:max_len] + "..."

    @staticmethod
    def _mask_secret(value: str) -> str:
        """Mask a secret value for safe display."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
