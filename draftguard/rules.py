"""Drift detection rules and severity classification.

Defines the rules engine that analyzes configuration differences between
environments and assigns severity levels to each finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class Severity(Enum):
    """Severity levels for drift findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARNING = "WARNING"
    INFO = "INFO"

    @property
    def level(self) -> int:
        """Numeric level for comparison (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.WARNING: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def color(self) -> str:
        """Rich color name for console output."""
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.WARNING: "dark_orange",
            Severity.INFO: "blue",
        }[self]

    @property
    def emoji(self) -> str:
        """Emoji for each severity level."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.WARNING: "⚠️",
            Severity.INFO: "🔵",
        }[self]


class RuleCategory(Enum):
    """Categories for drift detection rules."""

    MISSING_KEY = "missing_key"
    EXTRA_KEY = "extra_key"
    VALUE_MISMATCH = "value_mismatch"
    TYPE_DRIFT = "type_drift"
    DEFAULT_LEAKAGE = "default_leakage"
    SECRET_EXPOSURE = "secret_exposure"
    COMMENT_DRIFT = "comment_drift"


@dataclass
class Finding:
    """A single drift detection finding."""

    category: RuleCategory
    severity: Severity
    key: str
    message: str
    env_source: str  # e.g., "dev"
    env_target: str  # e.g., "prod"
    value_source: Optional[str] = None
    value_target: Optional[str] = None
    file_source: Optional[str] = None
    file_target: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "key": self.key,
            "message": self.message,
            "env_source": self.env_source,
            "env_target": self.env_target,
            "value_source": self.value_source,
            "value_target": self.value_target,
            "file_source": self.file_source,
            "file_target": self.file_target,
            "suggestion": self.suggestion,
        }


class DriftRules:
    """Engine for detecting configuration drift between environments."""

    # Patterns for detecting secrets/credentials
    SECRET_KEY_PATTERNS: List[re.Pattern] = [
        re.compile(r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth|credential)"),
        re.compile(r"(?i)(private[_-]?key|access[_-]?key|jwt[_-]?secret|encryption[_-]?key)"),
        re.compile(r"(?i)(db[_-]?pass|database[_-]?password|pg[_-]?pass|mysql[_-]?pass)"),
    ]

    # Patterns for detecting default/placeholder values
    DEFAULT_VALUE_PATTERNS: List[re.Pattern] = [
        re.compile(r"^(changeme|change_me|todo|fixme|xxx|your-|my-|example|sample|test)",
                   re.IGNORECASE),
        re.compile(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0)$"),
        re.compile(r"^<.*>$"),  # Placeholder like <your_key_here>
    ]

    # Patterns for detecting URLs/hostnames (expected to differ)
    URL_PATTERN = re.compile(r"^(https?://|postgres(ql)?://|mysql://|redis://|mongodb://|amqp://)")

    # Keys expected to differ between environments
    EXPECTED_DIFF_KEYS: Set[str] = {
        "DATABASE_URL",
        "DATABASE_HOST",
        "DATABASE_PORT",
        "DATABASE_NAME",
        "REDIS_URL",
        "REDIS_HOST",
        "REDIS_PORT",
        "API_URL",
        "BASE_URL",
        "APP_URL",
        "SITE_URL",
        "HOST",
        "PORT",
        "BIND",
        "DEBUG",
        "LOG_LEVEL",
        "NODE_ENV",
        "ENV",
        "ENVIRONMENT",
        "APP_ENV",
        "DJANGO_SETTINGS_MODULE",
        "FLASK_ENV",
        "RAILS_ENV",
        "RACK_ENV",
        "ALLOWED_HOSTS",
        "CORS_ORIGINS",
        "SENTRY_DSN",
        "SENTRY_ENVIRONMENT",
        "DD_ENV",
        "DD_SERVICE",
    }

    # Boolean-ish values (DEBUG, feature flags)
    BOOLEAN_VALUES: Set[str] = {"true", "false", "yes", "no", "1", "0", "on", "off", "enabled",
                                "disabled"}

    def __init__(self, expected_diff_keys: Optional[Set[str]] = None):
        self.expected_diff_keys = expected_diff_keys or self.EXPECTED_DIFF_KEYS

    def detect(
        self,
        source: Dict[str, str],
        target: Dict[str, str],
        env_source: str = "dev",
        env_target: str = "prod",
        source_comments: Optional[Dict[str, str]] = None,
        target_comments: Optional[Dict[str, str]] = None,
        file_source: Optional[str] = None,
        file_target: Optional[str] = None,
    ) -> List[Finding]:
        """Run all drift detection rules on a pair of config maps.

        Args:
            source: Config key-values from the source environment (e.g., dev).
            target: Config key-values from the target environment (e.g., prod).
            env_source: Name of source environment.
            env_target: Name of target environment.
            source_comments: Optional comments from source.
            target_comments: Optional comments from target.
            file_source: Optional source file path.
            file_target: Optional target file path.

        Returns:
            List of drift findings.
        """
        findings: List[Finding] = []

        source_keys = set(source.keys())
        target_keys = set(target.keys())
        all_keys = source_keys | target_keys

        for key in sorted(all_keys):
            sv = source.get(key)
            tv = target.get(key)

            # 1. Missing keys (CRITICAL)
            if key in source_keys and key not in target_keys:
                if not self._is_excluded_key(key):
                    findings.append(Finding(
                        category=RuleCategory.MISSING_KEY,
                        severity=Severity.CRITICAL,
                        key=key,
                        message=f"Key '{key}' exists in {env_source} but is missing in {env_target}",
                        env_source=env_source,
                        env_target=env_target,
                        value_source=sv,
                        file_source=file_source,
                        file_target=file_target,
                        suggestion=f"Add '{key}' to {env_target} configuration",
                    ))
                continue

            # 2. Extra keys (WARNING)
            if key in target_keys and key not in source_keys:
                findings.append(Finding(
                    category=RuleCategory.EXTRA_KEY,
                    severity=Severity.WARNING,
                    key=key,
                    message=f"Key '{key}' exists in {env_target} but is undocumented (not in "
                            f"{env_source})",
                    env_source=env_source,
                    env_target=env_target,
                    value_target=tv,
                    file_source=file_source,
                    file_target=file_target,
                    suggestion=f"Document '{key}' in {env_source} or remove from {env_target}",
                ))
                continue

            # Both have the key — compare values
            if sv is None and tv is None:
                continue

            if sv is not None and tv is not None and sv != tv:
                # 3. Secret exposure (CRITICAL) — check BEFORE expected diff
                secret_finding = self._check_secret_exposure(key, sv, tv, env_source, env_target,
                                                             file_source, file_target)
                if secret_finding:
                    findings.append(secret_finding)
                    continue

                # 4. Default leakage (HIGH)
                default_finding = self._check_default_leakage(key, sv, tv, env_source, env_target,
                                                              file_source, file_target)
                if default_finding:
                    findings.append(default_finding)
                    continue

                # 5. Expected diffs (INFO)
                if self._is_expected_diff(key):
                    findings.append(Finding(
                        category=RuleCategory.VALUE_MISMATCH,
                        severity=Severity.INFO,
                        key=key,
                        message=f"Expected difference: '{key}' differs between {env_source} and "
                                f"{env_target}",
                        env_source=env_source,
                        env_target=env_target,
                        value_source=sv,
                        value_target=tv,
                        file_source=file_source,
                        file_target=file_target,
                    ))
                    continue

                # 6. Type drift (MEDIUM)
                type_finding = self._check_type_drift(key, sv, tv, env_source, env_target,
                                                      file_source, file_target)
                if type_finding:
                    findings.append(type_finding)
                    continue

                # 7. Generic value mismatch (HIGH)
                findings.append(Finding(
                    category=RuleCategory.VALUE_MISMATCH,
                    severity=Severity.HIGH,
                    key=key,
                    message=f"Value mismatch: '{key}' differs between {env_source} and {env_target}",
                    env_source=env_source,
                    env_target=env_target,
                    value_source=sv,
                    value_target=tv,
                    file_source=file_source,
                    file_target=file_target,
                    suggestion=f"Review if '{key}' should differ between environments",
                ))

        # 8. Comment drift (INFO) — check for comment differences
        if source_comments and target_comments:
            comment_findings = self._check_comment_drift(
                source_comments, target_comments, all_keys, env_source, env_target,
                file_source, file_target
            )
            findings.extend(comment_findings)

        return findings

    def _is_expected_diff(self, key: str) -> bool:
        """Check if a key is expected to differ between environments."""
        upper = key.upper()
        # Direct match
        if upper in self.expected_diff_keys:
            return True
        # Pattern match (e.g., DATABASE_URL_SLAVE)
        for base in self.expected_diff_keys:
            if upper.startswith(base):
                return True
        return False

    def _is_excluded_key(self, key: str) -> bool:
        """Check if a missing key should be excluded from reporting."""
        # Skip keys that look like file-specific local overrides
        local_patterns = [
            re.compile(r"(?i)^local_"),
            re.compile(r"(?i)_local$"),
        ]
        for pat in local_patterns:
            if pat.search(key):
                return True
        return False

    def _is_secret_key(self, key: str) -> bool:
        """Check if a key looks like it holds a secret."""
        for pattern in self.SECRET_KEY_PATTERNS:
            if pattern.search(key):
                return True
        return False

    def _is_default_value(self, value: str) -> bool:
        """Check if a value looks like a default/placeholder."""
        if not value:
            return True
        for pattern in self.DEFAULT_VALUE_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def _check_secret_exposure(
        self,
        key: str,
        sv: str,
        tv: str,
        env_source: str,
        env_target: str,
        file_source: Optional[str],
        file_target: Optional[str],
    ) -> Optional[Finding]:
        """Check if a secret key uses a default/placeholder value."""
        if not self._is_secret_key(key):
            return None

        # Check if either environment has a default value
        for env_name, value in [(env_source, sv), (env_target, tv)]:
            if self._is_default_value(value):
                return Finding(
                    category=RuleCategory.SECRET_EXPOSURE,
                    severity=Severity.CRITICAL,
                    key=key,
                    message=f"Secret key '{key}' has a default/placeholder value in {env_name}",
                    env_source=env_source,
                    env_target=env_target,
                    value_source=sv,
                    value_target=tv,
                    file_source=file_source,
                    file_target=file_target,
                    suggestion=f"Replace default value for '{key}' in {env_name} with a real "
                               f"secret, or use a secret manager",
                )

        return None

    def _check_default_leakage(
        self,
        key: str,
        sv: str,
        tv: str,
        env_source: str,
        env_target: str,
        file_source: Optional[str],
        file_target: Optional[str],
    ) -> Optional[Finding]:
        """Check if production value matches a default/example value from dev."""
        if self._is_default_value(tv) and not self._is_default_value(sv):
            return Finding(
                category=RuleCategory.DEFAULT_LEAKAGE,
                severity=Severity.HIGH,
                key=key,
                message=f"'{key}' in {env_target} still uses a default value while "
                        f"{env_source} has a real value",
                env_source=env_source,
                env_target=env_target,
                value_source=sv,
                value_target=tv,
                file_source=file_source,
                file_target=file_target,
                suggestion=f"Set proper {env_target} value for '{key}'",
            )

        # Check if both match a known default pattern
        if self._is_default_value(sv) and self._is_default_value(tv):
            return Finding(
                category=RuleCategory.DEFAULT_LEAKAGE,
                severity=Severity.MEDIUM,
                key=key,
                message=f"'{key}' has a default placeholder value in both {env_source} and "
                        f"{env_target}",
                env_source=env_source,
                env_target=env_target,
                value_source=sv,
                value_target=tv,
                file_source=file_source,
                file_target=file_target,
                suggestion=f"Set real values for '{key}' in both environments",
            )

        return None

    def _check_type_drift(
        self,
        key: str,
        sv: str,
        tv: str,
        env_source: str,
        env_target: str,
        file_source: Optional[str],
        file_target: Optional[str],
    ) -> Optional[Finding]:
        """Check if values have different types across environments."""
        sv_type = self._infer_type(sv)
        tv_type = self._infer_type(tv)

        if sv_type != tv_type and sv_type != "unknown" and tv_type != "unknown":
            return Finding(
                category=RuleCategory.TYPE_DRIFT,
                severity=Severity.MEDIUM,
                key=key,
                message=f"Type drift: '{key}' is {sv_type} in {env_source} but {tv_type} in "
                        f"{env_target}",
                env_source=env_source,
                env_target=env_target,
                value_source=sv,
                value_target=tv,
                file_source=file_source,
                file_target=file_target,
                suggestion=f"Ensure '{key}' has consistent type across environments",
            )

        return None

    def _check_comment_drift(
        self,
        source_comments: Dict[str, str],
        target_comments: Dict[str, str],
        all_keys: Set[str],
        env_source: str,
        env_target: str,
        file_source: Optional[str],
        file_target: Optional[str],
    ) -> List[Finding]:
        """Check for differences in documentation comments."""
        findings = []
        for key in all_keys:
            sc = source_comments.get(key, "")
            tc = target_comments.get(key, "")
            if sc != tc:
                findings.append(Finding(
                    category=RuleCategory.COMMENT_DRIFT,
                    severity=Severity.INFO,
                    key=key,
                    message=f"Comment for '{key}' differs between {env_source} and {env_target}",
                    env_source=env_source,
                    env_target=env_target,
                    value_source=sc,
                    value_target=tc,
                    file_source=file_source,
                    file_target=file_target,
                ))
        return findings

    def _infer_type(self, value: str) -> str:
        """Infer the type of a string value."""
        if not value:
            return "empty"
        if value.lower() in self.BOOLEAN_VALUES:
            return "boolean"
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return "integer"
        try:
            float(value)
            return "float"
        except ValueError:
            pass
        if self.URL_PATTERN.match(value):
            return "url"
        if re.match(r"^\d+[mMhHsS]$", value):
            return "duration"
        return "string"

    def filter_by_severity(
        self, findings: List[Finding], min_severity: Severity
    ) -> List[Finding]:
        """Filter findings to only those at or above a minimum severity."""
        return [f for f in findings if f.severity.level >= min_severity.level]

    def filter_by_category(
        self, findings: List[Finding], categories: List[RuleCategory]
    ) -> List[Finding]:
        """Filter findings by rule category."""
        cat_set = set(categories)
        return [f for f in findings if f.category in cat_set]
