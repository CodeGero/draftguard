"""Configuration file scanner.

Discovers all config files in a directory tree, groups them by environment,
and returns parsed configs ready for comparison.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Set

from .parser import ConfigParser, ParsedConfig


class ConfigScanner:
    """Scans a directory tree for configuration files."""

    # Config file glob patterns to scan
    DEFAULT_PATTERNS: List[str] = [
        ".env",
        ".env.*",
        "*.env",
        "config.yaml",
        "config.yml",
        "config.json",
        "config.toml",
        "appsettings.json",
        "appsettings.*.json",
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.*.yml",
        "docker-compose.*.yaml",
        "*configmap*.yaml",
        "*configmap*.yml",
        "*secret*.yaml",
        "*secret*.yml",
    ]

    # Directories to skip
    SKIP_DIRS: Set[str] = {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".tox",
        ".venv",
        "venv",
        "env",
        ".env",
        "dist",
        "build",
        ".idea",
        ".vscode",
    }

    # Files to skip
    SKIP_FILES: Set[str] = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
    }

    def __init__(
        self,
        patterns: Optional[List[str]] = None,
        skip_dirs: Optional[Set[str]] = None,
        skip_files: Optional[Set[str]] = None,
        parser: Optional[ConfigParser] = None,
    ):
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.skip_dirs = skip_dirs or self.SKIP_DIRS
        self.skip_files = skip_files or self.SKIP_FILES
        self.parser = parser or ConfigParser()

    def scan(self, root: Path, recursive: bool = True) -> List[ParsedConfig]:
        """Scan a directory tree for config files.

        Args:
            root: Root directory to scan.
            recursive: Whether to recurse into subdirectories.

        Returns:
            List of parsed config files.
        """
        configs: List[ParsedConfig] = []
        seen: Set[Path] = set()

        for pattern in self.patterns:
            glob_method = root.rglob if recursive else root.glob
            for filepath in glob_method(pattern):
                filepath = filepath.resolve()
                if not filepath.is_file():
                    continue
                # Only skip dotfiles that are NOT config files (.env is fine)
                if filepath.name.startswith(".") and not self._is_known_dotfile(filepath.name):
                    continue
                if filepath in seen:
                    continue
                if self._should_skip(filepath):
                    continue
                seen.add(filepath)

                parsed = self.parser.parse(filepath)
                configs.append(parsed)

        # Sort for deterministic output
        configs.sort(key=lambda c: (c.env_name, c.filepath))
        return configs

    def group_by_environment(self, configs: List[ParsedConfig]) -> Dict[str, List[ParsedConfig]]:
        """Group scanned configs by environment name.

        Returns:
            Dict mapping env name -> list of ParsedConfig.
        """
        groups: Dict[str, List[ParsedConfig]] = {}
        for cfg in configs:
            env = cfg.env_name
            if env not in groups:
                groups[env] = []
            groups[env].append(cfg)
        return groups

    def merge_env_configs(self, configs: List[ParsedConfig]) -> ParsedConfig:
        """Merge multiple configs from the same environment into one.

        Later configs override earlier ones for duplicate keys.
        """
        if not configs:
            raise ValueError("No configs to merge")

        merged = ParsedConfig(
            filepath=configs[0].filepath.parent,
            format="merged",
            env_name=configs[0].env_name,
        )

        for cfg in configs:
            merged.values.update(cfg.values)
            merged.raw.update(cfg.raw)
            merged.comments.update(cfg.comments)
            merged.errors.extend(cfg.errors)

        return merged

    @staticmethod
    def _is_known_dotfile(name: str) -> bool:
        """Check if a dotfile is a known config file we want to scan."""
        known = {".env", ".env.example", ".env.production", ".env.staging",
                 ".env.development", ".env.local", ".env.prod", ".env.dev",
                 ".env.stage"}
        if name in known:
            return True
        if name.startswith(".env."):
            return True
        return False

    def _should_skip(self, filepath: Path) -> bool:
        """Check if a file should be skipped."""
        # Check parent directories only (not the filename itself)
        for part in filepath.parent.parts:
            if part in self.skip_dirs:
                return True

        # Check filename
        if filepath.name in self.skip_files:
            return True

        return False
