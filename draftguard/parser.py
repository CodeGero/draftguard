"""Multi-format configuration parser.

Handles: .env, YAML, JSON, TOML, docker-compose.yml (environment sections),
and Kubernetes ConfigMap/Secret YAML files.

Each parser returns a flat Dict[str, str] of config keys to values, along with
metadata about the source file.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

try:
    from dotenv import dotenv_values
except ImportError:
    dotenv_values = None  # type: ignore[assignment]

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class ParsedConfig:
    """A parsed configuration file."""

    filepath: Path
    format: str  # "env", "yaml", "json", "toml", "docker-compose", "k8s-configmap", "k8s-secret"
    env_name: str = "unknown"  # inferred environment name
    values: Dict[str, str] = field(default_factory=dict)
    comments: Dict[str, str] = field(default_factory=dict)  # key -> inline comment
    raw: Dict[str, Any] = field(default_factory=dict)  # original typed values
    errors: List[str] = field(default_factory=list)


class ConfigParser:
    """Parse configuration files of various formats into a flat key-value store."""

    # Patterns for recognizing environment names from file paths
    ENV_PATTERNS: List[Tuple[re.Pattern, str]] = [
        # By filename suffix: .env.production, .env.prod
        (re.compile(r"\.env\.(production|prod)$", re.IGNORECASE), "prod"),
        (re.compile(r"\.env\.(staging|stage)$", re.IGNORECASE), "staging"),
        (re.compile(r"\.env\.(development|dev)$", re.IGNORECASE), "dev"),
        (re.compile(r"\.env\.(local)$", re.IGNORECASE), "local"),
        (re.compile(r"\.env\.example$", re.IGNORECASE), "example"),
        # By directory name: dev/, production/, staging/
        (re.compile(r"(?:^|[\\/])(production|prod)[\\/]", re.IGNORECASE), "prod"),
        (re.compile(r"(?:^|[\\/])(staging|stage)[\\/]", re.IGNORECASE), "staging"),
        (re.compile(r"(?:^|[\\/])(development|dev)[\\/]", re.IGNORECASE), "dev"),
        (re.compile(r"(?:^|[\\/])(local)[\\/]", re.IGNORECASE), "local"),
    ]

    # Patterns for detecting config formats by filename
    FORMAT_DETECTORS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"docker-compose[^/\\]*\.ya?ml$", re.IGNORECASE), "docker-compose"),
        (re.compile(r"configmap[^/\\]*\.ya?ml$", re.IGNORECASE), "k8s-configmap"),
        (re.compile(r"secret[^/\\]*\.ya?ml$", re.IGNORECASE), "k8s-secret"),
        (re.compile(r"\.env(\..*)?$", re.IGNORECASE), "env"),
        (re.compile(r"\.ya?ml$", re.IGNORECASE), "yaml"),
        (re.compile(r"\.json$", re.IGNORECASE), "json"),
        (re.compile(r"\.toml$", re.IGNORECASE), "toml"),
    ]

    # Known keys where values are expected to differ by environment
    EXPECTED_DIFF_KEYS: set = {
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

    @classmethod
    def infer_format(cls, filepath: Path) -> str:
        """Detect config format from filename."""
        fname = filepath.name
        for pattern, fmt in cls.FORMAT_DETECTORS:
            if pattern.search(fname):
                return fmt

        # Fall back to extension detection
        suffix = filepath.suffix.lower()
        if suffix in (".yml", ".yaml"):
            # Read first few lines to detect k8s resources
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    head = "".join(f.readline() for _ in range(10))
                if re.search(r"kind:\s*(ConfigMap|Secret)", head):
                    return "k8s-configmap" if "ConfigMap" in head else "k8s-secret"
            except Exception:
                pass
            return "yaml"
        if suffix == ".json":
            return "json"
        if suffix == ".toml":
            return "toml"
        return "unknown"

    @classmethod
    def infer_environment(cls, filepath: Path) -> str:
        """Infer environment name from file path."""
        path_str = filepath.as_posix()
        for pattern, env in cls.ENV_PATTERNS:
            if pattern.search(path_str):
                return env

        # Check parent directory name
        parent = filepath.parent.name.lower()
        if parent in ("production", "prod"):
            return "prod"
        if parent in ("staging", "stage"):
            return "staging"
        if parent in ("development", "dev"):
            return "dev"
        if parent == "local":
            return "local"

        return "unknown"

    def parse(self, filepath: Path) -> ParsedConfig:
        """Parse a single config file and return a ParsedConfig."""
        fmt = self.infer_format(filepath)
        env = self.infer_environment(filepath)

        result = ParsedConfig(
            filepath=filepath,
            format=fmt,
            env_name=env,
        )

        try:
            if fmt == "env":
                self._parse_env(filepath, result)
            elif fmt == "yaml":
                self._parse_yaml(filepath, result)
            elif fmt == "json":
                self._parse_json(filepath, result)
            elif fmt == "toml":
                self._parse_toml(filepath, result)
            elif fmt in ("docker-compose",):
                self._parse_docker_compose(filepath, result)
            elif fmt in ("k8s-configmap", "k8s-secret"):
                self._parse_k8s(filepath, result)
            else:
                result.errors.append(f"Unknown format: {fmt}")
        except Exception as e:
            result.errors.append(f"Parse error: {e}")

        return result

    def parse_directory(self, directory: Path) -> List[ParsedConfig]:
        """Parse all config files found in a directory tree."""
        results = []
        for filepath in directory.rglob("*"):
            if filepath.is_file() and not filepath.name.startswith("."):
                fmt = self.infer_format(filepath)
                if fmt != "unknown":
                    results.append(self.parse(filepath))
        return results

    # ── Internal parsers ──────────────────────────────────────────────

    def _parse_env(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse .env file using python-dotenv with comment extraction."""
        if dotenv_values is None:
            self._parse_env_fallback(filepath, result)
            return

        try:
            raw = dotenv_values(filepath)
            for key, value in raw.items():
                if value is None:
                    value = ""
                result.values[key] = str(value)
                result.raw[key] = value
            self._extract_env_comments(filepath, result)
        except Exception as e:
            result.errors.append(f"dotenv parse error: {e}")
            self._parse_env_fallback(filepath, result)

    def _parse_env_fallback(self, filepath: Path, result: ParsedConfig) -> None:
        """Fallback .env parser (no python-dotenv)."""
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    result.values[key] = value
                    result.raw[key] = value

    def _extract_env_comments(self, filepath: Path, result: ParsedConfig) -> None:
        """Extract inline comments from .env files."""
        with open(filepath, "r", encoding="utf-8") as f:
            last_comment = ""
            for line in f:
                stripped = line.strip()
                if stripped.startswith("#"):
                    last_comment += stripped[1:].strip() + " "
                    continue
                if "=" in stripped:
                    key = stripped.split("=", 1)[0].strip()
                    if last_comment:
                        result.comments[key] = last_comment.strip()
                    last_comment = ""

    def _parse_yaml(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse YAML file and flatten to key-value pairs."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            self._flatten_dict(data, "", result)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    self._flatten_dict(item, f"[{i}]", result)

    def _parse_json(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse JSON file and flatten to key-value pairs."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            self._flatten_dict(data, "", result)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    self._flatten_dict(item, f"[{i}]", result)

    def _parse_toml(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse TOML file and flatten to key-value pairs."""
        if tomllib is None:
            result.errors.append("tomli/tomllib not available; install tomli for Python <3.11")
            return
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
        self._flatten_dict(data, "", result)

    def _parse_docker_compose(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse docker-compose.yml, extracting environment sections."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return

        services = data.get("services", {})
        for svc_name, svc_def in services.items():
            if not isinstance(svc_def, dict):
                continue
            environment = svc_def.get("environment", {})
            if isinstance(environment, dict):
                for key, value in environment.items():
                    full_key = f"{svc_name}.{key}"
                    result.values[full_key] = str(value) if value is not None else ""
                    result.raw[full_key] = value
            elif isinstance(environment, list):
                for item in environment:
                    if isinstance(item, str) and "=" in item:
                        key, _, value = item.partition("=")
                        full_key = f"{svc_name}.{key}"
                        result.values[full_key] = value
                        result.raw[full_key] = value

    def _parse_k8s(self, filepath: Path, result: ParsedConfig) -> None:
        """Parse Kubernetes ConfigMap or Secret YAML."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return

        # Handle both single resources and List items
        resources = [data]
        if data.get("kind") == "List" and "items" in data:
            resources = data["items"]

        for resource in resources:
            if not isinstance(resource, dict):
                continue
            kind = resource.get("kind", "")
            if kind not in ("ConfigMap", "Secret"):
                continue

            rdata = resource.get("data", {})
            if isinstance(rdata, dict):
                for key, value in rdata.items():
                    result.values[key] = str(value) if value is not None else ""
                    result.raw[key] = value

            # Also handle stringData for Secrets
            string_data = resource.get("stringData", {})
            if isinstance(string_data, dict):
                for key, value in string_data.items():
                    result.values[key] = str(value) if value is not None else ""
                    result.raw[key] = value

    def _flatten_dict(
        self, data: Dict[str, Any], prefix: str, result: ParsedConfig, sep: str = "."
    ) -> None:
        """Recursively flatten a nested dict into dot-notation keys."""
        for key, value in data.items():
            full_key = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                self._flatten_dict(value, f"{full_key}{sep}", result, sep)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._flatten_dict(item, f"{full_key}{sep}{i}{sep}", result, sep)
                    else:
                        result.values[f"{full_key}{sep}{i}"] = self._to_str(item)
                        result.raw[f"{full_key}{sep}{i}"] = item
            else:
                result.values[full_key] = self._to_str(value)
                result.raw[full_key] = value

    @staticmethod
    def _to_str(value: Any) -> str:
        """Convert any value to string representation."""
        if value is None:
            return ""
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        return str(value)

    @classmethod
    def is_expected_diff(cls, key: str) -> bool:
        """Check if a key is expected to differ between environments."""
        upper = key.upper()
        return upper in cls.EXPECTED_DIFF_KEYS
