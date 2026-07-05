"""Tests for the configuration scanner."""

import tempfile
from pathlib import Path

from draftguard.parser import ConfigParser
from draftguard.scanner import ConfigScanner


class TestConfigScanner:
    """Tests for ConfigScanner."""

    def test_scan_finds_env_files(self, dev_dir):
        scanner = ConfigScanner()
        configs = scanner.scan(dev_dir)

        assert len(configs) >= 2  # .env and config.yaml
        formats = {c.format for c in configs}
        assert "env" in formats
        assert "yaml" in formats

    def test_scan_respects_recursive(self, fixtures_dir):
        scanner = ConfigScanner()

        recursive = scanner.scan(fixtures_dir, recursive=True)
        # 3 envs × at least 2 files each (plus .env.example making it 7)
        assert len(recursive) >= 6

        non_recursive = scanner.scan(fixtures_dir, recursive=False)

    def test_scan_finds_all_envs(self, fixtures_dir):
        scanner = ConfigScanner()
        configs = scanner.scan(fixtures_dir, recursive=True)

        groups = scanner.group_by_environment(configs)
        assert "dev" in groups
        assert "prod" in groups
        # staging .env detected as staging by path
        assert "staging" in groups

    def test_group_by_environment(self, fixtures_dir):
        scanner = ConfigScanner()
        configs = scanner.scan(fixtures_dir, recursive=True)

        groups = scanner.group_by_environment(configs)

        assert len(groups["dev"]) >= 2  # .env + config.yaml
        assert len(groups["prod"]) >= 2
        assert len(groups["staging"]) >= 2

    def test_merge_env_configs(self, dev_dir):
        scanner = ConfigScanner()
        configs = scanner.scan(dev_dir)

        merged = scanner.merge_env_configs(configs)

        # Should have keys from both .env and config.yaml
        assert "DATABASE_URL" in merged.values
        assert "database.url" in merged.values  # from YAML

    def test_merge_empty_raises(self):
        scanner = ConfigScanner()
        with __import__("pytest").raises(ValueError):
            scanner.merge_env_configs([])

    def test_should_skip_node_modules(self, tmp_path):
        scanner = ConfigScanner()
        node_modules = tmp_path / "node_modules" / ".env"
        node_modules.parent.mkdir()
        node_modules.write_text("SKIP=me")

        assert scanner._should_skip(node_modules) is True

    def test_should_skip_package_lock(self, tmp_path):
        scanner = ConfigScanner()
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}")

        assert scanner._should_skip(lock) is True

    def test_scan_empty_directory(self, tmp_path):
        scanner = ConfigScanner()
        configs = scanner.scan(tmp_path)

        assert len(configs) == 0

    def test_scan_with_custom_patterns(self, tmp_path):
        # Create custom config file — this will still be picked up
        # by the scanner but marked as "unknown" by parser
        cfg = tmp_path / "my-config.ini"
        cfg.write_text("[app]\ndebug=true\n")

        scanner = ConfigScanner(patterns=["*.ini"])
        configs = scanner.scan(tmp_path)

        # The ini file is found but has "unknown" format — that's expected
        assert len(configs) == 1
        assert configs[0].format == "unknown"

    def test_scan_skips_dot_git(self, tmp_path):
        scanner = ConfigScanner()
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        env_file = git_dir / ".env"
        env_file.write_text("GIT_DIR=yes")

        configs = scanner.scan(tmp_path)
        # Should not find files in .git
        assert len(configs) == 0

    def test_parser_can_parse_all_fixtures(self, fixtures_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        configs = scanner.scan(fixtures_dir, recursive=True)

        for cfg in configs:
            assert len(cfg.errors) == 0, f"Errors in {cfg.filepath}: {cfg.errors}"
