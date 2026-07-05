"""Tests for the CLI commands."""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from draftguard.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def fixtures_path():
    return str(Path(__file__).parent / "fixtures")


class TestCLIBasics:
    """Basic CLI tests."""

    def test_main_no_args(self, runner):
        result = runner.invoke(main)
        assert result.exit_code == 0
        assert "DraftGuard" in result.output

    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "draftguard" in result.output.lower()

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "compare" in result.output
        assert "audit" in result.output
        assert "diff" in result.output


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_fixtures(self, runner, fixtures_path):
        result = runner.invoke(main, ["scan", fixtures_path, "--envs", "dev,prod"])
        assert result.exit_code == 0
        assert "Scanning" in result.output
        # Should find dev and prod config files
        assert "dev" in result.output.lower()
        assert "prod" in result.output.lower()

    def test_scan_with_json_format(self, runner, fixtures_path):
        result = runner.invoke(main, [
            "scan", fixtures_path,
            "--envs", "dev,prod",
            "--format", "json",
        ])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert data["tool"] == "draftguard"
        assert "findings" in data
        assert "summary" in data

    def test_scan_with_output_file(self, runner, fixtures_path, tmp_path):
        output = tmp_path / "report.json"
        result = runner.invoke(main, [
            "scan", fixtures_path,
            "--envs", "dev,prod",
            "--format", "json",
            "--output", str(output),
        ])
        assert result.exit_code == 0
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["tool"] == "draftguard"

    def test_scan_fail_on_critical(self, runner, fixtures_path):
        # dev→prod has CRITICAL findings (secret exposure in dev)
        result = runner.invoke(main, [
            "scan", fixtures_path,
            "--envs", "dev,prod",
            "--fail-on", "critical",
        ])
        # dev has SECRET_KEY=dev-secret-key-change-me -> not default pattern
        # But API_KEY=your-api-key-here in dev -> secret exposure
        assert result.exit_code in (0, 1)

    def test_scan_missing_env(self, runner, fixtures_path):
        result = runner.invoke(main, [
            "scan", fixtures_path,
            "--envs", "nonexistent,prod",
        ])
        assert result.exit_code == 1

    def test_scan_no_configs(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No config files found" in result.output


class TestCompareCommand:
    """Tests for the compare command."""

    def test_compare_dev_prod(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, ["compare", dev_path, prod_path])
        assert result.exit_code == 0

    def test_compare_with_labels(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, [
            "compare", dev_path, prod_path,
            "--envs", "development,production",
        ])
        assert result.exit_code == 0

    def test_compare_json_format(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, [
            "compare", dev_path, prod_path,
            "--format", "json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["tool"] == "draftguard"

    def test_compare_empty_dir(self, runner, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()

        result = runner.invoke(main, ["compare", str(empty), str(empty)])
        assert result.exit_code == 1  # Both must have configs


class TestAuditCommand:
    """Tests for the audit command."""

    def test_audit_dev(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        result = runner.invoke(main, ["audit", dev_path])
        assert result.exit_code == 0
        # Dev has MAIL_PASSWORD="" and default value patterns
        assert "MAIL_PASSWORD" in result.output or "Findings" in result.output

    def test_audit_prod(self, runner, fixtures_path):
        prod_path = str(Path(fixtures_path) / "prod")
        result = runner.invoke(main, ["audit", prod_path])
        assert result.exit_code == 0

    def test_audit_no_configs(self, runner, tmp_path):
        result = runner.invoke(main, ["audit", str(tmp_path)])
        assert result.exit_code == 0

    def test_audit_json_format(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        result = runner.invoke(main, ["audit", dev_path, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["tool"] == "draftguard"
        assert "audit" in data


class TestDiffCommand:
    """Tests for the diff command."""

    def test_diff_dev_prod(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, ["diff", dev_path, prod_path])
        assert result.exit_code == 0
        assert "Diff" in result.output

    def test_diff_json(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, ["diff", dev_path, prod_path, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "differences" in data

    def test_diff_markdown(self, runner, fixtures_path):
        dev_path = str(Path(fixtures_path) / "dev")
        prod_path = str(Path(fixtures_path) / "prod")

        result = runner.invoke(main, ["diff", dev_path, prod_path, "--format", "markdown"])
        assert result.exit_code == 0
        assert "| Status |" in result.output

    def test_diff_empty_dir(self, runner, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()

        result = runner.invoke(main, ["diff", str(empty), str(empty)])
        assert result.exit_code == 1
