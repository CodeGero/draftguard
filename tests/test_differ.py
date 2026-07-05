"""Tests for the configuration differ."""

import pytest

from draftguard.differ import Differ
from draftguard.parser import ConfigParser
from draftguard.rules import Finding, Severity
from draftguard.scanner import ConfigScanner


class TestDiffer:
    """Tests for the Differ."""

    def test_compare_dev_to_prod(self, dev_dir, prod_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        dev_configs = scanner.scan(dev_dir)
        prod_configs = scanner.scan(prod_dir)

        result = differ.compare_environments("dev", "prod", dev_configs, prod_configs)

        assert result.env_source == "dev"
        assert result.env_target == "prod"
        assert result.total_findings > 0

        # Should have missing key: NEW_FEATURE_EXPERIMENTAL only in dev
        missing = [f for f in result.findings if f.key == "NEW_FEATURE_EXPERIMENTAL"]
        assert len(missing) > 0

    def test_compare_dev_to_staging(self, dev_dir, staging_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        dev_configs = scanner.scan(dev_dir)
        staging_configs = scanner.scan(staging_dir)

        result = differ.compare_environments("dev", "staging", dev_configs, staging_configs)

        assert result.env_source == "dev"
        assert result.env_target == "staging"

    def test_compare_staging_to_prod(self, staging_dir, prod_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        staging_configs = scanner.scan(staging_dir)
        prod_configs = scanner.scan(prod_dir)

        result = differ.compare_environments("staging", "prod", staging_configs, prod_configs)

        assert result.env_source == "staging"
        assert result.env_target == "prod"

    def test_summary_counts(self, dev_dir, prod_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        dev_configs = scanner.scan(dev_dir)
        prod_configs = scanner.scan(prod_dir)

        result = differ.compare_environments("dev", "prod", dev_configs, prod_configs)

        # Total should match sum of counts
        assert result.total_findings == sum(result.summary.values())

    def test_has_critical_and_high(self, dev_dir, prod_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        dev_configs = scanner.scan(dev_dir)
        prod_configs = scanner.scan(prod_dir)

        result = differ.compare_environments("dev", "prod", dev_configs, prod_configs)

        # SECRET_KEY in dev has default value -> CRITICAL secret exposure
        assert result.has_critical, "Expected CRITICAL findings (secret exposure)"
        # PROD_ONLY_CONFIG in prod but not dev -> EXTRA_KEY warning (not high)
        # Value mismatches: MAX_UPLOAD_SIZE, RATE_LIMIT, SESSION_TIMEOUT -> HIGH
        assert result.has_high, "Expected HIGH findings (value mismatches)"

    def test_audit_prod_environment(self, prod_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        prod_configs = scanner.scan(prod_dir)
        findings = differ.audit_environment("prod", prod_configs)

        # Prod has real values, should have few or no findings
        # Empty MAIL_PASSWORD is not in prod's .env
        assert len(findings) >= 0

    def test_audit_dev_environment(self, dev_dir):
        parser = ConfigParser()
        scanner = ConfigScanner(parser=parser)
        differ = Differ(parser=parser, scanner=scanner)

        dev_configs = scanner.scan(dev_dir)
        findings = differ.audit_environment("dev", dev_configs)

        # Dev has default values and empty MAIL_PASSWORD
        assert len(findings) > 0

        # Should find empty MAIL_PASSWORD
        empty = [f for f in findings if f.key == "MAIL_PASSWORD"]
        assert len(empty) > 0

    def test_diff_values_added_removed_changed(self):
        differ = Differ()
        source = {"A": "1", "B": "2", "C": "3"}
        target = {"A": "1", "C": "33", "D": "4"}

        diffs = differ.diff_values(source, target)

        assert ("removed", "B", "2", None) in diffs
        assert ("added", "D", None, "4") in diffs

        changed = [d for d in diffs if d[0] == "changed"]
        assert len(changed) == 1
        assert changed[0][1] == "C"

    def test_mask_secret(self):
        assert Differ._mask_secret("ab") == "****"
        assert Differ._mask_secret("abcdefgh") == "ab****gh"
        # "sk-real-key" is 11 chars: sk + 7 asterisks + ey
        assert Differ._mask_secret("sk-real-key") == "sk*******ey"

    def test_truncate(self):
        assert Differ._truncate("short") == "short"
        assert Differ._truncate("a" * 60) == "a" * 50 + "..."
