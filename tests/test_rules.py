"""Tests for the drift detection rules engine."""

from draftguard.rules import (
    DriftRules,
    Finding,
    RuleCategory,
    Severity,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_levels_are_ordered(self):
        assert Severity.CRITICAL.level > Severity.HIGH.level
        assert Severity.HIGH.level > Severity.MEDIUM.level
        assert Severity.MEDIUM.level > Severity.WARNING.level
        assert Severity.WARNING.level > Severity.INFO.level

    def test_emoji(self):
        assert Severity.CRITICAL.emoji == "🔴"
        assert Severity.HIGH.emoji == "🟠"

    def test_finding_to_dict(self):
        finding = Finding(
            category=RuleCategory.MISSING_KEY,
            severity=Severity.CRITICAL,
            key="SECRET_KEY",
            message="Missing in prod",
            env_source="dev",
            env_target="prod",
            value_source="abc",
            suggestion="Add the key",
        )
        d = finding.to_dict()
        assert d["category"] == "missing_key"
        assert d["severity"] == "CRITICAL"
        assert d["key"] == "SECRET_KEY"


class TestDriftRules:
    """Tests for the drift detection engine."""

    def test_missing_key_in_target(self):
        rules = DriftRules()
        source = {"SECRET_KEY": "abc", "DEBUG": "true", "DATABASE_URL": "postgres://localhost/db"}
        target = {"DEBUG": "false"}

        findings = rules.detect(source, target, "dev", "prod")

        missing = [f for f in findings if f.category == RuleCategory.MISSING_KEY]
        assert len(missing) >= 1
        # SECRET_KEY is missing
        secret_missing = [f for f in missing if f.key == "SECRET_KEY"]
        assert len(secret_missing) == 1
        assert secret_missing[0].severity == Severity.CRITICAL

        # DATABASE_URL is an expected diff, but missing is still CRITICAL
        db_missing = [f for f in missing if f.key == "DATABASE_URL"]
        assert len(db_missing) == 1

    def test_extra_key_in_target(self):
        rules = DriftRules()
        source = {"DEBUG": "true"}
        target = {"DEBUG": "false", "PROD_ONLY_CONFIG": "value"}

        findings = rules.detect(source, target, "dev", "prod")

        extra = [f for f in findings if f.category == RuleCategory.EXTRA_KEY]
        assert len(extra) == 1
        assert extra[0].key == "PROD_ONLY_CONFIG"
        assert extra[0].severity == Severity.WARNING

    def test_expected_diff_is_info(self):
        rules = DriftRules()
        source = {"DATABASE_URL": "postgres://localhost/dev", "DEBUG": "true"}
        target = {"DATABASE_URL": "postgres://prod/db", "DEBUG": "true"}

        findings = rules.detect(source, target, "dev", "prod")

        db_findings = [f for f in findings if f.key == "DATABASE_URL"]
        assert len(db_findings) == 1
        assert db_findings[0].severity == Severity.INFO

    def test_value_mismatch_is_high(self):
        rules = DriftRules()
        source = {"MAX_UPLOAD_SIZE": "10485760"}
        target = {"MAX_UPLOAD_SIZE": "104857600"}

        findings = rules.detect(source, target, "dev", "prod")

        mismatch = [f for f in findings if f.category == RuleCategory.VALUE_MISMATCH]
        assert len(mismatch) == 1
        assert mismatch[0].severity == Severity.HIGH
        assert mismatch[0].key == "MAX_UPLOAD_SIZE"

    def test_secret_exposure_with_default_value(self):
        rules = DriftRules()
        source = {"API_KEY": "sk-real-key-12345"}
        target = {"API_KEY": "your-api-key-here"}

        findings = rules.detect(source, target, "dev", "prod")

        secret = [f for f in findings if f.category == RuleCategory.SECRET_EXPOSURE]
        assert len(secret) == 1
        assert secret[0].severity == Severity.CRITICAL
        assert "prod" in secret[0].message.lower()

    def test_secret_exposure_in_dev(self):
        rules = DriftRules()
        source = {"API_KEY": "changeme"}
        target = {"API_KEY": "sk-real-key"}

        findings = rules.detect(source, target, "dev", "prod")

        secret = [f for f in findings if f.category == RuleCategory.SECRET_EXPOSURE]
        assert len(secret) == 1
        assert "dev" in secret[0].message.lower()

    def test_default_leakage_in_prod(self):
        rules = DriftRules()
        source = {"SESSION_TIMEOUT": "3600"}
        target = {"SESSION_TIMEOUT": "changeme"}

        findings = rules.detect(source, target, "dev", "prod")

        leak = [f for f in findings if f.category == RuleCategory.DEFAULT_LEAKAGE]
        assert len(leak) >= 1
        assert any("prod" in f.message.lower() for f in leak)

    def test_type_drift_number_vs_string(self):
        rules = DriftRules()
        # PORT is in EXPECTED_DIFF_KEYS, so use a non-expected key
        source = {"MAX_ITEMS": "100"}
        target = {"MAX_ITEMS": "one-hundred"}

        findings = rules.detect(source, target, "dev", "prod")

        type_drift = [f for f in findings if f.category == RuleCategory.TYPE_DRIFT]
        assert len(type_drift) == 1
        assert type_drift[0].severity == Severity.MEDIUM

    def test_comment_drift(self):
        rules = DriftRules()
        source = {"DEBUG": "true", "API_KEY": "sk-abc"}
        target = {"DEBUG": "false", "API_KEY": "sk-xyz"}
        source_comments = {"DEBUG": "Enable debug mode", "API_KEY": "The API key"}
        target_comments = {"DEBUG": "Disable in production", "API_KEY": "The API key"}

        findings = rules.detect(
            source, target, "dev", "prod",
            source_comments=source_comments,
            target_comments=target_comments,
        )

        comment_drifts = [f for f in findings if f.category == RuleCategory.COMMENT_DRIFT]
        assert any(f.key == "DEBUG" for f in comment_drifts)

    def test_filter_by_severity(self):
        rules = DriftRules()
        findings = [
            Finding(RuleCategory.MISSING_KEY, Severity.CRITICAL, "A", "msg", "dev", "prod"),
            Finding(RuleCategory.EXTRA_KEY, Severity.WARNING, "B", "msg", "dev", "prod"),
            Finding(RuleCategory.COMMENT_DRIFT, Severity.INFO, "C", "msg", "dev", "prod"),
        ]

        filtered = rules.filter_by_severity(findings, Severity.HIGH)
        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL

    def test_no_findings_when_identical(self):
        rules = DriftRules()
        source = {"A": "1", "B": "2", "C": "3"}
        target = {"A": "1", "B": "2", "C": "3"}

        findings = rules.detect(source, target, "dev", "prod")
        assert len(findings) == 0

    def test_empty_configs(self):
        rules = DriftRules()
        source = {}
        target = {}

        findings = rules.detect(source, target, "dev", "prod")
        assert len(findings) == 0

    def test_secret_key_detection_patterns(self):
        rules = DriftRules()
        assert rules._is_secret_key("API_KEY") is True
        assert rules._is_secret_key("SECRET_TOKEN") is True
        assert rules._is_secret_key("DB_PASSWORD") is True
        assert rules._is_secret_key("JWT_SECRET") is True
        assert rules._is_secret_key("ENCRYPTION_KEY") is True
        assert rules._is_secret_key("DATABASE_URL") is False
        assert rules._is_secret_key("DEBUG") is False

    def test_default_value_detection(self):
        rules = DriftRules()
        assert rules._is_default_value("changeme") is True
        assert rules._is_default_value("changeme123") is True
        assert rules._is_default_value("your-api-key-here") is True
        assert rules._is_default_value("localhost") is True
        assert rules._is_default_value("127.0.0.1") is True
        assert rules._is_default_value("<your_key>") is True
        assert rules._is_default_value("sk-real-key-abc") is False
        assert rules._is_default_value("") is True
