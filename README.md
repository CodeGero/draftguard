# 🔍 Kryptorious DraftGuard

**Detect environment configuration drift before it causes production incidents.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI version](https://img.shields.io/badge/pypi-1.0.0-green.svg)](https://pypi.org/project/kryptorious-draftguard/)

DraftGuard scans your dev, staging, and production config files and catches mismatches, missing keys, default leakage, and secret exposure **before they break production**.

---

## Quick Start

```bash
pip install kryptorious-draftguard

# Scan current directory comparing dev → prod
draftguard scan .

# Compare specific environments
draftguard scan /app --envs dev,staging,prod

# JSON output for CI/CD pipelines
draftguard scan . --format json --fail-on high

# Audit a single environment for issues
draftguard audit ./prod

# Show detailed key-by-key diff
draftguard diff ./dev ./prod --format markdown
```

## What It Detects

| Severity | Rule | Description |
|---|---|---|
| 🔴 CRITICAL | Missing keys | Key exists in `.env.example` or dev but missing in production |
| 🔴 CRITICAL | Secret exposure | API keys, tokens, passwords using default/placeholder values |
| 🟠 HIGH | Value mismatches | Same key, different values across environments (unexpected) |
| 🟠 HIGH | Default leakage | Production config still using `changeme`/`localhost` defaults |
| 🟡 MEDIUM | Type drift | String in dev but number in prod (or vice versa) |
| ⚠️ WARNING | Extra keys | Keys in production not documented in example files |
| 🔵 INFO | Expected diffs | DATABASE_URL, DEBUG, etc. — flagged but non-blocking |
| 🔵 INFO | Comment drift | Documentation comments differ between environments |

### Smart Detection

- **Knows what's expected**: `DATABASE_URL`, `DEBUG`, `HOST`, `PORT` etc. are flagged as INFO not errors
- **Pattern matching**: Recognizes API keys (`API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `JWT_*`, `ENCRYPTION_*`)
- **Default detection**: Catches `changeme`, `your-*-here`, `localhost`, `127.0.0.1`, `<placeholder>` patterns
- **Type inference**: Integer vs string vs boolean vs URL vs duration

## Supported Formats

- `.env` files (via python-dotenv)
- `.env.example`, `.env.production`, `.env.staging`, `.env.local`
- YAML config files (`config.yaml`, `config.yml`)
- JSON config files (`config.json`, `appsettings.json`)
- TOML config files (`config.toml`)
- Docker Compose `environment:` sections
- Kubernetes ConfigMap and Secret YAML files

## CLI Reference

```
Usage: draftguard [OPTIONS] COMMAND [ARGS]

Commands:
  scan     Scan directory tree for all config files and compare environments
  compare  Compare two specific config directories
  audit    Audit a single environment for issues (empty values, defaults, weak secrets)
  diff     Show detailed key-by-key diff between two config directories

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.
```

### `draftguard scan [DIR]`

```bash
# Basic scan
draftguard scan .

# Multi-environment
draftguard scan /app --envs dev,staging,prod

# JSON output + exit code for CI
draftguard scan . --format json --fail-on critical -o report.json

# Markdown report
draftguard scan . --format markdown -o drift-report.md

# Summary only
draftguard scan . --format summary
```

### `draftguard compare DIR1 DIR2`

```bash
draftguard compare ./dev-configs ./prod-configs
draftguard compare ./dev ./staging --envs development,staging
```

### `draftguard audit [DIR]`

```bash
draftguard audit .              # Auto-detect environment
draftguard audit ./prod --env production
draftguard audit ./prod --fail-on warning
```

### `draftguard diff DIR1 DIR2`

```bash
draftguard diff ./dev ./prod
draftguard diff ./dev ./prod --format json
draftguard diff ./staging ./prod --format markdown
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Config Drift Check

on:
  pull_request:
    paths:
      - '.env*'
      - '**/config.*'
      - 'docker-compose*.yml'
  push:
    branches: [main]

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install DraftGuard
        run: pip install kryptorious-draftguard

      - name: Check config drift
        run: |
          draftguard scan . --envs dev,prod --format json -o draftguard-report.json --fail-on high

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: draftguard-report
          path: draftguard-report.json
```

### GitLab CI

```yaml
drift-check:
  image: python:3.11
  script:
    - pip install kryptorious-draftguard
    - draftguard scan . --envs staging,prod --format json --fail-on critical
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: draftguard
        name: Config Drift Check
        entry: draftguard scan . --fail-on warning
        language: system
        pass_filenames: false
        always_run: true
```

## Programmatic API

```python
from draftguard.parser import ConfigParser
from draftguard.scanner import ConfigScanner
from draftguard.differ import Differ
from draftguard.rules import DriftRules

# Scan and compare
parser = ConfigParser()
scanner = ConfigScanner(parser=parser)
differ = Differ(parser=parser)

dev_configs = scanner.scan(Path("./dev"))
prod_configs = scanner.scan(Path("./prod"))

result = differ.compare_environments("dev", "prod", dev_configs, prod_configs)

print(f"Found {result.total_findings} issues:")
for finding in result.findings:
    print(f"  [{finding.severity.value}] {finding.key}: {finding.message}")

# Audit single environment
findings = differ.audit_environment("prod", prod_configs)

# Custom rules
rules = DriftRules(expected_diff_keys={"MY_CUSTOM_URL"})
differ = Differ(rules=rules)
```

## Example Output

### Table Format (default)

```
╔══════════════════════════════════════════════════╗
║         🔍 KRYPTORIOUS DRAFTGUARD v1.0.0         ║
║   Detect config drift before it causes outages   ║
╚══════════════════════════════════════════════════╝

📂 Scanning: /app
   Found 6 config files across 3 environments

                        Summary
┌───────────┬───────┬──────────┐
│ Severity  │ Count │ Status   │
├───────────┼───────┼──────────┤
│ 🔴 CRITICAL │   3  │ ❌ FAIL  │
│ 🟠 HIGH     │   2  │ ❌ FAIL  │
│ 🟡 MEDIUM   │   1  │ ✅ OK   │
│ ⚠️ WARNING  │   0  │ ✅ OK   │
│ 🔵 INFO     │   5  │ ✅ OK   │
└───────────┴───────┴──────────┘

              Findings (11 issues)
┌───────────┬─────────────────┬──────────────────────┬──────────────────────────────────────┐
│ Severity  │ Category        │ Key                  │ Message                              │
├───────────┼─────────────────┼──────────────────────┼──────────────────────────────────────┤
│ 🔴 CRITICAL │ secret_exposure │ SECRET_KEY           │ Secret key has default value in dev  │
│ 🔴 CRITICAL │ missing_key     │ NEW_FEATURE_EXPER…  │ Key exists in dev but missing in prod│
│ 🔴 CRITICAL │ secret_exposure │ API_KEY              │ Secret key has placeholder in dev    │
│ 🟠 HIGH     │ value_mismatch  │ MAX_UPLOAD_SIZE     │ Value mismatch between dev and prod  │
│ 🟠 HIGH     │ value_mismatch  │ RATE_LIMIT           │ Value mismatch: 100 vs 1000          │
│ 🟡 MEDIUM   │ type_drift      │ PORT                 │ Integer in dev but string in prod    │
│ 🔵 INFO     │ value_mismatch  │ DATABASE_URL         │ Expected difference                  │
└───────────┴─────────────────┴──────────────────────┴──────────────────────────────────────┘
```

---

## 🔥 Premium — Supercharge Your Config Safety

Get the **DraftGuard Premium** license for just **$9** (lifetime, one-time payment):

✅ **Kubernetes-native support** — Helm chart value diffs, Kustomize overlays, sealed secrets validation  
✅ **Custom rule engine** — Write your own drift detection rules in YAML/Python  
✅ **Slack / Discord alerts** — Real-time notifications when drift is detected  
✅ **Team dashboard** — Web UI to track drift across all your projects and environments  
✅ **Historical trends** — Track config changes over time, see drift patterns  
✅ **Encrypted secret scanning** — Validate values against HashiCorp Vault / AWS Secrets Manager  
✅ **Priority support** — Direct access to the Kryptorious engineering team  

👉 **[Get DraftGuard Premium — $9 Lifetime](https://kryptorious.gumroad.com/l/jbvet)**

---

## Development

```bash
git clone https://github.com/kryptorious/draftguard.git
cd draftguard
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=draftguard --cov-report=term-missing

# Run linters
ruff check .
black --check .
```

## License

MIT © Kryptorious

---

<div align="center">

**[Website](https://kryptorious.gumroad.com/l/jbvet)** · **[GitHub](https://github.com/kryptorious/draftguard)** · **[Premium ($9)](https://kryptorious.gumroad.com/l/jbvet)**

Made with ❤️ by the Kryptorious team

</div>
