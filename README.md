# draftguard

> Environment configuration drift detection across dev/staging/prod.

[![PyPI](https://img.shields.io/pypi/v/kryptorious-draftguard)](https://pypi.org/project/kryptorious-draftguard/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Part of the [Kryptorious developer toolkit](https://kryptorious.gumroad.com/l/jbvet) — 31 open-source tools, one $9 lifetime license.

## Install

```bash
pip install kryptorious-draftguard
```

## Quickstart

```bash
draftguard compare ./dev ./prod
# -> reports missing keys, value mismatches, type drift
```

## Commands

| Command | Description |
|---------|-------------|
| `draftguard audit` | Audit a single environment for config issues. |
| `draftguard compare dirA dirB` | Compare config files from two directories. |
| `draftguard diff env1 env2` | Key-by-key diff between two config directories. |
| `draftguard scan` | Scan a tree for config files and compare environments. |



## License

MIT — free for personal and commercial use. The $9 lifetime license adds DevFlow Premium (multi-environment CI/CD, approval gates, infrastructure-as-code). Get it at [kryptorious.gumroad.com/l/jbvet](https://kryptorious.gumroad.com/l/jbvet).


---

**Part of the Kryptorious developer-tools suite.** Get the full bundle with DevFlow Premium (multi-env CI, approval gates, infra-as-code): 👉 https://codegero.github.io/store/

---

**Part of the Kryptorious developer-tools suite.** Get the full bundle with DevFlow Premium (multi-env CI, approval gates, infra-as-code): 👉 https://codegero.github.io/store/