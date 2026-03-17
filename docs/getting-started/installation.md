# Installation

## Requirements

- **Python 3.9+** (tested on 3.9–3.14)
- **No external dependencies** — lumen-argus uses only the Python standard library

## Install from PyPI

```bash
pip install lumen-argus
```

## Install from Source

```bash
git clone https://github.com/slima4/lumen-argus.git
cd lumen-argus
pip install -e .
```

## Verify Installation

```bash
lumen-argus --version
# lumen-argus 0.1.0
```

## First Run

Start the proxy — a default config is created automatically on first launch:

```bash
lumen-argus serve
```

This creates `~/.lumen-argus/config.yaml` with sensible defaults:

- Secrets detection: **block** (prevents sending)
- PII detection: **alert** (allows but warns)
- Proprietary detection: **alert**
- Proxy port: **8080**
- Binding: **127.0.0.1** (localhost only)

## Directory Structure

lumen-argus creates the following on first run:

```
~/.lumen-argus/
├── config.yaml                  # Global configuration
├── audit/
│   └── guard-20260317-143000.jsonl  # Audit log (JSONL)
└── logs/
    └── lumen-argus.log          # Application log (rotated)
```
