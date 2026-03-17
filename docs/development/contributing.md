# Contributing

## Development Setup

```bash
git clone https://github.com/slima4/lumen-argus.git
cd lumen-argus
pip install -e .
```

### Documentation

```bash
pip install -e ".[docs]"
mkdocs serve  # http://localhost:8000
```

## Running Tests

```bash
# Run all tests
python3 -m unittest discover -v tests/

# Run a single test file
python3 -m unittest tests/test_secrets_detector.py

# Run a single test
python3 -m unittest tests.test_secrets_detector.TestSecretsDetector.test_aws_access_key
```

All tests must pass before submitting a pull request.

## Code Style

### Python Version

- Target Python 3.9+ (tested 3.9–3.14)
- Use type comments (`# type: List[str]`) instead of annotations for 3.8 compatibility in core modules

### Zero Dependencies

**The Community Edition must be Python stdlib only.** This is a core differentiator. No external packages — not even for YAML parsing (we bundle a minimal parser in `config.py`).

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(detection): add custom regex rules in config
fix(proxy): support custom CA bundles for corporate proxies
refactor(cli): make signal handlers async-signal-safe
test(logging): add tests for log_utils and logging config validation
docs(readme): add application logging section
```

### Security Invariants

These must never be violated:

1. **`Finding.matched_value` never written to disk** — not in audit logs, app logs, metrics, or baselines
2. **Proxy binds to `127.0.0.1` only** — enforced by runtime assertion
3. **File permissions `0o600`** — all log files, audit files
4. **No external dependencies** in community edition

## Project Structure

```
lumen_argus/
├── cli.py              # CLI entry point, arg parsing, serve lifecycle
├── proxy.py            # HTTP proxy server (ThreadingHTTPServer)
├── pipeline.py         # Scan pipeline: extract → detect → evaluate
├── extractor.py        # Parse Anthropic/OpenAI/Gemini JSON
├── provider.py         # Provider auto-detection and routing
├── scanner.py          # Offline file scanning (scan command)
├── config.py           # Config loading + bundled YAML parser
├── policy.py           # Action evaluation (block > alert > log)
├── models.py           # Shared dataclasses
├── detectors/
│   ├── __init__.py     # BaseDetector ABC
│   ├── secrets.py      # 34+ regex patterns + entropy
│   ├── pii.py          # 8 patterns with validators
│   ├── proprietary.py  # File patterns + keywords
│   └── custom.py       # User-defined regex rules
├── patterns/
│   ├── secrets_patterns.py
│   └── pii_patterns.py
├── allowlist.py        # Allowlist matching (exact + glob)
├── audit.py            # Thread-safe JSONL audit logger
├── baseline.py         # Baseline file for known findings
├── pool.py             # Connection pooling + SSL context
├── stats.py            # Session statistics + Prometheus metrics
├── log_utils.py        # Logging setup, sanitization, config diff
├── display.py          # Terminal output formatting
├── actions.py          # Block/SSE response builders
└── extensions.py       # Plugin registry (entry points)
```
