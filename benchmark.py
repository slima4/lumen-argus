#!/usr/bin/env python3
"""Performance benchmark for lumen-argus scan pipeline.

Measures scanning overhead against the <50ms target using realistic
AI API request payloads at various sizes.

Usage:
    python3 benchmark.py
    python3 benchmark.py --iterations 200
    python3 benchmark.py --payload large
"""

import argparse
import json
import random
import string
import statistics
import time
from typing import List, Tuple

from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.allowlist import AllowlistMatcher


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

def _random_code(size: int) -> str:
    """Generate realistic-looking Python code of approximately `size` bytes."""
    snippets = [
        'def process_request(self, data: dict) -> dict:\n'
        '    """Process incoming API request."""\n'
        '    validated = self._validate(data)\n'
        '    result = self._transform(validated)\n'
        '    self.logger.info("Processed request %s", data.get("id"))\n'
        '    return {"status": "ok", "result": result}\n\n',

        'class UserService:\n'
        '    def __init__(self, db_session):\n'
        '        self.db = db_session\n'
        '        self.cache = {}\n\n'
        '    def get_user(self, user_id: int):\n'
        '        if user_id in self.cache:\n'
        '            return self.cache[user_id]\n'
        '        user = self.db.query(User).filter_by(id=user_id).first()\n'
        '        self.cache[user_id] = user\n'
        '        return user\n\n',

        'async def fetch_data(url: str, timeout: int = 30):\n'
        '    async with aiohttp.ClientSession() as session:\n'
        '        async with session.get(url, timeout=timeout) as resp:\n'
        '            if resp.status != 200:\n'
        '                raise APIError(f"Failed: {resp.status}")\n'
        '            return await resp.json()\n\n',

        'import logging\n'
        'from pathlib import Path\n'
        'from typing import Optional, List\n\n'
        'logger = logging.getLogger(__name__)\n\n'
        'BASE_DIR = Path(__file__).parent\n'
        'CONFIG_PATH = BASE_DIR / "config" / "settings.yaml"\n\n',

        '# Database migration: create users table\n'
        'CREATE_TABLE = """\n'
        'CREATE TABLE IF NOT EXISTS users (\n'
        '    id SERIAL PRIMARY KEY,\n'
        '    email VARCHAR(255) UNIQUE NOT NULL,\n'
        '    name VARCHAR(100),\n'
        '    created_at TIMESTAMP DEFAULT NOW()\n'
        ');\n'
        '"""\n\n',

        'def calculate_metrics(data: list) -> dict:\n'
        '    total = sum(d["value"] for d in data)\n'
        '    avg = total / len(data) if data else 0\n'
        '    sorted_vals = sorted(d["value"] for d in data)\n'
        '    median = sorted_vals[len(sorted_vals) // 2] if sorted_vals else 0\n'
        '    return {"total": total, "average": avg, "median": median}\n\n',

        'class Config:\n'
        '    DEBUG = False\n'
        '    TESTING = False\n'
        '    LOG_LEVEL = "INFO"\n'
        '    MAX_RETRIES = 3\n'
        '    TIMEOUT = 30\n'
        '    BATCH_SIZE = 100\n\n',

        'def parse_response(raw: bytes) -> dict:\n'
        '    try:\n'
        '        data = json.loads(raw)\n'
        '    except json.JSONDecodeError as e:\n'
        '        logger.error("Failed to parse response: %s", e)\n'
        '        return {"error": str(e)}\n'
        '    if "error" in data:\n'
        '        raise APIError(data["error"]["message"])\n'
        '    return data\n\n',
    ]
    result = []
    current_size = 0
    while current_size < size:
        snippet = random.choice(snippets)
        result.append(snippet)
        current_size += len(snippet)
    return "".join(result)[:size]


def _random_prose(size: int) -> str:
    """Generate realistic-looking assistant response text."""
    sentences = [
        "I'll help you refactor this code to improve its maintainability.",
        "The main issue is that the authentication middleware isn't properly validating tokens.",
        "Here's a step-by-step approach to fix the database connection pooling issue.",
        "Looking at the error traceback, the problem is in the serialization layer.",
        "I recommend splitting this into separate service classes for better separation of concerns.",
        "The test coverage for this module is quite low, so let's add unit tests first.",
        "This implementation follows the repository pattern which makes testing easier.",
        "The API endpoint should return a 422 status code for validation errors.",
        "Let me review the configuration to ensure the caching layer is properly set up.",
        "The migration script looks correct, but we should add an index on the email column.",
        "I've identified three potential security issues in the authentication flow.",
        "The rate limiter should use a sliding window algorithm instead of fixed windows.",
    ]
    result = []
    current_size = 0
    while current_size < size:
        s = random.choice(sentences) + " "
        result.append(s)
        current_size += len(s)
    return "".join(result)[:size]


# ---------------------------------------------------------------------------
# Payload builders (Anthropic Messages API format)
# ---------------------------------------------------------------------------

def build_clean_payload(target_size: int) -> bytes:
    """Build a payload with no secrets/PII (should PASS)."""
    system = "You are an expert software engineer. Help the user with their code."
    messages = []
    current_size = len(system) + 200  # JSON overhead

    msg_id = 0
    while current_size < target_size:
        remaining = target_size - current_size
        if msg_id % 3 == 0:
            # User message with code (tool_result)
            code_size = min(remaining // 2, 30000)
            messages.append({
                "role": "user",
                "content": [
                    {"type": "text", "text": "Please review this file:"},
                    {
                        "type": "tool_result",
                        "content": _random_code(code_size),
                        "input": {"file_path": "/src/module_%d.py" % msg_id},
                    },
                ],
            })
            current_size += code_size + 200
        elif msg_id % 3 == 1:
            # Assistant response
            prose_size = min(remaining, 5000)
            messages.append({
                "role": "assistant",
                "content": _random_prose(prose_size),
            })
            current_size += prose_size + 100
        else:
            # User follow-up
            messages.append({
                "role": "user",
                "content": "Can you also add error handling and type hints?",
            })
            current_size += 100
        msg_id += 1

    return json.dumps({
        "model": "claude-opus-4-6",
        "max_tokens": 4096,
        "system": system,
        "messages": messages,
    }).encode()


def build_secrets_payload(target_size: int) -> bytes:
    """Build a payload with embedded secrets (should trigger detection)."""
    system = "You are an expert software engineer."

    # Build secrets code with tokens constructed dynamically to avoid
    # GitHub push protection triggering on test fixture values.
    stripe_key = "sk_" + "live" + "_" + "a" * 24 + "EXAMPLE"
    github_token = "ghp_" + "A" * 36 + "EXAMPLE"
    slack_token = "xoxb-" + "1" * 12 + "-" + "2" * 13 + "-" + "a" * 16
    secrets_code = (
        '# Configuration for deployment\n'
        'import os\n\n'
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n\n'
        'DATABASE_URL = "postgres://admin:supersecret@db.prod.internal:5432/maindb"\n\n'
        'STRIPE_KEY = "%s"\n\n'
        '# API tokens\n'
        'GITHUB_TOKEN = "%s"\n'
        'SLACK_TOKEN = "%s"\n\n'
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEAm6AALzBGcy1VvFn5MnXS+OBCoFskz2CTqp0MAJfOq4GNKA5l\n'
        '-----END RSA PRIVATE KEY-----\n'
    ) % (stripe_key, github_token, slack_token)

    pii_text = '''
Customer records:
- John Smith, SSN: 123-45-6789, email: john.smith@company.com
- Card on file: 4111111111111111
- Phone: (555) 123-4567
- Server IP: 52.14.200.1
'''

    proprietary_text = '''
CONFIDENTIAL - TRADE SECRET
This algorithm is proprietary to our company.
INTERNAL ONLY - Do not distribute.
'''

    # Build padding first (earlier messages = clean conversation history)
    messages = []
    current_size = 300  # JSON overhead

    msg_id = 0
    # Reserve space for the secrets at the end
    secrets_size = len(secrets_code) + len(pii_text) + len(proprietary_text) + 500
    pad_target = target_size - secrets_size

    while current_size < pad_target:
        remaining = pad_target - current_size
        code_size = min(remaining, 20000)
        if code_size < 100:
            break
        messages.append({
            "role": "user",
            "content": [
                {"type": "text", "text": "Review this module:"},
                {
                    "type": "tool_result",
                    "content": _random_code(code_size),
                    "input": {"file_path": "/src/service_%d.py" % msg_id},
                },
            ],
        })
        current_size += code_size + 200
        msg_id += 1

    # Secrets at the END — realistic: newest file reads contain the sensitive data
    messages.append({"role": "user", "content": proprietary_text})
    messages.append({"role": "user", "content": pii_text})
    messages.append({
        "role": "user",
        "content": [
            {"type": "text", "text": "Check this config file:"},
            {
                "type": "tool_result",
                "content": secrets_code,
                "input": {"file_path": "/app/.env"},
            },
        ],
    })

    return json.dumps({
        "model": "claude-opus-4-6",
        "max_tokens": 4096,
        "system": system,
        "messages": messages,
    }).encode()


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

PAYLOAD_SIZES = {
    "tiny":   1_000,       # 1 KB
    "small":  10_000,      # 10 KB
    "medium": 100_000,     # 100 KB
    "large":  500_000,     # 500 KB
    "xlarge": 1_000_000,   # 1 MB (stress test)
}


def run_benchmark(
    pipeline: ScannerPipeline,
    payload: bytes,
    label: str,
    iterations: int,
) -> dict:
    """Run benchmark and return stats."""
    times = []  # type: List[float]

    # Warmup (3 runs, not counted)
    for _ in range(3):
        pipeline.scan(payload, "anthropic")

    # Timed runs
    for _ in range(iterations):
        t0 = time.monotonic()
        result = pipeline.scan(payload, "anthropic")
        elapsed_ms = (time.monotonic() - t0) * 1000
        times.append(elapsed_ms)

    return {
        "label": label,
        "payload_bytes": len(payload),
        "iterations": iterations,
        "min_ms": min(times),
        "max_ms": max(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "p95_ms": sorted(times)[int(len(times) * 0.95)],
        "p99_ms": sorted(times)[int(len(times) * 0.99)],
        "stddev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "findings": len(result.findings),
        "action": result.action,
    }


def format_results(results: List[dict]) -> str:
    """Format benchmark results as a table."""
    lines = []
    lines.append("")
    lines.append("  %-28s %8s %8s %8s %8s %8s %8s  %s" % (
        "Payload", "Size", "Mean", "Median", "P95", "P99", "Max", "Result",
    ))
    lines.append("  " + "-" * 100)

    target_ms = 50.0

    for r in results:
        size_str = "%.0fKB" % (r["payload_bytes"] / 1000)
        status = "PASS" if r["p95_ms"] < target_ms else "SLOW"
        if r["findings"] > 0:
            result_str = "%s (%d findings)" % (r["action"].upper(), r["findings"])
        else:
            result_str = "clean"

        marker = " *" if status == "SLOW" else ""
        lines.append("  %-28s %8s %7.1fms %7.1fms %7.1fms %7.1fms %7.1fms  %-20s%s" % (
            r["label"],
            size_str,
            r["mean_ms"],
            r["median_ms"],
            r["p95_ms"],
            r["p99_ms"],
            r["max_ms"],
            result_str,
            marker,
        ))

    lines.append("  " + "-" * 100)
    lines.append("  Target: <50ms at P95.  * = exceeds target.")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="lumen-argus scan pipeline benchmark")
    parser.add_argument(
        "--iterations", "-n", type=int, default=100,
        help="Number of timed iterations per payload (default: 100)",
    )
    parser.add_argument(
        "--payload", "-p", type=str, default=None,
        choices=list(PAYLOAD_SIZES.keys()),
        help="Run only a specific payload size",
    )
    args = parser.parse_args()

    pipeline = ScannerPipeline(
        default_action="alert",
        action_overrides={"secrets": "block"},
        allowlist=AllowlistMatcher(),
        entropy_threshold=4.5,
    )

    print("\n  lumen-argus benchmark — %d iterations per payload\n" % args.iterations)

    if args.payload:
        sizes = {args.payload: PAYLOAD_SIZES[args.payload]}
    else:
        sizes = PAYLOAD_SIZES

    results = []

    for name, target_size in sizes.items():
        # Clean payload (no secrets)
        clean = build_clean_payload(target_size)
        r = run_benchmark(pipeline, clean, "%s / clean" % name, args.iterations)
        results.append(r)
        print("    done: %s / clean" % name)

        # Dirty payload (with secrets, PII, proprietary)
        dirty = build_secrets_payload(target_size)
        r = run_benchmark(pipeline, dirty, "%s / secrets+pii" % name, args.iterations)
        results.append(r)
        print("    done: %s / secrets+pii" % name)

    print(format_results(results))


if __name__ == "__main__":
    main()
