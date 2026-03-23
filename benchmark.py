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
import statistics
import time
from typing import List

from lumen_argus.pipeline import ScannerPipeline
from lumen_argus.allowlist import AllowlistMatcher


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------


def _random_code(size: int) -> str:
    """Generate realistic-looking Python code of approximately `size` bytes."""
    snippets = [
        "def process_request(self, data: dict) -> dict:\n"
        '    """Process incoming API request."""\n'
        "    validated = self._validate(data)\n"
        "    result = self._transform(validated)\n"
        '    self.logger.info("Processed request %s", data.get("id"))\n'
        '    return {"status": "ok", "result": result}\n\n',
        "class UserService:\n"
        "    def __init__(self, db_session):\n"
        "        self.db = db_session\n"
        "        self.cache = {}\n\n"
        "    def get_user(self, user_id: int):\n"
        "        if user_id in self.cache:\n"
        "            return self.cache[user_id]\n"
        "        user = self.db.query(User).filter_by(id=user_id).first()\n"
        "        self.cache[user_id] = user\n"
        "        return user\n\n",
        "async def fetch_data(url: str, timeout: int = 30):\n"
        "    async with aiohttp.ClientSession() as session:\n"
        "        async with session.get(url, timeout=timeout) as resp:\n"
        "            if resp.status != 200:\n"
        '                raise APIError(f"Failed: {resp.status}")\n'
        "            return await resp.json()\n\n",
        "import logging\n"
        "from pathlib import Path\n"
        "from typing import Optional, List\n\n"
        "logger = logging.getLogger(__name__)\n\n"
        "BASE_DIR = Path(__file__).parent\n"
        'CONFIG_PATH = BASE_DIR / "config" / "settings.yaml"\n\n',
        "# Database migration: create users table\n"
        'CREATE_TABLE = """\n'
        "CREATE TABLE IF NOT EXISTS users (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    email VARCHAR(255) UNIQUE NOT NULL,\n"
        "    name VARCHAR(100),\n"
        "    created_at TIMESTAMP DEFAULT NOW()\n"
        ");\n"
        '"""\n\n',
        "def calculate_metrics(data: list) -> dict:\n"
        '    total = sum(d["value"] for d in data)\n'
        "    avg = total / len(data) if data else 0\n"
        '    sorted_vals = sorted(d["value"] for d in data)\n'
        "    median = sorted_vals[len(sorted_vals) // 2] if sorted_vals else 0\n"
        '    return {"total": total, "average": avg, "median": median}\n\n',
        "class Config:\n"
        "    DEBUG = False\n"
        "    TESTING = False\n"
        '    LOG_LEVEL = "INFO"\n'
        "    MAX_RETRIES = 3\n"
        "    TIMEOUT = 30\n"
        "    BATCH_SIZE = 100\n\n",
        "def parse_response(raw: bytes) -> dict:\n"
        "    try:\n"
        "        data = json.loads(raw)\n"
        "    except json.JSONDecodeError as e:\n"
        '        logger.error("Failed to parse response: %s", e)\n'
        '        return {"error": str(e)}\n'
        '    if "error" in data:\n'
        '        raise APIError(data["error"]["message"])\n'
        "    return data\n\n",
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
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Please review this file:"},
                        {
                            "type": "tool_result",
                            "content": _random_code(code_size),
                            "input": {"file_path": "/src/module_%d.py" % msg_id},
                        },
                    ],
                }
            )
            current_size += code_size + 200
        elif msg_id % 3 == 1:
            # Assistant response
            prose_size = min(remaining, 5000)
            messages.append(
                {
                    "role": "assistant",
                    "content": _random_prose(prose_size),
                }
            )
            current_size += prose_size + 100
        else:
            # User follow-up
            messages.append(
                {
                    "role": "user",
                    "content": "Can you also add error handling and type hints?",
                }
            )
            current_size += 100
        msg_id += 1

    return json.dumps(
        {
            "model": "claude-opus-4-6",
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
        }
    ).encode()


def build_secrets_payload(target_size: int) -> bytes:
    """Build a payload with embedded secrets (should trigger detection)."""
    system = "You are an expert software engineer."

    # Build secrets code with tokens constructed dynamically to avoid
    # GitHub push protection triggering on test fixture values.
    stripe_key = "sk_" + "live" + "_" + "a" * 24 + "EXAMPLE"
    github_token = "ghp_" + "A" * 36 + "EXAMPLE"
    slack_token = "xoxb-" + "1" * 12 + "-" + "2" * 13 + "-" + "a" * 16
    secrets_code = (
        "# Configuration for deployment\n"
        "import os\n\n"
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n\n'
        'DATABASE_URL = "postgres://admin:supersecret@db.prod.internal:5432/maindb"\n\n'
        'STRIPE_KEY = "%s"\n\n'
        "# API tokens\n"
        'GITHUB_TOKEN = "%s"\n'
        'SLACK_TOKEN = "%s"\n\n'
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAm6AALzBGcy1VvFn5MnXS+OBCoFskz2CTqp0MAJfOq4GNKA5l\n"
        "-----END RSA PRIVATE KEY-----\n"
    ) % (stripe_key, github_token, slack_token)

    pii_text = """
Customer records:
- John Smith, SSN: 123-45-6789, email: john.smith@company.com
- Card on file: 4111111111111111
- Phone: (555) 123-4567
- Server IP: 52.14.200.1
"""

    proprietary_text = """
CONFIDENTIAL - TRADE SECRET
This algorithm is proprietary to our company.
INTERNAL ONLY - Do not distribute.
"""

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
        messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Review this module:"},
                    {
                        "type": "tool_result",
                        "content": _random_code(code_size),
                        "input": {"file_path": "/src/service_%d.py" % msg_id},
                    },
                ],
            }
        )
        current_size += code_size + 200
        msg_id += 1

    # Secrets at the END — realistic: newest file reads contain the sensitive data
    messages.append({"role": "user", "content": proprietary_text})
    messages.append({"role": "user", "content": pii_text})
    messages.append(
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Check this config file:"},
                {
                    "type": "tool_result",
                    "content": secrets_code,
                    "input": {"file_path": "/app/.env"},
                },
            ],
        }
    )

    return json.dumps(
        {
            "model": "claude-opus-4-6",
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
        }
    ).encode()


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

PAYLOAD_SIZES = {
    "tiny": 1_000,  # 1 KB
    "small": 10_000,  # 10 KB
    "medium": 100_000,  # 100 KB
    "large": 500_000,  # 500 KB
    "xlarge": 1_000_000,  # 1 MB (stress test)
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
    lines.append(
        "  %-28s %8s %8s %8s %8s %8s %8s  %s"
        % (
            "Payload",
            "Size",
            "Mean",
            "Median",
            "P95",
            "P99",
            "Max",
            "Result",
        )
    )
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
        lines.append(
            "  %-28s %8s %7.1fms %7.1fms %7.1fms %7.1fms %7.1fms  %-20s%s"
            % (
                r["label"],
                size_str,
                r["mean_ms"],
                r["median_ms"],
                r["p95_ms"],
                r["p99_ms"],
                r["max_ms"],
                result_str,
                marker,
            )
        )

    lines.append("  " + "-" * 100)
    lines.append("  Target: <50ms at P95.  * = exceeds target.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dedup benchmark helpers
# ---------------------------------------------------------------------------


def build_conversation_body(num_messages: int, with_secrets: bool = True) -> bytes:
    """Build an Anthropic conversation with N messages.

    First message contains secrets (if with_secrets). Subsequent messages
    alternate user/assistant with clean code — simulating real usage where
    secrets leak once and then conversation continues.
    """
    messages = []
    if with_secrets:
        stripe_key = "sk_" + "live" + "_" + "a" * 24 + "EXAMPLE"
        github_token = "ghp_" + "A" * 36 + "EXAMPLE"
        messages.append(
            {
                "role": "user",
                "content": (
                    "Deploy with these creds:\n"
                    'AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"\n'
                    'AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
                    'STRIPE_KEY="%s"\n'
                    'GITHUB_TOKEN="%s"\n'
                    "Customer SSN: 123-45-6789, email: john@company.com\n"
                )
                % (stripe_key, github_token),
            }
        )
        messages.append(
            {
                "role": "assistant",
                "content": "I see credentials. Let me help you set up secure credential management.",
            }
        )
    for i in range(len(messages), num_messages):
        role = "user" if i % 2 == 0 else "assistant"
        messages.append(
            {
                "role": role,
                "content": _random_code(1000) if role == "user" else _random_prose(800),
            }
        )
    return json.dumps(
        {
            "model": "claude-opus-4-6",
            "max_tokens": 4096,
            "messages": messages,
        }
    ).encode()


def run_dedup_benchmarks(iterations: int) -> List[dict]:
    """Run dedup-specific benchmarks."""
    from lumen_argus.models import SessionContext

    results = []

    # --- Benchmark 1: First scan vs repeat scan (same body) ---
    for num_msgs, label in [(10, "10-msg"), (30, "30-msg"), (50, "50-msg")]:
        body = build_conversation_body(num_msgs, with_secrets=True)

        # Cold scan (fresh pipeline, no dedup cache)
        cold_times = []
        for i in range(iterations):
            p = ScannerPipeline(default_action="alert", allowlist=AllowlistMatcher())
            sess = SessionContext(session_id="cold-%d-%d" % (num_msgs, i))
            t0 = time.monotonic()
            r = p.scan(body, "anthropic", session=sess)
            cold_times.append((time.monotonic() - t0) * 1000)

        cold_findings = len(r.findings)

        # Warm scan (same pipeline + session, dedup active)
        p_warm = ScannerPipeline(default_action="alert", allowlist=AllowlistMatcher())
        sess_warm = SessionContext(session_id="warm-%d" % num_msgs)
        p_warm.scan(body, "anthropic", session=sess_warm)  # prime cache
        warm_times = []
        for _ in range(iterations):
            t0 = time.monotonic()
            r2 = p_warm.scan(body, "anthropic", session=sess_warm)
            warm_times.append((time.monotonic() - t0) * 1000)

        results.append(
            {
                "label": "%s / first scan" % label,
                "payload_bytes": len(body),
                "iterations": iterations,
                "min_ms": min(cold_times),
                "max_ms": max(cold_times),
                "mean_ms": statistics.mean(cold_times),
                "median_ms": statistics.median(cold_times),
                "p95_ms": sorted(cold_times)[int(len(cold_times) * 0.95)],
                "p99_ms": sorted(cold_times)[int(len(cold_times) * 0.99)],
                "stddev_ms": statistics.stdev(cold_times) if len(cold_times) > 1 else 0,
                "findings": cold_findings,
                "action": r.action,
            }
        )
        results.append(
            {
                "label": "%s / dedup repeat" % label,
                "payload_bytes": len(body),
                "iterations": iterations,
                "min_ms": min(warm_times),
                "max_ms": max(warm_times),
                "mean_ms": statistics.mean(warm_times),
                "median_ms": statistics.median(warm_times),
                "p95_ms": sorted(warm_times)[int(len(warm_times) * 0.95)],
                "p99_ms": sorted(warm_times)[int(len(warm_times) * 0.99)],
                "stddev_ms": statistics.stdev(warm_times) if len(warm_times) > 1 else 0,
                "findings": len(r2.findings),
                "action": r2.action,
            }
        )

    # --- Benchmark 2: Growing conversation (realistic usage) ---
    # Each iteration adds a new message to the conversation
    p_grow = ScannerPipeline(default_action="alert", allowlist=AllowlistMatcher())
    sess_grow = SessionContext(session_id="grow-bench")
    grow_times = []
    for msg_count in range(2, 52):
        body = build_conversation_body(msg_count, with_secrets=True)
        t0 = time.monotonic()
        r = p_grow.scan(body, "anthropic", session=sess_grow)
        grow_times.append((time.monotonic() - t0) * 1000)

    results.append(
        {
            "label": "growing conv (2→50 msgs)",
            "payload_bytes": len(body),
            "iterations": len(grow_times),
            "min_ms": min(grow_times),
            "max_ms": max(grow_times),
            "mean_ms": statistics.mean(grow_times),
            "median_ms": statistics.median(grow_times),
            "p95_ms": sorted(grow_times)[int(len(grow_times) * 0.95)],
            "p99_ms": sorted(grow_times)[int(len(grow_times) * 0.99)],
            "stddev_ms": statistics.stdev(grow_times) if len(grow_times) > 1 else 0,
            "findings": len(r.findings),
            "action": r.action,
        }
    )

    # --- Benchmark 3: Multiple concurrent sessions ---
    p_multi = ScannerPipeline(default_action="alert", allowlist=AllowlistMatcher())
    body_multi = build_conversation_body(20, with_secrets=True)
    multi_times = []
    for i in range(iterations):
        sess = SessionContext(session_id="multi-%d" % (i % 50))
        t0 = time.monotonic()
        p_multi.scan(body_multi, "anthropic", session=sess)
        multi_times.append((time.monotonic() - t0) * 1000)

    results.append(
        {
            "label": "50 sessions rotating",
            "payload_bytes": len(body_multi),
            "iterations": iterations,
            "min_ms": min(multi_times),
            "max_ms": max(multi_times),
            "mean_ms": statistics.mean(multi_times),
            "median_ms": statistics.median(multi_times),
            "p95_ms": sorted(multi_times)[int(len(multi_times) * 0.95)],
            "p99_ms": sorted(multi_times)[int(len(multi_times) * 0.99)],
            "stddev_ms": statistics.stdev(multi_times) if len(multi_times) > 1 else 0,
            "findings": 0,
            "action": "pass",
        }
    )

    return results


def main():
    parser = argparse.ArgumentParser(description="lumen-argus scan pipeline benchmark")
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=100,
        help="Number of timed iterations per payload (default: 100)",
    )
    parser.add_argument(
        "--payload",
        "-p",
        type=str,
        default=None,
        choices=list(PAYLOAD_SIZES.keys()),
        help="Run only a specific payload size",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        help="Run dedup benchmarks (first scan vs repeat, growing conversation, multi-session)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run both payload and dedup benchmarks",
    )
    parser.add_argument(
        "--rules",
        action="store_true",
        help="Benchmark RulesDetector with Aho-Corasick pre-filter (1700+ rules)",
    )
    args = parser.parse_args()

    run_payload = not args.dedup or args.all
    run_dedup = args.dedup or args.all

    pipeline = ScannerPipeline(
        default_action="alert",
        action_overrides={"secrets": "block"},
        allowlist=AllowlistMatcher(),
        entropy_threshold=4.5,
    )

    print("\n  lumen-argus benchmark — %d iterations per payload\n" % args.iterations)

    results = []

    if run_payload:
        if args.payload:
            sizes = {args.payload: PAYLOAD_SIZES[args.payload]}
        else:
            sizes = PAYLOAD_SIZES

        for name, target_size in sizes.items():
            clean = build_clean_payload(target_size)
            r = run_benchmark(pipeline, clean, "%s / clean" % name, args.iterations)
            results.append(r)
            print("    done: %s / clean" % name)

            dirty = build_secrets_payload(target_size)
            r = run_benchmark(pipeline, dirty, "%s / secrets+pii" % name, args.iterations)
            results.append(r)
            print("    done: %s / secrets+pii" % name)

        print(format_results(results))

    if run_dedup:
        print("\n  === Dedup Benchmarks ===\n")
        dedup_results = run_dedup_benchmarks(args.iterations)

        # Print with speedup annotations
        for i, r in enumerate(dedup_results):
            label = r["label"]
            if "first scan" in label:
                print("    done: %s" % label)
            elif "dedup repeat" in label:
                # Calculate speedup vs previous (first scan)
                first = dedup_results[i - 1]
                speedup = first["median_ms"] / r["median_ms"] if r["median_ms"] > 0 else 0
                print("    done: %s (%.0fx speedup)" % (label, speedup))
            else:
                print("    done: %s" % label)

        print(format_results(dedup_results))

    if args.rules or args.all:
        print("\n  === Rules Engine Benchmark (Aho-Corasick) ===\n")
        run_rules_benchmark(args.iterations)


def run_rules_benchmark(iterations: int = 50):
    """Benchmark RulesDetector with Aho-Corasick pre-filter."""
    import os
    import shutil
    import tempfile

    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.detectors.rules import RulesDetector
    from lumen_argus.models import ScanField

    tmpdir = tempfile.mkdtemp()
    try:
        store = AnalyticsStore(db_path=os.path.join(tmpdir, "bench.db"))

        # Import community rules
        rules_path = os.path.join(os.path.dirname(__file__), "lumen_argus", "rules", "community.json")
        if os.path.exists(rules_path):
            import json as _json

            with open(rules_path) as f:
                data = _json.load(f)
            rules = data.get("rules", data) if isinstance(data, dict) else data
            result = store.import_rules(rules, tier="community")
            print("    loaded %d community rules" % result["created"])
        else:
            print("    WARNING: community.json not found")
            return

        detector = RulesDetector(store=store)
        allowlist = AllowlistMatcher()

        print("    accelerator: %s" % ("enabled" if detector._accelerator.available else "DISABLED"))
        stats = detector._accelerator.stats
        print(
            "    rules: %d total, %d with literals, %d fallback"
            % (stats["total_rules"], stats["rules_with_literals"], stats["fallback_rules"])
        )

        # Test with different payload sizes
        for label, text_size in [("3KB", 3000), ("80KB", 80_000), ("184KB", 184_000)]:
            text = _random_code(text_size)
            # Add a detectable secret to measure actual match path
            text += "\nsk_live_xxxtestvaluehere\n"

            fields = [ScanField(path="messages[0].content", text=text)]

            # Warmup
            detector.scan(fields, allowlist)

            times = []
            for _ in range(iterations):
                t0 = time.monotonic()
                findings = detector.scan(fields, allowlist)
                elapsed = (time.monotonic() - t0) * 1000
                times.append(elapsed)

            med = statistics.median(times)
            p95 = sorted(times)[int(len(times) * 0.95)]
            p99 = sorted(times)[int(len(times) * 0.99)]
            target = "PASS" if med < 50 else "FAIL"

            print(
                "    %s: median=%.1fms  P95=%.1fms  P99=%.1fms  findings=%d  [%s]"
                % (label, med, p95, p99, len(findings), target)
            )

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
