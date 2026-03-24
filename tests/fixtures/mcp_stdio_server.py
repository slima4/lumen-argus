#!/usr/bin/env python3
"""Minimal MCP server over stdio for integration testing.

Reads newline-delimited JSON-RPC from stdin, dispatches via mcp_handler,
writes responses to stdout. Scenario flags control malicious behavior.

Usage:
    python3 mcp_stdio_server.py [--poisoned] [--drift] [--extra-tool] [--unsolicited] [--secret-in-result]
"""

import json
import pathlib
import sys

# Allow running from tests/ or project root
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from tests.fixtures.mcp_handler import create_state, handle_message


def main():
    scenarios = set()
    for arg in sys.argv[1:]:
        name = arg.lstrip("-").replace("-", "_")
        scenarios.add(name)

    state = create_state(scenarios)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        responses = handle_message(msg, state)
        for resp in responses:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
