"""
CLI & stdio MCP Transport for TITAN Statutory Gate (`com.titancapitalforensics/statutory-gate`).
Zero-secret, zero-PII, stateless diagnostic applicability & Ed25519 hash gate.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from typing import Any

from .gate_engine import (
    PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    TOOLS,
    handle_jsonrpc_message,
)


def run_stdio_server() -> int:
    """Serve newline-delimited JSON-RPC 2.0 MCP over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload: Any = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        if isinstance(payload, list):
            out = []
            for item in payload:
                r = handle_jsonrpc_message(item)
                if r is not None:
                    out.append(r)
            if out:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()
        else:
            r = handle_jsonrpc_message(payload)
            if r is not None:
                sys.stdout.write(json.dumps(r) + "\n")
                sys.stdout.flush()
    return 0


def probe_remote(endpoint: str) -> int:
    """Verify remote Streamable HTTP MCP endpoint initialize + tools/list."""
    if not endpoint.startswith("https://"):
        raise ValueError("Remote MCP endpoint must use https:// (TLS 1.2+ required).")
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "titan-cli-probe", "version": SERVER_VERSION},
        },
    }
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": f"TITAN-Statutory-MCP-CLI/{SERVER_VERSION}",
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(init_req).encode("utf-8"),
        headers=base_headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - https:// enforced above
        init_res = json.loads(resp.read().decode("utf-8"))
        sess = resp.headers.get("Mcp-Session-Id", "")

    tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    headers = dict(base_headers)
    if sess:
        headers["Mcp-Session-Id"] = sess
    req2 = urllib.request.Request(
        endpoint,
        data=json.dumps(tools_req).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req2, timeout=15) as resp2:  # nosec B310 - https:// enforced above
        tools_res = json.loads(resp2.read().decode("utf-8"))

    print(json.dumps({"initialize": init_res, "tools_count": len(tools_res["result"]["tools"])}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="TITAN Statutory Gate MCP Server (stdio & remote probe)")
    ap.add_argument("--schema-tokens", action="store_true", help="Print schema byte and approximate token size")
    ap.add_argument("--probe-remote", default="", help="Probe remote Streamable HTTP MCP URL")
    args = ap.parse_args()

    if args.schema_tokens:
        raw = json.dumps({"tools": TOOLS}, separators=(",", ":"))
        print(json.dumps({
            "server": SERVER_NAME,
            "tools_count": len(TOOLS),
            "compact_bytes": len(raw),
            "approx_tokens_div4": round(len(raw) / 4, 1),
        }, indent=2))
        return 0

    if args.probe_remote:
        return probe_remote(args.probe_remote)

    return run_stdio_server()


if __name__ == "__main__":
    sys.exit(main())
