#!/usr/bin/env python3
"""Fake tooling server for seahawk's feedback wire tests.

Speaks the fleet's modern-era stdio shape (NDJSON, sessions
open with server/discover) and answers the exact tool surface
the code.feedback client is allowed to call:

- theodolite mode (argv[1] == "theodolite"): diagnostics,
  session_status. A file whose path contains "bad" yields one
  error diagnostic; anything else is clean.
- periscope mode (argv[1] == "periscope"): broker_status,
  get_diagnostics, list_servers, list_formatters, list_linters,
  run_lint, run_format. run_format reports changed=true only
  for paths containing "unformatted".

Any other tool is an isError result, so a client that widens
its dispatch table fails the wire tests loudly.
"""
import json
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "theodolite"


def result(frame, payload, is_error=False):
    return {
        "jsonrpc": "2.0",
        "id": frame.get("id"),
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "structuredContent": payload,
            "isError": is_error,
        },
    }


def diagnostics_for(path):
    if "bad" in path:
        return {
            "server": "bacon-ls",
            "count": 1,
            "diagnostics": [
                {
                    "uri": path,
                    "severity": 1,
                    "source": "bacon-ls",
                    "message": "seeded error: this file is the dirty fixture",
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 4},
                    },
                }
            ],
        }
    return {"server": "bacon-ls", "count": 0, "diagnostics": []}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        frame = json.loads(line)
        method = frame.get("method")
        if method == "server/discover":
            out = {
                "jsonrpc": "2.0",
                "id": frame.get("id"),
                "result": {
                    "protocolVersion": "2026-07-28",
                    "serverInfo": {"name": "fake-tooling", "version": "0"},
                    "capabilities": {},
                },
            }
        elif method == "tools/call":
            params = frame.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if MODE == "theodolite" and name == "diagnostics":
                out = result(frame, diagnostics_for(args.get("path", "")))
            elif MODE == "theodolite" and name == "session_status":
                out = result(frame, {"sessions": []})
            elif MODE == "periscope" and name == "get_diagnostics":
                out = result(frame, diagnostics_for(args.get("path", "")))
            elif MODE == "periscope" and name == "run_lint":
                out = result(frame, {
                    "linters": [
                        {"name": "clippy", "status": "ok", "diagnostics": []}
                    ]
                })
            elif MODE == "periscope" and name == "run_format":
                changed = "unformatted" in args.get("path", "")
                out = result(frame, {
                    "changed": changed,
                    "steps": ["rustfmt"],
                    "written": False,
                    "text": "fn main() {}\n" if changed else "",
                })
            elif MODE == "periscope" and name == "list_servers":
                out = result(frame, {"servers": ["bacon-ls", "rust-analyzer"]})
            elif MODE == "periscope" and name == "list_formatters":
                out = result(frame, {"formatters": ["rustfmt"]})
            elif MODE == "periscope" and name == "list_linters":
                out = result(frame, {"linters": ["clippy"]})
            elif MODE == "periscope" and name == "broker_status":
                out = result(frame, {"mode": "managed", "config_root": "/fake/diver"})
            else:
                out = result(
                    frame,
                    {"error": f"fake refuses tool {name}"},
                    is_error=True,
                )
        else:
            continue
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
