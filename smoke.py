#!/usr/bin/env python3
# Eclipse Constellation MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Smoke: drive server.py over real stdio with a temp state file.

"""Smoke: drive server.py over real stdio with a temp state file.
Declares nothing new — probes the shipped registry (self-vm only),
walks the policy-evaluation flows, prints a compact transcript.
Localhost only; nothing mutates (v0.1 has no mutation code paths)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
ACTOR = {"agent": "jett-cirrus", "desk": "operations"}


def call(proc, rid, name, args):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                 "method": "tools/call",
                                 "params": {"name": name,
                                            "arguments": args}}) + "\n")
    proc.stdin.flush()
    resp = json.loads(proc.stdout.readline())
    return json.loads(resp["result"]["content"][0]["text"])


def main():
    with tempfile.TemporaryDirectory() as td:
        env = {"ECLIPSE_CONSTELLATION_STATE": str(Path(td) / "state.json"),
               "PATH": "/usr/bin:/bin:/usr/local/bin",
               "HOME": str(Path.home())}
        proc = subprocess.Popen([sys.executable, str(ROOT / "server.py")],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                text=True, env=env)
        try:
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26"}}) + "\n")
            proc.stdin.flush()
            init = json.loads(proc.stdout.readline())
            print("server:", init["result"]["serverInfo"])
            rid = 1
            lst = call(proc, rid, "target_list", {}); rid += 1
            print("declared targets:", [t["name"] for t in lst["targets"]])
            probe = call(proc, rid, "probe_target",
                         {"target": "self-vm",
                          "probes": ["identity", "memory"]}); rid += 1
            ident = probe["results"]["identity"]["data"]
            mem = probe["results"]["memory"]["data"]
            print(f"probe self-vm: host={ident.get('hostname')} "
                  f"os={ident.get('os')} mem_total={mem.get('total_mb')}MB")
            denied = call(proc, rid, "policy_evaluate",
                          {"actor": ACTOR, "target": "self-vm",
                           "action": "resize", "params": {}}); rid += 1
            print("resize w/o snapshot:", denied["verdict"], "—",
                  denied["reasons"][0][:80], "…")
            snap = call(proc, rid, "policy_evaluate",
                        {"actor": ACTOR, "target": "self-vm",
                         "action": "snapshot_create", "params": {}})
            rid += 1
            ok = call(proc, rid, "policy_evaluate",
                      {"actor": ACTOR, "target": "self-vm",
                       "action": "resize",
                       "params": {"snapshot_receipt_seq":
                                  snap["receipt_seq"]}}); rid += 1
            print("resize w/ snapshot receipt:", ok["verdict"])
            destroy = call(proc, rid, "policy_evaluate",
                           {"actor": ACTOR, "target": "self-vm",
                            "action": "destroy", "params": {}}); rid += 1
            print("destroy (v0.1):", destroy["verdict"], "(Tier-3 "
                  "approval gate + observe-only build)")
            fleet = call(proc, rid, "fleet_snapshot", {}); rid += 1
            print("fleet snapshot:", fleet["snapshot_id"],
                  {k: v["status"] for k, v in fleet["targets"].items()})
            led = call(proc, rid, "receipt_list", {}); rid += 1
            print(f"ledger: {led['count']} receipts, "
                  f"chain_valid={led['chain_valid']}")
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)


if __name__ == "__main__":
    main()

# Eclipse Constellation MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
