# Eclipse Constellation MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Constellation v0.1 tests — governance core + observe adapter.

"""Eclipse Constellation v0.1 tests — governance core + observe adapter.

All tests run against a temp state + the product's real targets.json /
policy.json. Probes execute for real against localhost (declared
channel 'local'). No external host is touched; nothing mutates.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
_TMP = tempfile.mkdtemp(prefix="constellation-test-")
os.environ["ECLIPSE_CONSTELLATION_STATE"] = str(Path(_TMP) / "state.json")
# targets + policy deliberately NOT overridden: tests exercise the
# shipped registry (self-vm declared, droplet NOT declared) and policy.

_spec = importlib.util.spec_from_file_location("constellation_server",
                                              ROOT / "server.py")
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)

ACTOR = {"agent": "silas-forge", "desk": "product-engineering"}


def fresh_state():
    return server.empty_state()


def evaluate(state, action, target="self-vm", params=None, actor=ACTOR):
    return server.evaluate(state, server.load_targets(),
                           server.load_policy(),
                           {"actor": actor, "target": target,
                            "action": action, "params": params or {}})


class RegistryTests(unittest.TestCase):
    def test_only_self_vm_declared_droplet_absent(self):
        out = server.t_target_list(fresh_state(), {})
        names = [t["name"] for t in out["targets"]]
        self.assertEqual(names, ["self-vm"])
        self.assertNotIn("eclipse-connect", names)

    def test_undeclared_target_invisible_to_probe(self):
        with self.assertRaises(server.ToolError):
            server.t_probe_target(fresh_state(), {"target": "droplet"})

    def test_undeclared_target_evaluation_denied(self):
        out = evaluate(fresh_state(), "inventory", target="droplet")
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("not declared" in r for r in out["reasons"]))


class PolicyTests(unittest.TestCase):
    def test_actor_required(self):
        out = evaluate(fresh_state(), "inventory", actor={})
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("identity" in r for r in out["reasons"]))

    def test_tier0_read_allows(self):
        out = evaluate(fresh_state(), "metrics_read")
        self.assertEqual(out["verdict"], "ALLOW")

    def test_destroy_without_snapshot_denied_with_reasons(self):
        out = evaluate(fresh_state(), "destroy")
        self.assertEqual(out["verdict"], "DENY")
        joined = " ".join(out["reasons"])
        self.assertIn("snapshot", joined)
        self.assertIn("human", joined)

    def test_destroy_with_snapshot_still_denied_in_v01(self):
        state = fresh_state()
        snap = evaluate(state, "snapshot_create")
        self.assertEqual(snap["verdict"], "ALLOW")
        out = evaluate(state, "destroy",
                       params={"snapshot_receipt_seq": snap["receipt_seq"]})
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("human confirmation" in r
                            for r in out["reasons"]))

    def test_snapshot_precondition_flow_for_resize(self):
        state = fresh_state()
        denied = evaluate(state, "resize")
        self.assertEqual(denied["verdict"], "DENY")
        self.assertTrue(any("no snapshot receipt, no mutation" in r
                            for r in denied["reasons"]))
        snap = evaluate(state, "snapshot_create")
        allowed = evaluate(state, "resize",
                           params={"snapshot_receipt_seq":
                                   snap["receipt_seq"]})
        self.assertEqual(allowed["verdict"], "ALLOW")

    def test_stale_snapshot_receipt_denied(self):
        state = fresh_state()
        snap = evaluate(state, "snapshot_create")
        # Age the receipt beyond the freshness window.
        state["receipts"][-1]["ts"] -= 90000
        # Re-seal the aged receipt so only freshness fails, not the chain.
        r = state["receipts"][-1]
        r["hash"] = server.sha(server.canon(
            {k: r[k] for k in ("seq", "ts", "type", "prev_hash",
                               "detail")}))
        out = evaluate(state, "resize",
                       params={"snapshot_receipt_seq": snap["receipt_seq"]})
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("stale" in r for r in out["reasons"]))

    def test_quota_excess_denied_with_arithmetic(self):
        out = evaluate(fresh_state(), "provision",
                       params={"image": "bench-base-ubuntu-24.04",
                               "network": "isolated", "purpose": "bench",
                               "ttl_hours": 24, "vcpu": 9999})
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("quota exceeded" in r and "9999" in r
                            for r in out["reasons"]))

    def test_provision_happy_path_allows(self):
        out = evaluate(fresh_state(), "provision",
                       params={"image": "bench-base-ubuntu-24.04",
                               "network": "isolated",
                               "purpose": "test-bench pristine run",
                               "ttl_hours": 24, "vcpu": 2, "ram_gb": 4,
                               "disk_gb": 20})
        self.assertEqual(out["verdict"], "ALLOW", out["reasons"])

    def test_provision_unregistered_image_denied(self):
        out = evaluate(fresh_state(), "provision",
                       params={"image": "random-internet-image",
                               "network": "isolated", "purpose": "x",
                               "ttl_hours": 24})
        self.assertEqual(out["verdict"], "DENY")
        self.assertTrue(any("allowlist" in r for r in out["reasons"]))

    def test_provision_missing_purpose_and_ttl_over_ceiling(self):
        no_purpose = evaluate(fresh_state(), "provision",
                              params={"image": "bench-base-ubuntu-24.04",
                                      "ttl_hours": 24})
        self.assertEqual(no_purpose["verdict"], "DENY")
        long_ttl = evaluate(fresh_state(), "provision",
                            params={"image": "bench-base-ubuntu-24.04",
                                    "purpose": "forever box",
                                    "ttl_hours": 99999})
        self.assertEqual(long_ttl["verdict"], "DENY")
        self.assertTrue(any("ceiling" in r for r in long_ttl["reasons"]))

    def test_unknown_action_denied(self):
        out = evaluate(fresh_state(), "nuke_from_orbit")
        self.assertEqual(out["verdict"], "DENY")


class ProbeTests(unittest.TestCase):
    def test_probe_localhost_returns_real_data(self):
        out = server.t_probe_target(fresh_state(),
                                    {"target": "self-vm",
                                     "probes": ["identity", "memory"]})
        ident = out["results"]["identity"]
        self.assertTrue(ident["ok"], ident)
        self.assertEqual(ident["data"]["hostname"], os.uname().nodename)
        mem = out["results"]["memory"]
        self.assertTrue(mem["ok"], mem)
        self.assertGreater(mem["data"]["total_mb"], 1000)

    def test_freeform_command_rejected(self):
        with self.assertRaises(server.ToolError):
            server.t_probe_target(fresh_state(),
                                  {"target": "self-vm",
                                   "command": "cat /etc/shadow"})
        with self.assertRaises(server.ToolError):
            server.t_probe_target(fresh_state(),
                                  {"target": "self-vm",
                                   "probes": ["rm_rf"]})

    def test_argv_uses_templates_and_declared_channels(self):
        target = {"name": "future", "channel": "ssh",
                  "ssh_destination": "vm.example.invalid",
                  "address": "vm.example.invalid"}
        argv = server.probe_argv(target, server.PROBE_TEMPLATES["identity"])
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", " ".join(argv))
        self.assertEqual(argv[-1], server.PROBE_TEMPLATES["identity"])
        local = server.probe_argv({"name": "self-vm", "channel": "local"},
                                  server.PROBE_TEMPLATES["disk"])
        self.assertEqual(local[:2], ["/bin/sh", "-c"])
        self.assertEqual(local[2], server.PROBE_TEMPLATES["disk"])


class FleetAndLedgerTests(unittest.TestCase):
    def test_fleet_snapshot_stored_and_receipted(self):
        state = fresh_state()
        snap = server.t_fleet_snapshot(state, {})
        self.assertEqual(snap["targets"]["self-vm"]["status"], "ok")
        self.assertEqual(len(state["snapshots"]), 1)
        self.assertTrue(any(r["type"] == "fleet_snapshot"
                            for r in state["receipts"]))

    def test_receipts_chain_includes_denials(self):
        state = fresh_state()
        evaluate(state, "destroy")                 # DENY, receipted
        evaluate(state, "metrics_read")            # ALLOW, receipted
        out = server.t_receipt_list(state, {})
        self.assertTrue(out["chain_valid"])
        evals = [r for r in out["receipts"]
                 if r["type"] == "policy_evaluation"]
        verdicts = {r["detail"]["verdict"] for r in evals}
        self.assertEqual(verdicts, {"ALLOW", "DENY"})

    def test_receipt_chain_detects_tamper(self):
        state = fresh_state()
        evaluate(state, "metrics_read")
        state["receipts"][0]["detail"]["verdict"] = "DENY"
        self.assertFalse(server.verify_receipt_chain(state["receipts"]))


if __name__ == "__main__":
    unittest.main()

# Eclipse Constellation MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
