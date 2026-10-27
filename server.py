#!/usr/bin/env python3
# Eclipse Constellation MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai

"""Eclipse Constellation MCP — v0.1.0 (governance core + SSH-observe adapter).

Powered by Cyan Eclipse Technologies (cetech.ai).

Eclipse Constellation — the governed, vendor-neutral VM fleet layer for
agents: one policy, one receipt ledger, every cloud and hypervisor
underneath.

V0.1 IS OBSERVE-ONLY. There are NO mutation code paths in this file —
no start/stop/destroy/snapshot execution, no provisioning, nothing that
changes any machine. Lifecycle actions exist only as policy
EVALUATIONS (policy_evaluate -> ALLOW/DENY + reasons + preconditions)
against DECLARED targets. Execution adapters are a later phase behind
an owner gate (spec phases C1+).

What v0.1 does:
  * Target Registry — only DECLARED targets exist. A target that is
    not in targets.json is invisible to every tool (Device Registry
    doctrine). v0.1 declares exactly one target: this VM itself
    ("self-vm", channel "local"). The Eclipse Connect droplet is NOT
    declared in v0.1 — its migration is owner-gated per spec SS6.4.
  * Policy engine — the Agent Wallet pattern transposed to machines:
    quotas as caps (arithmetic shown on refusal), image + network
    allowlists, TTL + purpose required for creations, the
    snapshot-before-mutation precondition ("no snapshot receipt, no
    mutation" — mechanical, not advisory), destructive operations
    classified Tier 3 and approval-gated. EVERY evaluation — ALLOW or
    DENY — appends a hash-chained receipt. Refusals are receipts too.
  * SSH observe adapter — read-only probes over the target's DECLARED
    channel ("ssh" = system ssh client; "local" = this host, for the
    self target — this VM runs no sshd, and this build does not start
    one). Probes are FIXED COMMAND TEMPLATES from an allowlist. There
    is NO free-form remote command execution in v0.1; that is law,
    stated here and enforced in probe_target.
  * Fleet state — probes aggregate into a stored, receipted fleet
    snapshot with per-target freshness.

Snapshot-receipt binding (v0.1 semantics, stated plainly): until real
execution adapters land (C1+), a "snapshot receipt" is the ALLOW
evaluation receipt of a snapshot_create action for the same target,
recorded in this ledger, fresh within policy.snapshot_fresh_seconds.
C1 adapters will record execution receipts of the same shape; the
precondition check does not change.

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0), stdlib only.
State:   $ECLIPSE_CONSTELLATION_STATE  or ./data/state.json
Targets: $ECLIPSE_CONSTELLATION_TARGETS or ./targets.json
Policy:  $ECLIPSE_CONSTELLATION_POLICY  or ./policy.json
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent
STATE_PATH = Path(os.environ.get(
    "ECLIPSE_CONSTELLATION_STATE", BASE / "data" / "state.json"))
TARGETS_PATH = Path(os.environ.get(
    "ECLIPSE_CONSTELLATION_TARGETS", BASE / "targets.json"))
POLICY_PATH = Path(os.environ.get(
    "ECLIPSE_CONSTELLATION_POLICY", BASE / "policy.json"))

# ---------------------------------------------------------------- probes
# FIXED command templates. These strings are module constants. No user
# input — from tool arguments, target records, or anywhere else — is
# ever interpolated into them. A probe is chosen by NAME from this
# allowlist or it does not run.
PROBE_TEMPLATES = {
    "identity": "hostname && uname -srm && grep '^PRETTY_NAME=' /etc/os-release",
    "uptime": "cat /proc/uptime && uptime",
    "disk": "df -P -h",
    "memory": "free -m",
    "services": "(systemctl list-units --type=service --state=running "
                "--no-legend --no-pager 2>/dev/null | awk '{print $1}') "
                "|| ps -eo comm=",
}
PROBE_TIMEOUT_S = 20
SNAPSHOT_KEEP = 20  # fleet snapshots retained in state

# ---------------------------------------------------------------- policy
# Safety tiers (spec SS5). Tier 3 = destructive, human confirmation
# every time. In v0.1 NO Tier-3 evaluation can return ALLOW: the
# approval channel is not wired in an observe-only build, and that is
# stated in every Tier-3 verdict's reasons.
ACTION_TIERS = {
    "inventory": 0, "metrics_read": 0, "patch_read": 0, "compliance_read": 0,
    "power_on": 1, "power_off": 1, "clone": 1,
    "provision": 2, "resize": 2, "snapshot_create": 2, "exec_push": 2,
    "console_ticket": 2, "image_change": 2, "rollout": 2,
    "destroy": 3, "network_change": 3, "snapshot_delete": 3,
}
# Mutations of an existing machine require a fresh snapshot receipt
# (spec SS4). destroy requires one too: the ephemeral-expiry path is
# snapshot-the-final-state THEN destroy (spec SS4), so a destroy with
# no snapshot on record is a destroy with no evidence.
REQUIRES_SNAPSHOT = {"resize", "image_change", "exec_push", "rollout",
                     "destroy"}
CREATION_ACTIONS = {"provision", "clone"}  # TTL + purpose discipline
IMAGE_ACTIONS = {"provision", "clone"}     # image allowlist applies
CONSOLE_TICKET_MAX_MIN = 240


class ToolError(Exception):
    pass


def now() -> int:
    return int(time.time())


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------ state
def empty_state() -> dict:
    return {"receipts": [], "snapshots": []}


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return empty_state()


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=1))


def load_json_file(path: Path, what: str) -> dict:
    if not path.exists():
        raise ToolError(f"{what} file not found: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ToolError(f"{what} file is not valid JSON ({path}): {e}")


def load_targets() -> list:
    return load_json_file(TARGETS_PATH, "targets registry").get("targets", [])


def load_policy() -> dict:
    return load_json_file(POLICY_PATH, "policy")


def find_target(targets: list, name: str):
    for t in targets:
        if t.get("name") == name:
            return t
    return None


# --------------------------------------------------------------- receipts
def emit_receipt(state: dict, rtype: str, detail: dict) -> dict:
    prev = state["receipts"][-1]["hash"] if state["receipts"] else "GENESIS"
    entry = {"seq": len(state["receipts"]) + 1, "ts": now(), "type": rtype,
             "prev_hash": prev, "detail": detail}
    entry["hash"] = sha(canon({k: entry[k] for k in
                               ("seq", "ts", "type", "prev_hash", "detail")}))
    state["receipts"].append(entry)
    return entry


def verify_receipt_chain(receipts) -> bool:
    prev = "GENESIS"
    for e in receipts:
        if e.get("prev_hash") != prev:
            return False
        expect = sha(canon({k: e.get(k) for k in
                            ("seq", "ts", "type", "prev_hash", "detail")}))
        if e.get("hash") != expect:
            return False
        prev = e["hash"]
    return True


# ---------------------------------------------------------- policy engine
def desk_usage(targets: list) -> dict:
    """Declared-resource usage, derived from the registry itself: each
    declared target is one governed machine with declared resources.
    Returns {desk: {vcpu, ram_gb, disk_gb, vm_count}} + a 'fleet' total."""
    usage = {}
    fleet = {"vcpu": 0, "ram_gb": 0, "disk_gb": 0, "vm_count": 0}
    for t in targets:
        desk = t.get("desk", "default")
        res = t.get("declared_resources", {})
        u = usage.setdefault(desk, {"vcpu": 0, "ram_gb": 0,
                                    "disk_gb": 0, "vm_count": 0})
        for k in ("vcpu", "ram_gb", "disk_gb"):
            u[k] += res.get(k, 0) or 0
            fleet[k] += res.get(k, 0) or 0
        u["vm_count"] += 1
        fleet["vm_count"] += 1
    usage["fleet"] = fleet
    return usage


def _check(checks, name, ok, detail):
    checks.append({"check": name, "result": "pass" if ok else "fail",
                   "detail": detail})
    return ok


def _snapshot_receipt_status(state, policy, target_name, params):
    """Returns (ok, detail). A qualifying snapshot receipt is an ALLOW
    evaluation of snapshot_create for this target, fresh per policy."""
    seq = params.get("snapshot_receipt_seq")
    if seq is None:
        return False, "no snapshot_receipt_seq supplied"
    for r in state["receipts"]:
        if r.get("seq") == seq:
            d = r.get("detail", {})
            if not (r.get("type") == "policy_evaluation"
                    and d.get("action") == "snapshot_create"
                    and d.get("target") == target_name
                    and d.get("verdict") == "ALLOW"):
                return False, (f"receipt {seq} is not an ALLOW "
                               f"snapshot_create evaluation for "
                               f"'{target_name}'")
            age = now() - r.get("ts", 0)
            fresh = policy.get("snapshot_fresh_seconds", 86400)
            if age > fresh:
                return False, (f"snapshot receipt {seq} is stale: "
                               f"{age}s old > {fresh}s freshness window")
            return True, f"snapshot receipt {seq}, {age}s old (fresh)"
    return False, f"snapshot receipt {seq} not found in the ledger"


def evaluate(state, targets, policy, args) -> dict:
    actor = args.get("actor") or {}
    agent, desk = actor.get("agent"), actor.get("desk")
    target_name = args.get("target")
    action = args.get("action")
    params = args.get("params") or {}
    checks, reasons = [], []

    # Identity is bound, never anonymous (spec SS4).
    if not agent or not desk:
        reasons.append("actor identity missing: evaluations require "
                       "actor.agent and actor.desk — identity is bound, "
                       "never anonymous")
        _check(checks, "identity_bound", False, "actor incomplete")
    else:
        _check(checks, "identity_bound", True, f"{agent} ({desk})")

    target = find_target(targets, target_name) if target_name else None
    if target is None:
        reasons.append(f"target '{target_name}' is not declared in the "
                       f"registry — undeclared targets are invisible")
        _check(checks, "target_declared", False, "not in targets registry")
    else:
        _check(checks, "target_declared", True, target_name)

    tier = ACTION_TIERS.get(action)
    if tier is None:
        reasons.append(f"unknown action '{action}' — not in the "
                       f"Constellation action taxonomy")
        _check(checks, "action_known", False, str(action))
    else:
        _check(checks, "action_known", True, f"tier {tier}")

    if target is not None and tier is not None:
        # --- snapshot-before-mutation precondition (mechanical) ---
        if action in REQUIRES_SNAPSHOT:
            ok, detail = _snapshot_receipt_status(state, policy,
                                                   target_name, params)
            if not _check(checks, "snapshot_precondition", ok, detail):
                reasons.append(f"snapshot-before-mutation precondition "
                               f"unmet: {detail} — no snapshot receipt, "
                               f"no mutation")
        # --- image allowlist ---
        if action in IMAGE_ACTIONS:
            images = {i["name"]: i for i in policy.get("images", [])}
            img = params.get("image")
            if not img:
                _check(checks, "image_allowlist", False, "no image named")
                reasons.append("no image specified — creations boot "
                               "only from registered images")
            elif img not in images:
                _check(checks, "image_allowlist", False,
                       f"'{img}' not registered")
                reasons.append(f"image '{img}' is not on the allowlist "
                               f"— an unregistered image is refused")
            elif params.get("image_sha256") and \
                    params["image_sha256"] != images[img].get("sha256"):
                _check(checks, "image_allowlist", False, "hash mismatch")
                reasons.append(f"image '{img}' hash mismatch vs the "
                               f"registered hash — refused")
            else:
                _check(checks, "image_allowlist", True, img)
        # --- network allowlist ---
        if action in IMAGE_ACTIONS or action == "network_change":
            net = params.get("network")
            if net is not None:
                ok = net in policy.get("networks", [])
                if not _check(checks, "network_allowlist", ok, str(net)):
                    reasons.append(f"network '{net}' is not on the "
                                   f"allowlist — joining a new network "
                                   f"is a policy change, not a flag")
        # --- TTL + purpose for creations (ephemeral by default) ---
        if action in CREATION_ACTIONS:
            ttl = policy.get("ttl", {})
            if not params.get("purpose"):
                _check(checks, "purpose_tag", False, "missing")
                reasons.append("no purpose tag — every agent-created "
                               "machine is born with a purpose")
            else:
                _check(checks, "purpose_tag", True, params["purpose"])
            hours = params.get("ttl_hours", ttl.get("default_hours", 24))
            ceiling = ttl.get("ceiling_hours", 168)
            if not isinstance(hours, (int, float)) or hours <= 0:
                _check(checks, "ttl_within_ceiling", False, str(hours))
                reasons.append(f"ttl_hours '{hours}' is not a positive "
                               f"number of hours")
            elif hours > ceiling:
                _check(checks, "ttl_within_ceiling", False,
                       f"{hours}h > {ceiling}h ceiling")
                reasons.append(f"ttl {hours}h exceeds the {ceiling}h "
                               f"ceiling — permanence is a human grant, "
                               f"never an agent default")
            else:
                _check(checks, "ttl_within_ceiling", True,
                       f"{hours}h (default applied: "
                       f"{'ttl_hours' not in params})")
        # --- quotas are caps (creations consume) ---
        if action in CREATION_ACTIONS:
            usage = desk_usage(targets)
            count = params.get("count", 1)
            req = {"vcpu": (params.get("vcpu", 0) or 0) * count,
                   "ram_gb": (params.get("ram_gb", 0) or 0) * count,
                   "disk_gb": (params.get("disk_gb", 0) or 0) * count,
                   "vm_count": count}
            quotas = policy.get("quotas", {})
            scopes = (("desk", desk, quotas.get("desks", {}).get(
                        desk, quotas.get("desks", {}).get("default", {}))),
                      ("fleet", "fleet", quotas.get("fleet", {})))
            for scope_name, scope_key, cap in scopes:
                used = usage.get(scope_key, {})
                for k, want in req.items():
                    cap_v = cap.get(k)
                    if cap_v is None or want == 0:
                        continue
                    have = used.get(k, 0)
                    if have + want > cap_v:
                        _check(checks, f"quota_{scope_name}_{k}", False,
                               f"{have} in use + {want} requested = "
                               f"{have + want} > cap {cap_v}")
                        reasons.append(
                            f"{scope_name} quota exceeded for {k}: "
                            f"{have} in use + {want} requested = "
                            f"{have + want} > cap {cap_v} — refused "
                            f"with the arithmetic shown")
                    else:
                        _check(checks, f"quota_{scope_name}_{k}", True,
                               f"{have} + {want} <= {cap_v}")
        # --- declared exec channel for exec pushes ---
        if action == "exec_push":
            ok = bool(target.get("channel"))
            if not _check(checks, "exec_channel_declared", ok,
                          str(target.get("channel"))):
                reasons.append("target declares no exec channel — the "
                               "layer never improvises one")
        # --- console tickets are time-boxed ---
        if action == "console_ticket":
            mins = params.get("expires_minutes", 60)
            ok = isinstance(mins, (int, float)) and 0 < mins <= \
                CONSOLE_TICKET_MAX_MIN
            if not _check(checks, "console_timebox", ok, f"{mins} min"):
                reasons.append(f"console ticket expiry '{mins}' outside "
                               f"1..{CONSOLE_TICKET_MAX_MIN} minutes")
        # --- Tier 3: destructive, approval-gated, never in v0.1 ---
        if tier == 3:
            _check(checks, "human_approval", False,
                   "approval channel not wired in v0.1")
            reasons.append("destructive operation — Tier 3 requires "
                           "explicit human confirmation every time; "
                           "v0.1 is observe-only and the approval "
                           "channel is not wired, so this evaluation "
                           "cannot ALLOW")

    verdict = "DENY" if reasons else "ALLOW"
    detail = {"actor": {"agent": agent, "desk": desk}, "target": target_name,
              "action": action, "tier": tier, "verdict": verdict,
              "reasons": reasons, "checks": checks,
              "params_sha256": sha(canon(params))}
    receipt = emit_receipt(state, "policy_evaluation", detail)
    return {"verdict": verdict, "target": target_name, "action": action,
            "tier": tier, "reasons": reasons, "checks": checks,
            "receipt_seq": receipt["seq"]}


# ------------------------------------------------------------- ssh observe
def probe_argv(target: dict, template: str) -> list:
    """Build the argv for one probe. The template is always one of the
    PROBE_TEMPLATES constants — never caller-supplied text."""
    channel = target.get("channel")
    if channel == "local":
        return ["/bin/sh", "-c", template]
    if channel == "ssh":
        dest = target.get("ssh_destination") or target.get("address")
        return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=accept-new", dest, template]
    raise ToolError(f"target '{target.get('name')}' declares channel "
                    f"'{channel}', which v0.1 does not implement "
                    f"(declared channels: local, ssh)")


def _parse_identity(out: str) -> dict:
    lines = [l for l in out.splitlines() if l.strip()]
    d = {"hostname": lines[0].strip() if lines else None}
    if len(lines) > 1:
        parts = lines[1].split()
        d["kernel"] = " ".join(parts[:3]) if len(parts) >= 3 else lines[1]
    for l in lines:
        if l.startswith("PRETTY_NAME="):
            d["os"] = l.split("=", 1)[1].strip().strip('"')
    return d


def _parse_uptime(out: str) -> dict:
    lines = [l for l in out.splitlines() if l.strip()]
    d = {}
    if lines:
        nums = lines[0].split()
        if len(nums) >= 2:
            try:
                d["up_seconds"] = float(nums[0])
                d["idle_seconds"] = float(nums[1])
            except ValueError:
                pass
    if len(lines) > 1:
        d["summary"] = lines[1].strip()
    return d


def _parse_disk(out: str) -> dict:
    rows = []
    for l in out.splitlines()[1:]:
        parts = l.split()
        if len(parts) >= 6 and parts[4].endswith("%"):
            rows.append({"filesystem": parts[0], "size": parts[1],
                         "used": parts[2], "avail": parts[3],
                         "use_pct": parts[4], "mount": parts[5]})
    return {"filesystems": rows[:20], "count": len(rows)}


def _parse_memory(out: str) -> dict:
    for l in out.splitlines():
        if l.startswith("Mem:"):
            p = l.split()
            keys = ("total_mb", "used_mb", "free_mb", "shared_mb",
                    "buff_cache_mb", "available_mb")
            return {k: int(v) for k, v in zip(keys, p[1:7])
                    if v.isdigit()}
    return {}


def _parse_services(out: str) -> dict:
    names = [l.strip() for l in out.splitlines()
             if l.strip() and not l.strip().startswith("UNIT")]
    names = [n.split()[0] for n in names]
    return {"running": names[:100], "count": len(names)}


_PARSERS = {"identity": _parse_identity, "uptime": _parse_uptime,
            "disk": _parse_disk, "memory": _parse_memory,
            "services": _parse_services}


def run_probe(target: dict, probe_name: str) -> dict:
    template = PROBE_TEMPLATES[probe_name]
    argv = probe_argv(target, template)
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=PROBE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"probe timed out after "
                                      f"{PROBE_TIMEOUT_S}s"}
    except OSError as e:
        return {"ok": False, "error": f"probe transport failed: {e}"}
    if p.returncode != 0:
        err = (p.stderr or "").strip().splitlines()
        return {"ok": False, "error": f"probe exited {p.returncode}: "
                                      f"{err[0] if err else 'no stderr'}"}
    return {"ok": True, "data": _PARSERS[probe_name](p.stdout)}


def probe_target_impl(state, targets, target, probe_names) -> dict:
    results = {}
    for name in probe_names:
        results[name] = run_probe(target, name)
    receipt = emit_receipt(state, "probe", {
        "target": target["name"], "channel": target.get("channel"),
        "probes": {n: r["ok"] for n, r in results.items()}})
    return {"target": target["name"], "channel": target.get("channel"),
            "results": results, "receipt_seq": receipt["seq"]}


# ------------------------------------------------------------------ tools
def t_target_list(state, args):
    targets = load_targets()
    public = [{"name": t.get("name"), "kind": t.get("kind"),
               "address": t.get("address"), "channel": t.get("channel"),
               "owner_agent": t.get("owner_agent"), "desk": t.get("desk"),
               "declared_resources": t.get("declared_resources"),
               "purpose": t.get("purpose")} for t in targets]
    return {"targets": public, "count": len(public),
            "note": "Only DECLARED targets exist. Undeclared targets "
                    "are invisible to every Constellation tool."}


def t_policy_evaluate(state, args):
    return evaluate(state, load_targets(), load_policy(), args)


def t_probe_target(state, args):
    if "command" in args or "cmd" in args or "shell" in args:
        raise ToolError("free-form remote commands are refused: v0.1 "
                        "probes are fixed templates from an allowlist, "
                        "chosen by name — there is no command argument")
    targets = load_targets()
    target = find_target(targets, args.get("target"))
    if target is None:
        raise ToolError(f"target '{args.get('target')}' is not declared "
                        f"— undeclared targets are invisible")
    names = args.get("probes") or list(PROBE_TEMPLATES)
    for n in names:
        if n not in PROBE_TEMPLATES:
            raise ToolError(f"unknown probe '{n}' — allowlist: "
                            f"{sorted(PROBE_TEMPLATES)}")
    return probe_target_impl(state, targets, target, names)


def t_fleet_snapshot(state, args):
    targets = load_targets()
    snap_targets, statuses = {}, {}
    last_by_name = {}
    if state["snapshots"]:
        last_by_name = state["snapshots"][-1].get("targets", {})
    for t in targets:
        res = probe_target_impl(state, targets, t, list(PROBE_TEMPLATES))
        ok_count = sum(1 for r in res["results"].values() if r["ok"])
        if ok_count == len(res["results"]):
            status = "ok"
        elif ok_count:
            status = "degraded"
        else:
            status = "unreachable"
        entry = {"status": status, "channel": t.get("channel"),
                 "owner_agent": t.get("owner_agent"), "desk": t.get("desk"),
                 "declared_resources": t.get("declared_resources"),
                 "probed_at": now(), "freshness_seconds": 0,
                 "stale": False, "probes": res["results"]}
        if status == "unreachable" and t["name"] in last_by_name:
            prev = last_by_name[t["name"]]
            entry["last_known"] = prev.get("probes")
            entry["stale"] = True
            entry["freshness_seconds"] = now() - prev.get("probed_at", now())
        snap_targets[t["name"]] = entry
        statuses[t["name"]] = status
    snap = {"snapshot_id": f"snap-{len(state['snapshots']) + 1}",
            "generated_at": now(), "targets": snap_targets}
    state["snapshots"] = (state["snapshots"] + [snap])[-SNAPSHOT_KEEP:]
    receipt = emit_receipt(state, "fleet_snapshot",
                           {"snapshot_id": snap["snapshot_id"],
                            "target_statuses": statuses})
    snap["receipt_seq"] = receipt["seq"]
    return snap


def t_receipt_list(state, args):
    limit = args.get("limit", 50)
    rtype = args.get("type")
    receipts = state["receipts"]
    if rtype:
        receipts = [r for r in receipts if r.get("type") == rtype]
    return {"receipts": receipts[-limit:], "count": len(receipts),
            "chain_valid": verify_receipt_chain(state["receipts"])}


TOOLS = {
    "target_list": (t_target_list,
                    "List DECLARED targets only (name, kind, address, "
                    "declared channel, owner agent, desk, declared "
                    "resources). Undeclared targets are invisible.",
                    {}, []),
    "policy_evaluate": (t_policy_evaluate,
                        "Evaluate a lifecycle action against policy — "
                        "evaluation ONLY, nothing executes (v0.1 is "
                        "observe-only). Returns ALLOW/DENY + reasons + "
                        "per-check results; every evaluation is "
                        "receipted, DENYs included. Args: actor "
                        "{agent, desk}, target, action, params.",
                        {"actor": {"type": "object"},
                         "target": {"type": "string"},
                         "action": {"type": "string"},
                         "params": {"type": "object"}},
                        ["actor", "target", "action"]),
    "probe_target": (t_probe_target,
                     "Run read-only probes against a DECLARED target "
                     "over its declared channel. Probes are FIXED "
                     "templates chosen by name (identity, uptime, disk, "
                     "memory, services) — there is no free-form command "
                     "argument, by law.",
                     {"target": {"type": "string"},
                      "probes": {"type": "array",
                                 "items": {"type": "string"}}},
                     ["target"]),
    "fleet_snapshot": (t_fleet_snapshot,
                       "Probe every declared target and store a "
                       "receipted fleet snapshot with per-target "
                       "status and freshness.",
                       {}, []),
    "receipt_list": (t_receipt_list,
                     "List ledger receipts (evaluations incl. DENYs, "
                     "probes, snapshots) and verify the hash chain.",
                     {"limit": {"type": "integer"},
                      "type": {"type": "string"}}, []),
}


def tool_list():
    return [{"name": name, "description": desc,
             "inputSchema": {"type": "object", "properties": props,
                             "required": req}}
            for name, (_, desc, props, req) in TOOLS.items()]


def handle(req: dict):
    method, rid = req.get("method", ""), req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req.get("params", {}).get(
                "protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-constellation",
                           "version": "0.1.0"}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tool_list()}}
    if method == "tools/call":
        name = req["params"]["name"]
        args = req["params"].get("arguments", {})
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": f"unknown tool {name}"}}
        state = load_state()
        try:
            out = TOOLS[name][0](state, args)
            save_state(state)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=1)}]}}
        except ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps({"error": str(e)})}],
                "isError": True}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    return None  # notification


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
        except Exception as e:  # never crash the transport
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32603, "message": str(e)}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

# Eclipse Constellation MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
