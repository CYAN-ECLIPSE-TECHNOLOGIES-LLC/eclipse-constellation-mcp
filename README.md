# Eclipse Constellation MCP

**Powered by Cyan Eclipse Technologies** — https://cetech.ai

**Eclipse Constellation — the governed, vendor-neutral VM fleet layer for agents: one policy, one receipt ledger, every cloud and hypervisor underneath.**

## Why this exists

Every cloud and hypervisor now ships its own agent surface, and each one owns exactly its own estate. What none of them provides is the layer above: who may do what to a machine, under whose authority, within what limits — and the receipts to prove it afterwards. Constellation is that layer. It is the Agent Wallet pattern transposed from money to machines: policy is written by a human, checked *before* anything executes, and every decision is ledgered.

## Status — honest labels

v0.1.0, spec phase **C0+ (fleet state + policy evaluation)**. **OBSERVE-ONLY: this build contains no mutation code paths at all.** Nothing in this file can start, stop, resize, snapshot, or destroy a machine — lifecycle actions exist only as policy *evaluations* that return ALLOW/DENY with reasons. Local stdio transport, Python stdlib only. The only target probed is this host itself, over its declared channel. **No certification claimed — bench pending.**

Explicitly NOT in v0.1, by spec and by the build's safety brief:

- **No execution adapters.** ALLOW is a policy verdict, not an action. Execution lands in phase C1+ behind an owner gate.
- **No Tier-3 ALLOW.** Destroy, network changes, and snapshot deletion require explicit human confirmation every time; the approval channel is not wired in v0.1, so Tier-3 evaluations always DENY here, with the reason stated.
- **The Eclipse Connect droplet is NOT a declared target.** Its migration (spec §6.4: declare → read → snapshot discipline → gated mutation) is owner-gated; v0.1 declares this VM only.

## Tools (5)

| Tool | What it does |
|---|---|
| `target_list` | Lists **declared** targets only: name, kind, address, declared channel, owner agent, desk, declared resources. Undeclared targets are invisible to every tool. |
| `policy_evaluate` | Evaluates a lifecycle action against policy — quotas (arithmetic shown on refusal), image + network allowlists, TTL + purpose discipline, the snapshot-before-mutation precondition, Tier-3 approval gating. Returns ALLOW/DENY + reasons + per-check results. **Every evaluation is receipted, DENYs included.** Evaluates only; never executes. |
| `probe_target` | Read-only probes against a declared target over its declared channel. Probes are **fixed command templates chosen by name** (`identity`, `uptime`, `disk`, `memory`, `services`). There is no free-form command argument — that is law in v0.1, enforced in the tool. |
| `fleet_snapshot` | Probes every declared target and stores a receipted fleet snapshot with per-target status, probe results, and freshness. |
| `receipt_list` | Lists ledger receipts (evaluations incl. DENYs, probes, snapshots) and verifies the append-only hash chain. |

## The registry doctrine

Targets are **declared**, never discovered or improvised: `targets.json` is the fleet's Device Registry. Each target declares its kind, address, channel (`local` for this host — it runs no sshd, and this build does not start one; `ssh` for future declared remote targets, via the system ssh client in batch mode), owner agent, desk, and declared resources. A target with no declared channel is inventory-only; the layer never invents one.

Shipped registry v0.1: one target, `self-vm` — this VM (2 vCPU / 8 GB declared). Declared-resource figures in `targets.json` and image hashes in `policy.json` are **declared metadata**: the image entries are named registry slots whose real hashes land when the first allowlisted images are registered at C1.

## The policy core (spec §4, as evaluated)

- **Quotas are caps.** Per-desk and fleet ceilings on vCPU, RAM, disk, VM count. A creation that would breach a cap is refused with the arithmetic in the reason string.
- **Image + network allowlists.** Creations boot only from registered images (name, and hash when supplied); targets join only declared networks. A new network is a policy change, not a runtime flag.
- **Snapshot-before-mutation is mechanical.** `resize`, `image_change`, `exec_push`, `rollout`, and `destroy` require a fresh snapshot receipt for the same target. No snapshot receipt, no mutation — checked, not advised.
- **Ephemeral by default.** Creations require a purpose tag and a TTL within the policy ceiling (default 24h, ceiling 168h). Permanence is a human grant.
- **Identity is bound.** Every evaluation names its actor (agent + desk). Anonymous evaluations are denied.
- **Receipts are the product.** Append-only, hash-chained, GENESIS-anchored — evaluations, probes, and snapshots all land in the same ledger (`data/state.json`, overridable via env).

**Snapshot-receipt binding (v0.1 semantics, stated plainly):** until execution adapters land, a qualifying snapshot receipt is the ALLOW evaluation receipt of a `snapshot_create` action for the same target, fresh within `policy.snapshot_fresh_seconds` (24h). C1 adapters will record execution receipts of the same shape; the precondition check does not change.

## Run it

```bash
python3 server.py            # MCP over stdio, stdlib only, no dependencies
python3 smoke.py             # end-to-end smoke over real stdio (temp state)
python3 -m unittest discover tests   # test suite
```

Env overrides: `ECLIPSE_CONSTELLATION_STATE`, `ECLIPSE_CONSTELLATION_TARGETS`, `ECLIPSE_CONSTELLATION_POLICY`.

## Roadmap (spec §8)

C1 — lifecycle execution under policy on the first declared adapter (owner-gated; the droplet migration is its own owner decision). C2 — exec + console layers over declared channels. C3 — a second substrate behind the same policy core, which is when the vendor-neutrality claim becomes testable, then sayable.

---

A Cyan Eclipse Technologies product. The "Powered by Cyan Eclipse Technologies" attribution travels with it.
