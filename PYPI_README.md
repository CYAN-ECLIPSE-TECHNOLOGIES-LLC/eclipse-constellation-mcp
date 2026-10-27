# eclipse-constellation

**What this is:** `eclipse-constellation` is the MCP server edition
of **Eclipse Constellation** — Cyan Eclipse Technologies' governed,
vendor-neutral VM fleet layer for agents: one policy, one receipt
ledger, every cloud and hypervisor underneath. Policy is written by a
human, checked *before* anything executes, and every decision is
ledgered.

**What this is not:** v0.1 contains **no mutation code paths at all**.
Nothing in this build can start, stop, resize, snapshot, or destroy a
machine — lifecycle actions exist only as policy *evaluations* that
return ALLOW/DENY with reasons.

## Use

```console
$ pip install eclipse-constellation
$ eclipse-constellation     # MCP server over stdio
```

Or run it as a container: `ghcr.io/cyan-eclipse-technologies-llc/eclipse-constellation-mcp:0.1.0`.

Local stdio transport, Python stdlib only. The only target probed is
the host itself, over its declared channel.

## Tools (5)

| Tool | What it does |
|---|---|
| `target_list` | Lists **declared** targets only. Undeclared targets are invisible to every tool. |
| `policy_evaluate` | Evaluates a lifecycle action against policy — quotas, image + network allowlists, TTL + purpose discipline, snapshot-before-mutation precondition, Tier-3 approval gating. Returns ALLOW/DENY + reasons. **Evaluates only; never executes.** |
| `probe_target` | Read-only probes against a declared target via **fixed command templates chosen by name** (`identity`, `uptime`, `disk`, `memory`, `services`). No free-form command argument. |
| `fleet_snapshot` | Probes every declared target and stores a receipted fleet snapshot. |
| `receipt_list` | Lists ledger receipts (evaluations incl. DENYs, probes, snapshots) and verifies the append-only hash chain. |

## Honest scope

- **Observe-only in v0.1.** ALLOW is a policy verdict, not an action.
  Execution adapters are later-phase, behind an owner gate.
- **No Tier-3 ALLOW in v0.1.** Destroy, network changes, and snapshot
  deletion require explicit human confirmation every time; the
  approval channel is not wired, so Tier-3 evaluations always DENY,
  with the reason stated.
- A policy verdict is not an endorsement and not a Bazaar listing
  claim.

Powered by Cyan Eclipse Technologies LLC (cetech.ai) — a Veteran-Owned
Small Business. MIT licensed.
