# Deployment

## The constraint that shapes everything

A remote MCP connector is dialled **from Anthropic's infrastructure to your
server**, not from the user's laptop into your network. Claude Desktop's local
MCP is a separate mechanism and does not apply to claude.ai or Cowork surfaces.

So "point a Live Artifact dashboard at our internal harness" is not a
configuration detail. It means either publishing an authenticated endpoint to the
internet, or accepting that the dashboard reads a different (sanitised) copy of
the data than the executor writes.

Verify the current connector behaviour against Anthropic's docs before you design
around it — this is the part of the stack most likely to have moved.

---

## Option A — company remote MCP

```mermaid
flowchart TD
    AC["Anthropic infrastructure"] -->|OAuth 2.1 + TLS| GW
    subgraph dmz["DMZ"]
        GW["API gateway<br/>rate limit · WAF · mTLS"]
    end
    GW --> MCP["AgentSec MCP Gateway"]
    MCP --> SVC["HarnessService"]
    SVC --> H["Purple Harness + staging agents"]
```

**Needs:** OAuth/OIDC, company RBAC mapped to AgentSec roles, TLS, an API gateway,
rate limiting, audit shipping, network policy, and a data-minimisation review of
everything the gateway can return.

**Suits:** a team that already runs authenticated internal APIs for SaaS
consumption and has an owner for this one.

**Cost that is easy to underestimate:** you are exposing your purple-team control
plane to the internet. Even fully read-only, the responses describe your agents'
capabilities, your detection rules and your unfixed findings — a good target
package for anyone who gets in. Run `AGENTSEC_MCP_READ_ONLY=1` and treat the
allowlist as a published document.

---

## Option B — local POC (start here)

```mermaid
flowchart TD
    CC["Claude Code<br/>on a developer machine"] -->|stdio| MCP["agentsec-mcp"]
    MCP --> SVC["HarnessService"]
    SVC --> H["Local harness<br/>fixtures or local staging"]
    SVC --> R["Static HTML report<br/>SQLite results"]
```

Everything stays on one machine. No inbound network, no OAuth, no gateway.

```bash
pip install -e '.[mcp]'
claude mcp add agentsec -- agentsec-mcp    # or add to .mcp.json
```

```jsonc
// .mcp.json
{
  "mcpServers": {
    "agentsec": {
      "command": "agentsec-mcp",
      "env": { "AGENTSEC_WORKSPACE": "/abs/path/to/agentsec" }
    }
  }
}
```

**Validates, without any infrastructure commitment:** whether the Scenario
Contract expresses your real threats; whether your agents emit enough telemetry
for the evidence axis to be checkable at all; whether your Wazuh rules fire on
agent-layer attacks; whether the four-axis verdict tells your team something they
did not already know.

That last question is the one worth answering before building option A. If the
verdicts are not changing decisions, no amount of dashboard will fix it.

---

## Option C — hybrid (the realistic first team rollout)

```mermaid
flowchart TD
    LA["Live Artifact"] -->|remote MCP, read-only| RG["Report gateway<br/>AGENTSEC_MCP_READ_ONLY=1"]
    RG --> RO[("Sanitised results<br/>read replica")]
    CC["Claude Code"] -->|local MCP| EX["Execution harness"]
    EX --> DB[("Results + evidence")]
    DB -->|export + redact| RO
    CI["CI runner"] --> EX
```

Execution stays inside the network. The dashboard reads a redacted export.
Nothing internet-reachable can start a run — not by policy, but because
`start_run` is not registered on that process.

### What each side of that boundary holds

The export step used to be described here as work you had to write yourself. It
ships now, in `reporting/publish.py`, and the line it draws is between *declared
configuration* and *observed data*:

* **Declared configuration** — what an operator wrote in `policy/targets.yaml`,
  what a scenario author committed and a reviewer merged — has already been
  through review and already has its credentials withheld. It crosses.
* **Observed data** — transcript turns, span attributes, alert fields, tenant
  ids, audit detail — is whatever the system under test happened to emit. In a
  cross-tenant scenario that is, by construction, the record that leaked. It is
  projected, never passed through.

| | Execution host (local) | Report gateway (`AGENTSEC_MCP_READ_ONLY=1`) |
|---|---|---|
| Raw evidence bundle | on disk under `results/`, referenced by `run.evidence_ref` | not served, not referenced |
| `agentsec://runs/{run_id}/evidence` | projected: turn digests, pseudonymous principals, attribute keys without values | not registered |
| `agentsec://audit` | full rows | not registered |
| `agentsec://targets/{target_id}` | principals, executors, capabilities | not registered |
| `agentsec://runs/{run_id}` | projected run: no `evidence_ref`, no `raw_ref`, no approval token | same projection |
| `agentsec://coverage`, `findings`, `scenarios`, `targets` | served | served |

Raw evidence is a local capability on purpose. An investigator working an
incident reads the bundle off the execution host — as a file, or through the
report the CLI renders there. Nothing that crosses the MCP boundary carries it,
on either gateway, because the difference between the two is which URIs exist
rather than how carefully each one is rendered.

**What the projection keeps.** Redaction that costs the reader the finding is
not worth deploying. Verdicts, axis statuses, failed checks, rule ids, alert
levels, tool names and decisions all survive intact — the assertion text quotes
values declared in the contract, so it survives too. What goes is the payload:
turn content becomes a digest, free-form maps keep their keys and lose their
values, principals and tenant ids become stable pseudonyms that still correlate
across turns so the pivot remains visible.

**Pseudonyms are not anonymisation.** They preserve correlation without printing
the identifier. The identifier space is small and the default salt ships in the
source, so anyone holding both can invert them by enumeration. Set
`AGENTSEC_PSEUDONYM_SALT` per deployment when the reader is less trusted than
whoever can read the repository.

**Adding a resource is a decision, not a default.** Every `ResourceSpec` names a
publication policy, and the gateway refuses to start if one names a policy that
does not exist. A new resource whose output nobody has vetted fails on the
machine of whoever added it rather than serving a raw model in production.

The published shapes are versioned — `reporting.publish.PUBLISH_SCHEMA_VERSION`,
with the rollup described by `schemas/dashboard.schema.json` — so a Live Artifact
or MCP App can pin against them.

**Recommended sequencing:**

| Phase | Add | Gate before moving on |
|---|---|---|
| 1 | Option B, one agent, 4–6 scenarios | verdicts are changing engineering decisions |
| 2 | CI gate on the `pr` profile | the gate has caught a real regression |
| 3 | Option C read-only dashboard | someone outside the security team reads it weekly |
| 4 | Option A with RBAC and approvals | more than one team is authoring scenarios |

Skipping to phase 3 produces a dashboard nobody opens, because there is nothing
on it yet.

---

## Environment variables

| Variable | Purpose |
|---|---|
| `AGENTSEC_WORKSPACE` | workspace root holding `scenarios/`, `policy/`, `results/` |
| `AGENTSEC_DB` | override the SQLite path (CI often points this at a cache) |
| `AGENTSEC_ACTOR` | who is acting, recorded on every audit row |
| `AGENTSEC_MCP_READ_ONLY` | `1` runs the report gateway: non-read-only tools are not registered, and only the allowlisted resources are served |
| `AGENTSEC_PSEUDONYM_SALT` | salt for the principal/tenant/actor labels in published output; defaults to a value that ships in the source |
| `AGENTSEC_ALLOW_EXTERNAL_HOSTS` | comma-separated hosts exempt from the private-address check |
| target-specific | credential variable *names* come from `policy/targets.yaml`; the values live only in the environment |

No credential is ever written in a scenario, a target file, or a tool argument.

---

## Hardening checklist for options A and C

- [ ] `AGENTSEC_MCP_READ_ONLY=1` on any internet-reachable gateway
- [ ] OAuth scopes mapped to tool risk tiers (`read` / `write` / `execute`)
- [x] Evidence redaction on the export path — assume transcripts contain the leak
      (`reporting/publish.py`; the projection is asserted against the
      cross-tenant corpus in `tests/test_publish_redaction.py`)
- [ ] `AGENTSEC_PSEUDONYM_SALT` set, if the dashboard's readers should not be
      able to invert principal labels by enumeration
- [ ] Approvals in your change-management system, not the YAML ledger
- [ ] `audit_log` shipped to the SIEM, including refusals
- [ ] Per-target rate limits enforced at the gateway as well as in policy
- [ ] The allowlist reviewed like a firewall change, by someone who did not write it
- [ ] Staging data is synthetic; verify this rather than assuming it
- [ ] Egress policy on the runner, so a compromised target cannot use it as a pivot
