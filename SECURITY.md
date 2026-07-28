# Security

## Reporting

Open a private security advisory on the repository. Please do not file a public
issue for anything that would let someone reach a system they should not.

## What this tool does, stated plainly

AgentSec executes attacks against AI agents and reads adversarial content by
design — poisoned documents, injected tool responses, hostile transcripts. It is
built on the assumption that some of that content will try to influence the
harness itself.

## Design properties you can rely on

| Property | Where it is enforced |
|---|---|
| `production` is not a valid environment | absent from the enum in `schemas/target.schema.json`; no runtime flag exists |
| HTTP targets must be private/loopback | `policy/allowlist.py`, overridable only via `AGENTSEC_ALLOW_EXTERNAL_HOSTS` |
| No shell / SQL / arbitrary-URL tool on the MCP surface | `tests/test_mcp_contract.py` fails the build |
| Tool schemas are closed | `additionalProperties: false` on every tool |
| Models cannot approve their own runs | no MCP tool grants approvals; `agentsec approve` is CLI-only |
| Approvals are scoped, expiring and single-use | `policy/approvals.py` |
| Credentials never appear in scenarios, targets or tool arguments | `targets.yaml` stores variable *names*; `Target.redacted()` withholds even those |
| Refusals are audited | `audit_log`, including every declined request |
| `payload_ref` cannot traverse out of a scenario directory | `scenario/loader.py` |
| Scenario YAML cannot construct Python objects | `yaml.safe_load` only |
| Tool arguments are stored as a digest, not plaintext | `evidence.schema.json` |

## What is *not* protected

- **The runner is trusted.** Anyone who can run `agentsec` can reach every
  allowlisted target. Treat runner access as target access.
- **`policy/targets.yaml` is the security boundary.** Review changes to it like
  firewall changes, by someone who did not write them.
- **Evidence bundles contain the leak.** A successful cross-tenant test's
  transcript holds the data that leaked. `results/` is gitignored for this reason,
  and any export path to a hosted dashboard needs a redaction step you write.
- **Staging data.** Nothing verifies that your staging environment holds synthetic
  data. Check, rather than assume.

## Running the gateway on a network

Set `AGENTSEC_MCP_READ_ONLY=1` on anything internet-reachable. In that mode
non-read-only tools are refused by the dispatcher, so `start_run` is absent rather
than merely discouraged. See [`docs/deployment.md`](docs/deployment.md) for the
rest of the checklist.
