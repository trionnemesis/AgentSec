# Claude Desktop — the report gateway

Row 2 of the table in [`docs/deployment.md`](../../docs/deployment.md): a local
MCP server loaded by the desktop app, which is what a **locally-running Cowork
session** can reach. `.mcp.json` in the repository root is a different mechanism
— it is Claude Code's project registration and the desktop app does not read it.

Everything here registers the server **read-only**. That is not a suggestion in
the description; `AGENTSEC_MCP_READ_ONLY=1` is set in the registration itself, so
the process that Desktop starts has no execution tools registered at all. A model
cannot plan around a tool that is absent from the listing, and a Live Artifact
bound to this server cannot start a run however it is prompted.

## Install

```bash
pip install 'agentsec[mcp]'        # or `pip install -e '.[mcp]'` from a checkout
cd /path/to/your/repository
agentsec init                      # writes .agentsec/project.yaml — review and commit it
```

Then register the server, either by installing the bundle:

1. Build a bundle from this directory using the current Anthropic packaging tool.
2. Install it in Claude Desktop and pick your repository when it asks for the
   **project directory**.

or by hand, which needs no packaging tool at all:

1. Copy the `mcpServers` entry from
   [`claude_desktop_config.example.json`](claude_desktop_config.example.json)
   into your `claude_desktop_config.json`.
2. Set `AGENTSEC_WORKSPACE` to your repository's absolute path.
3. Restart Claude Desktop.

**On `manifest.json`.** The desktop bundle format has been renamed at least once
(DXT → MCP Bundle), so verify the current key names against Anthropic's
documentation before you publish one — this repository does not vendor a copy of
that spec and cannot tell you which is current today. Three things in that file
are not subject to that churn and are asserted by
[`tests/test_packaging.py`](../../tests/test_packaging.py):

| Pinned | Why |
|---|---|
| `command: agentsec-mcp` | the console script this package installs; a rename breaks the build, not a user |
| `AGENTSEC_MCP_READ_ONLY=1` | the capability boundary. Without it this entry is an execution host with a dashboard attached |
| workspace comes from `user_config` | directory selection at the process boundary. No AgentSec tool takes a path ([ADR 0003](../../docs/adr/0003-constrained-mcp-tools.md)) |

## What this gateway can and cannot do

| | Report gateway (here) | Execution host (`.mcp.json`, or the CLI) |
|---|---|---|
| Tools | the 8 read-only ones | all 11 |
| `agentsec_start_run` | **not registered** | registered, and needs an approval for high-risk scenarios |
| `agentsec_promote_finding` | not registered | registered |
| `agentsec_generate_report` | not registered — it writes files | registered |
| Resources | the 6 published | all 9 |
| `agentsec://runs/{id}/evidence` | not registered | registered, projected |
| `agentsec://audit` | not registered | registered |

`agentsec://dashboard/latest` is served here and is what a dashboard polls. It is
computed in memory: reading it, filtering it and refreshing it write nothing and
change nothing.

## Smoke test

Reproducible, and the parts a machine can check are checked by the test suite —
`tests/test_packaging.py` asserts steps 3, 4 and 6 against the real registration
without a desktop app. Steps 1, 2, 5 and 7 need a person at the application, so
they are written to be followed rather than claimed:

| # | Step | Expected |
|---|---|---|
| 1 | Open the repository folder in Claude Desktop / Cowork | the folder is the one with `.agentsec/project.yaml` |
| 2 | Check the MCP server connected | `agentsec-report` is listed and connected |
| 3 | Ask it to list its tools | 8 tools, none of them `agentsec_start_run` |
| 4 | Ask it to read `agentsec://dashboard/latest` | a document with `project`, `purple` and `skill_assurance` |
| 5 | Render the Artifact | project id, verdicts, four axes, findings, trend |
| 6 | Note the modification times under `results/` | unchanged by steps 3–5 |
| 7 | Refresh the Artifact | new `generated_at`, `results/` still unchanged |

If step 3 lists `agentsec_start_run`, the registration lost
`AGENTSEC_MCP_READ_ONLY=1` — fix that before going further, because everything
below it in this table is then being read from an execution host.

## Renaming the server

`agentsec-report` is a name you may change. `hooks/guard_agentsec.py` matches
AgentSec tools on any segment of the MCP name, so a renamed entry keeps its
argument check — but only in a Claude Code session, since that hook is this
repository's and Desktop does not run it. The closed tool schemas and the
resource allowlist travel with the server and apply everywhere.
