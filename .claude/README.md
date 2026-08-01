# Claude Code integration

Three pieces, in ascending order of how much they can be talked out of:

| File | Kind | Can a prompt bypass it? |
|---|---|---|
| `skills/agentsec/SKILL.md` | guidance | yes — it is text the model reads |
| `settings.json` `permissions` | harness rule | no |
| `hooks/guard_agentsec.py` | executed code | no |

That ordering is the reason the hook exists. This tool reads adversarial content
by design — poisoned documents, injected tool responses — so anything expressed
only as instructions is one convincing paragraph from being ignored. The hook runs
as a subprocess and returns a decision the harness enforces.

## What the hook refuses

- **Bash commands mentioning a production-looking host.** Deliberately broad
  matching (`prod`, `live`, `.com`, `billing`, …) with an exemption list for
  loopback, `.local`, `.svc`, `.internal` and the `example.*` reserved domains. A
  false refusal costs one clarifying message; a false allow costs an incident.
- **`agentsec run` via Bash.** Not because running is wrong, but because the Bash
  path skips the gateway's audit actor and approval check. Use
  `agentsec_start_run`. Read-only subcommands are allowed.
- **Writes to `policy/targets.yaml`, `policy/approvals.yaml` and `fixtures/`.**
  The allowlist is reviewed like a firewall change, and the fixture corpus is
  recorded evidence. Both are proposed to a human, not written by an agent.
- **AgentSec MCP calls carrying `url`, `sql`, `command`, `token` and similar.**
  Redundant with the closed tool schemas and `tests/test_mcp_contract.py` — kept
  as the third layer because the cost is one dictionary lookup. Scoped to this
  gateway on purpose: `settings.json` matches the hook on `mcp__.*` so that a
  renamed `.mcp.json` entry cannot slip past it, and the hook itself decides
  which calls are AgentSec's. Other servers in the session are left alone, since
  `query` and `headers` are ordinary arguments there and refusing them defends
  nothing.

The hook exits 0 on any internal error. A crashed hook must fail open loudly
rather than wedge the session, and the permission rules in `settings.json` remain
in force regardless.

## Wiring the MCP server

```bash
pip install -e '.[mcp]'
claude mcp add agentsec -- agentsec-mcp
```

Or commit it, so the whole team gets it:

```jsonc
// .mcp.json at the repository root
{
  "mcpServers": {
    "agentsec": {
      "command": "agentsec-mcp",
      "env": { "AGENTSEC_WORKSPACE": "${CLAUDE_PROJECT_DIR}/agentsec" }
    }
  }
}
```

For a read-only session — reviewing results without any possibility of starting a
run — add `"AGENTSEC_MCP_READ_ONLY": "1"`. In that mode `start_run` is refused by
the dispatcher, not merely discouraged.

## Verifying the hook works

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://api.acme-prod.com/v1"}}' \
  | python3 .claude/hooks/guard_agentsec.py

echo '{"tool_name":"Bash","tool_input":{"command":"agentsec run --target x"}}' \
  | python3 .claude/hooks/guard_agentsec.py

# should print nothing and exit 0
echo '{"tool_name":"Bash","tool_input":{"command":"agentsec validate"}}' \
  | python3 .claude/hooks/guard_agentsec.py
```

## Note on paths

This tree is its own repository root, so `settings.json` points the hook at
`"$CLAUDE_PROJECT_DIR/.claude/hooks/guard_agentsec.py"`. It was first committed as
`<repo>/agentsec/` inside `wazuh_ai_agent`; if you vendor it back into a
subdirectory, the hook command needs that prefix again.
