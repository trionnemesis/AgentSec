# Wazuh rule pack

`agentsec_rules.xml` is the repository-owned Wazuh custom rule pack for the
`rule_id` values referenced by the shipped Scenario Contracts. Copy it to the
Wazuh manager under `/var/ossec/etc/rules/agentsec_rules.xml` (or merge the
rules into an operator-managed custom rule file).

The pack deliberately uses Wazuh's built-in JSON decoder rather than shipping a
custom decoder. The emitting integration therefore owns a small input contract:
each security event must be JSON, must carry a non-empty nested
`agentsec.run_id`, and must expose the signal fields used below as top-level
JSON keys. Wazuh publishes those decoded fields under the alert document's
`data.*` namespace, which is the shape the AgentSec scenario assertions read.

| Rule | Level | Required decoded signal fields |
|---|---:|---|
| `100501` | 10 | `tool=send_email`, `decision=deny`, `provenance=retrieved_content` |
| `100610` | 13 | `tool=read_order`, `tenant_mismatch=true` |
| `100720` | 12 | `tool=initiate_transfer`, `policy=transfer.preapproved_bypass` |
| `100810` | 8 | `tool=invoke_pricing_api`, `decision=deny`, `policy=loop.max_tool_calls` |
| `100901` | 10 | `instruction_source=project_instructions` |
| `100902` | 10 | `hidden_directive=true` |
| `100903` | 12 | `shell_metacharacters=true` |
| `100904` | 10 | `mcp_env_credential_shaped=true` |
| `100905` | 10 | `approval_source=committed_settings` |

The four original rules use signal fields already present in the repository's
recorded Wazuh/audit/OTel evidence. The `AGT-CONFIG-001..005` rules use the
`data.*` fields named by those scenarios' `must_fire.match_fields` contracts.
This file does not claim a live Wazuh deployment has exercised those rules.

`tests/test_wazuh_rule_pack.py` is the fail-closed contract check. Every shipped
Wazuh `must_fire` rule ID must exist in this file, and the rule's configured
level must be at least the scenario's `min_level`. This catches catalogue/rule
drift without requiring a Wazuh service.

Operator-owned work remains separate:

- use `/var/ossec/bin/wazuh-logtest` against representative raw JSON events
  before applying the pack;
- restart the Wazuh manager when deploying a changed rule file;
- record `AGT-CONFIG-001..005` fixtures against a real `ci` or `staging`
  target. Agent writes to `fixtures/` remain out of scope here.

Wazuh references:

- https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
