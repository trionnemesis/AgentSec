# Claude Code Live Artifact workflow

The Live Artifact is AgentSec's primary runtime display in Claude Code. It is a
self-contained, read-only presentation of the current project's published
dashboard DTO. It is not the public GitHub Pages introduction, and it is not a
page that calls the local AgentSec MCP server after publication.

Claude Code's documented boundary is important: a local MCP server can provide
data while Claude builds a page, but a published page cannot call that local
server. Published pages may call only connectors available through the user's
Claude account. See the official
[Claude Code Artifacts documentation](https://code.claude.com/docs/en/artifacts).

## Build and publish

In the Claude Code session that has the selected AgentSec project and read-only
report gateway:

1. Read `agentsec://dashboard/latest`.
2. Keep repository risks, scenario IDs, run IDs, all four axes, and
   `recorded` / `mixed` / `live` provenance distinct. Preserve empty, error, and
   `not_tested` states.
3. Render the projected DTO as self-contained HTML using AgentSec's existing
   dashboard template. Do not add raw evidence, audit references, approval
   tokens, paths, queries, principals, or tenant data.
4. Publish that HTML as a Live Artifact from Claude Code.
5. Use `/artifacts`, or attach the existing Artifact URL, when the same Artifact
   should be used in a later Claude Code conversation.

The Artifact page is a snapshot. It has no direct local-stdio connection and
must not start a run, mutate a finding, or recalculate a verdict.

## Refresh the same Artifact

A refresh is another Claude Code session operation:

1. Re-read `agentsec://dashboard/latest`.
2. Re-render the same self-contained template from the new projected DTO.
3. Republish the existing Artifact at the same URL.

Do not add browser-side code that calls the local report gateway. Do not describe
opening or refreshing the published page itself as a data fetch.

## Acceptance boundary

Schema validation and local desktop/mobile HTML checks prove the projected DTO
and template render correctly. They do not prove the Claude Code publish,
attachment, same-URL refresh, or no-mutation flow. That acceptance requires a
real Claude Code client and remains open until a person records those steps.

The older Claude Desktop/Cowork packaging and its manual smoke test in
[#20](https://github.com/trionnemesis/AgentSec/issues/20) are a separate legacy
optional-client path. Completing #20 does not prove the Claude Code workflow.
