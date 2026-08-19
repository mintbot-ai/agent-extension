# Runtime profile: `openclaw` (draft)

OpenClaw plugins are distributed through ClawHub, a central signed registry.
An AXP manifest's OpenClaw target delegates delivery *and* trust to it.

## Runtime id / version

`runtime: "openclaw"`; `runtime_version` is OpenClaw's calver (`2026.3.x`).

## Delivery

`clawhub` — `package` (registry name), `min_registry_version`. The host asks
the local OpenClaw installation to install that package; ClawHub's registry
signature is the trust root for the bytes, and the AXP manifest signature (if
any) binds the *description* to the publisher. The host records which root it
relied on. `archive` MAY also be used for side-loaded plugins.

## Scopes

`openclaw:plugins`, `openclaw:channels`, `openclaw:skills` → the corresponding
OpenClaw config directories; core scopes as usual.

## Environment

SPEC §6.2 plus `AXP_OPENCLAW_HOME`.

## Component realisation

OpenClaw's own manifest is capability-declared (channels, tools, hooks,
skills, model providers, speech). `provides` maps 1:1: `channels`, `tools`,
`hooks`, `skills`, `model_providers`; `mcp_servers` register through
OpenClaw's MCP client config.

## Enforcement

OpenClaw enforces its manifest-driven security for plugin runtime code, so a
host MAY report `enforced` for components OpenClaw contains (declared
capabilities only) and `advisory` for lifecycle scripts.
