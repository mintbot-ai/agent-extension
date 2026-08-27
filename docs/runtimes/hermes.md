# Runtime profile: `hermes`

Hermes (the agent framework; hosts include mintbot's agent plugin). This
profile is the evolution of the pre-AXP `hermes-integration` manifest; a
Hermes host reads both.

## Runtime id / version

`runtime: "hermes"`. `runtime_version` is the Hermes **package version** —
what `hermes --version` prints first (`Hermes Agent v0.20.0 (2026.8.3)` →
`0.20.0`) and what `hermes_cli.__version__` exposes — matched with the SPEC §4.3
grammar (`>=0.18`). The parenthesised release date is not the version.

## Delivery

- `archive` — preferred for new manifests.
- `hermes-integration` — legacy block, byte-compatible with the pre-AXP
  manifest: `install_url`, `install_sha256`, `uninstall_command`,
  `requires_oauth` (`"claude"` | `"codex"` | null), plus optional publisher
  extras (`url_slug`, `default_model`, …) the host records verbatim. A host
  treats it as `archive` + the OAuth precondition. `uninstall_command` is
  honoured for records created before the host retained artifacts; new installs
  run `lifecycle.uninstall` from `AXP_ARTIFACT_DIR`.

## Scopes

| scope             | path                                     |
|-------------------|------------------------------------------|
| `hermes:skills`   | `$HERMES_HOME/skills/`                   |
| `hermes:plugins`  | `$HERMES_HOME/plugins/`                  |
| `hermes:memories` | `$HERMES_HOME/memories/`                 |
| `config`          | `$HERMES_HOME/` (config.yaml is rewritten atomically, so the dir) |
| `secrets`         | `$HERMES_HOME/env*` (read-only)          |
| `workspace`       | the session's working directory          |

`HERMES_HOME` defaults to `~/.hermes`. v0.2 manifests that wrote bare
`skills:rw` are read as `hermes:skills:rw`.

## Environment

SPEC §6.2 plus `AXP_HERMES_HOME` (= `HERMES_HOME`) and `AXP_HERMES_VERSION`.

## Component realisation

- `skills` — `dir` linked or copied into `hermes:skills` (`link: symlink|copy`).
- `tools` — a Hermes plugin package (`module`) placed under `hermes:plugins`;
  Hermes discovers it on restart. `register`/`unregister` are the package's
  entrypoints the host may call.
- `mcp_servers` — `register: "auto"` adds the server to Hermes's MCP config
  (`mcp_servers.<name>` in `config.yaml`; a name already taken by another
  extension is registered as `<ext-name>-<server>`). On a Sandboxed host a
  stdio server is registered as a `systemd-run --pipe` wrapper around the
  `command` (or the component's `command_ref` inside the retained artifact),
  so Hermes spawns it contained.
- `prompts` — fragment appended to the persona overlay (host-specific).
- `cron` — a Hermes cron job (host-side) or a `systemd:` timer (script-side).
- `services` — `command` → a host-owned `mintbot-ext-<publisher>-<name>-svc-
  <service>.service` the host writes, enables and removes; `unit: systemd:<x>`
  → the unit the install script created, re-affirmed after install / stopped
  before uninstall and, on a Sandboxed host, given a containment drop-in.

## Enforcement

- `advisory` for lifecycle scripts (systemd-run sandbox derived from
  `permissions`; see posix profile). Egress is enforced **by name** through a
  host-run allow-list proxy, so wildcards are enforced too. `root: true` →
  filesystem half off, no systemd → `declared`; all recorded.
- `enforced` for the runtime components the host launches itself:
  `services` (host-owned unit or drop-in) and stdio `mcp_servers`
  (`systemd-run --pipe` wrapper), each behind a per-extension egress proxy —
  see HOST-GUIDE, "Runtime containment". The install record lists the tier
  per component under `containment`; a component that refuses to start
  contained runs bare and is reported `declared` with the reason.
- Runtime code of a Hermes *plugin* (`tools`, `hooks`, `channels`,
  `model_providers`, `memory`) executes inside the Hermes process and is
  **not** contained; an extension providing only those caps at `advisory`.

## Consent

A Hermes host that installs via an LLM tool call performs consent in two
steps: the first call returns the permission summary and runs nothing; the
second call carries an explicit `consented: true` given by the user in the
conversation (or in the host's UI). Consent is recorded with the install.
