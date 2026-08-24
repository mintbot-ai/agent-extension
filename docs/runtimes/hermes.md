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
- `mcp_servers` — `register: "auto"` adds the server to Hermes's MCP config.
- `prompts` — fragment appended to the persona overlay (host-specific).
- `cron` — a Hermes cron job (host-side) or a `systemd:` timer (script-side).
- `services` — `systemd:` unit actions after install / before uninstall.

## Enforcement

- `advisory` for lifecycle scripts (systemd-run sandbox derived from
  `permissions`; see posix profile). Egress is enforced **by name** through a
  host-run allow-list proxy, so wildcards are enforced too. `root: true` →
  filesystem half off, no systemd → `declared`; all recorded.
- Runtime code of a Hermes plugin executes inside the Hermes process and is
  **not** contained; a Hermes host never reports `enforced`.

## Consent

A Hermes host that installs via an LLM tool call performs consent in two
steps: the first call returns the permission summary and runs nothing; the
second call carries an explicit `consented: true` given by the user in the
conversation (or in the host's UI). Consent is recorded with the install.
