# Runtime profile: `posix` (baseline, normative)

The `posix` target is AXP's universality guarantee: any POSIX machine with a
shell and `tar` can install it, with no knowledge of any agent runtime. Every
host MAY fall back to a `posix` target when no runtime-specific target matches
(SPEC §5.1).

## Runtime id / version

`runtime: "posix"`. `runtime_version` is not meaningful and SHOULD be omitted;
use `platforms` (`linux/amd64`, `darwin/arm64`, …) to constrain instead.

## Delivery

Only `archive` (`url`, `sha256`, optional `format: tar.gz|zip`). The host
verifies the digest, unpacks into a fresh directory, and retains it as
`AXP_ARTIFACT_DIR` after a successful install (SPEC §6.1).

## Scopes

Exactly the core scopes (SPEC §4.4): `state`, `cache`, `config`, `secrets`,
`workspace`, `system`. On a bare POSIX host `config`, `secrets` and
`workspace` have no runtime behind them; a host MAY map them to nothing (the
script gets no extra writable path) and MUST say so in the install record.

## Environment

Exactly SPEC §6.2, no extras. Default paths when unset:

- root:  `AXP_PREFIX=/opt/<name>`, `AXP_STATE_DIR=/var/lib/axp/<publisher>/<name>`,
  `AXP_CACHE_DIR=/var/cache/axp/<publisher>/<name>`
- user:  `AXP_PREFIX=~/.local/opt/<name>`,
  `AXP_STATE_DIR=~/.local/state/axp/<publisher>/<name>`,
  `AXP_CACHE_DIR=${XDG_CACHE_HOME:-~/.cache}/axp/<publisher>/<name>`

## Component realisation

A `posix` host runs the lifecycle scripts and otherwise treats `component_map`
as informational, except:

- `mcp_servers` with `register: "auto"` — a host that knows how to register an
  MCP server somewhere (it may be a generic MCP client) MAY do so; a bare host
  records the `command`/`url` in the install record so the user can wire it up.
- `services` with a `systemd:`/`launchd:` unit — the host MAY run the listed
  `actions` after `install` and `stop` before `uninstall`; the install script
  MUST already do this itself (SPEC §10 standalone rule), so the host's
  actions are idempotent re-affirmations, never the only path.

## Enforcement

`declared` by default. A host with systemd MAY offer `advisory` for the
lifecycle scripts: a transient unit whose only reachable address is a
host-run egress proxy that decides **by name and port** against
`network_egress` (wildcards included) plus the publisher's own hosts, and
which refuses names that resolve to internal ranges (`IPAddressDeny=any` +
`IPAddressAllow=<proxy>`, declared IP literals and the extension's own
listeners; `HTTPS_PROXY`/`HTTP_PROXY` point at the proxy). Filesystem:
`ProtectSystem=strict` + `ReadWritePaths` for `AXP_PREFIX`, `AXP_STATE_DIR`,
`AXP_CACHE_DIR`, `AXP_ARTIFACT_DIR` and declared `:rw` scopes, `PrivateTmp`.
`root: true` disables the filesystem half; it is recorded. `enforced` is out
of scope for `posix`.
