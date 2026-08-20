# Changelog

## unreleased

- Publisher tooling: `axp init` writes a structurally valid v0.3 manifest
  skeleton (all-zero digest placeholders, posix target by default) and
  `axp release` performs a whole release in one step — explicit `--version`
  or `--bump major|minor|patch`, version-in-URL rewrite, real sha256 per
  archive target from `--artifact [runtime=]path`, `published_at` /
  `valid_until` stamping, optional `--key` signing, validation before
  anything is written (unsigned releases succeed with a loud warning).
- Reference implementation: the `axp` Python package (`axp.manifest`
  validation + target selection, `axp.jcs` RFC 8785 canonicalization,
  `axp.signing` ed25519 sign/verify with the TOFU `PinStore`) and the `axp`
  CLI (`validate | canonicalize | keygen | sign | verify | target`). No hard
  dependencies; signing works via the `cryptography` package or the openssl
  CLI.
- Conformance suite (`conformance/`): executable SPEC §11 checks for the
  Core and Trusted host profiles, runnable against any host through a
  three-method adapter (reference adapter included).
- The graph-memory example manifest is now really signed (with the
  committed, explicitly untrusted `example-signing.key`) so
  `axp verify examples/graph-memory/agent-extension.json` works out of the box.

## v0.3 (draft, 2026-08-19) — universality revision

Breaking (v0.2 → v0.3 migration table in SPEC §13):

- `identity.publisher` (DNS name) is required; the extension id is
  `<publisher>/<name>`. Key pinning, state and dependencies key on the id.
- `provides.persona` → `provides.prompts` (`persona` still read as alias).
- `requires.extensions` entries are objects `{ id, version }`.
- Filesystem scopes are runtime-neutral (`state`, `cache`, `config`,
  `secrets`, `workspace`, `system`); runtime scopes are namespaced
  (`hermes:skills:rw`).
- `signing.public_key` is the raw 32-byte ed25519 key, base64 (was ambiguous).
- `delivery.uninstall_command` is no longer the uninstall path: the host
  retains the unpacked artifact (`AXP_ARTIFACT_DIR`) and runs
  `lifecycle.uninstall` from there (`hermes-integration` keeps the field for
  legacy records).

Added:

- `posix` baseline runtime + `archive` delivery method (every host supports it).
- Host ↔ script contract (§6): standard `AXP_*` env, `AXP_CONFIG_FILE` dotenv
  handoff for config + secrets, exit-code semantics, health output.
- `permissions.network_ingress`, `permissions.secrets`, per-permission `reason`.
- `targets[].platforms`.
- `provides.mcp_servers`, `channels`, `model_providers`, `hooks`;
  `identity.keywords`, `identity.i18n`; `requires.commands`.
- Explicit forward-compatibility rule (§2.4) and namespacing (§2.3); schema
  made permissive where the rule says "ignore".
- Version-constraint grammar (§4.3).
- `updates.source.kind: forge` for non-GitHub forges; canonical filename and
  release-asset rules.
- Host conformance profiles (§11) and runtime profile documents
  (`docs/runtimes/`), moving all Hermes/OpenClaw specifics out of the core.
- `claude-code` runtime profile (draft).

## v0.2 (draft) — updates, channels, ed25519 signing + rotation, mandatory
   standalone lifecycle scripts.

## v0.1 (draft) — spec, JSON Schema, graph-memory example.
