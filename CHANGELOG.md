# Changelog

## unreleased

- `sign_manifest(…, prev_private_key_pem=…)` / `axp sign --prev-key` /
  `axp release --prev-key`: the dual-signed rotation release (SPEC 8.3) can
  now be produced by the tooling instead of by hand; a re-sign always drops
  a stale `signature_prev`; the same key on both sides is refused.
- `axp verify --artifact FILE` checks that a file's sha256 is one the
  manifest signs (release.artifact or an archive target) before upload.
- SPEC: a published version is immutable (7.0); manifests SHOULD stay under
  64 KiB and hosts MAY cap artifact download / unpack sizes (3.1, 5.2); the
  `^`/`~` constraint semantics are spelled out and `axp.versions` is
  normative (4.3); no grace window for expired candidates and the
  once-then-monthly cadence also for failing sources (7.4); rotation
  tooling named (8.3). HOST-GUIDE: apply what you checked, re-install is an
  upgrade, errors are not nags, purge semantics, the wildcard-listener caveat
  of `IPAddressAllow`.

- SPEC 9: an origin that can never be the publisher's own (a code forge, a
  CDN) proves nothing about identity — hosts SHOULD require a signed
  manifest for such locators and name the foreign origin in the consent
  prompt; HOST-GUIDE covers the repository-locator resolution order.
- `schema/agent-extension-keys.schema.json` for the publisher key directory
  (SPEC 8.5); the manifest schema identifies as 0.4.
- `axp verify --keydir FILE` checks that the signing key is one the
  publisher lists for the extension; `examples/graph-memory/` ships a key
  directory so the check runs out of the box.
- `docs/HOST-GUIDE.md`: implementing a host profile by profile with the
  package calls that do the work, plus a pre-flight checklist.
- CI (GitHub Actions): tests + conformance on Python 3.10/3.13 with the
  `cryptography` wheel and openssl-only; the worked example round-trips
  through the CLI; both schemas validate their example documents.
- Package ships `py.typed`.
- SPEC v0.4 (draft, additive): publisher key directory
  `/.well-known/agent-extension-keys.json` as the second trust channel for
  key rotation and lost-key recovery (8.5); the tracked channel is host
  state preserved across updates (7.2); `valid_until` guidance — optional,
  generous windows, warn once then monthly, expired candidates refused
  (7.4); the consent ratchet for updates with normative coverage rules
  (7.6); `AXP_SPEC_VERSION` is the host's version, `AXP_ARTIFACT_DIR` is the
  running hook's own artifact (6.2); Managed profile evaluates
  `runtime_version` and `requires.extensions` with the 4.3 grammar (11).
- Reference implementation: `axp.versions` (the 4.3 constraint grammar and
  one ordering for semver + calver, pre-release aware), `axp.updates`
  (channel rule, policy grammar, freshness, `permissions_widened` with the
  7.6 coverage semantics), `select_target(runtime_versions=…)` honours
  `runtime_version`; `PinStore.decide()` is pure and `commit()` persists —
  a failed download or hook can no longer leave a pin behind; `decide()`
  takes the publisher key directory (`directory_keys`) and returns the new
  `recover` action; `parse_key_directory` / `key_directory_url`.
- CLI: `axp release --valid-days` defaults to 180 (0 omits `valid_until`);
  `axp target --runtime-version RUNTIME=VERSION`; new `axp keydir` writes
  the key directory document.
- Conformance: Trusted profile gains the key-directory rotation case
  (optional adapter method `evaluate_trust_with_directory`).
- Runtime profiles: `hermes` `runtime_version` is the Hermes package version
  (`0.20.0`), not the release date; the graph-memory example now says
  `>=0.18` (re-signed). Advisory enforcement is described as name-based
  egress through a host-run proxy (wildcards enforced) — the
  "wildcard → network not filtered" downgrade is gone.

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
