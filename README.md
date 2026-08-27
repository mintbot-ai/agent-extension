# Agent Extension Protocol (AXP)

A runtime-neutral standard for **describing** a packaged agent capability
(memory backends, MCP servers, tools, channels, services, skills…) and
**installing, updating, and verifying** it on any agent runtime — or on a bare
POSIX machine.

AXP is an **envelope, not a package manager.** It does not replace a
runtime's own install machinery; it delegates to it. It is the common
description layer every runtime can be generated from or mapped onto — the
role OCI image manifests play across container runtimes, or OpenAPI across
HTTP servers. Nothing in the core names a vendor, a product, or a registry.

## What AXP gives you

1. **Portable description** — `identity` (publisher-namespaced) / `provides`
   (MCP servers, tools, services, memory, skills, prompts, channels, model
   providers, hooks, cron, config) / `requires` / `permissions`.
2. **Per-runtime targets** — concrete install recipes per runtime, plus a
   **`posix` baseline** any host can execute with `archive` delivery and
   standalone lifecycle scripts.
3. **A host ↔ script contract** — standard `AXP_*` environment, a 0600 dotenv
   config/secrets file, host-retained artifacts so upgrade/uninstall/health
   always work.
4. **Safe updates** — semver + channels, three update sources, monotonic
   progression, freshness (`valid_until`), per-extension policy.
5. **Signing & trust** — ed25519 with Trust-On-First-Use pinning per extension
   id, "updates only from the same key", no-brick rotation, unsigned ratchet.
6. **Honest enforcement** — declared permissions, a tier (`declared` /
   `advisory` / `enforced`) the host really applies, and host conformance
   profiles (Core / Trusted / Managed / Sandboxed).
7. **Forward compatibility** — unknown fields and component types are ignored
   by rule, vendor extensions are `x-` namespaced, runtime extras are
   `<runtime>:` namespaced.

## Layout

- [`SPEC.md`](SPEC.md) — the specification (draft v0.4).
- [`schema/agent-extension.schema.json`](schema/agent-extension.schema.json) —
  JSON Schema for manifests;
  [`schema/agent-extension-keys.schema.json`](schema/agent-extension-keys.schema.json)
  for the publisher key directory (§8.5).
- [`docs/HOST-GUIDE.md`](docs/HOST-GUIDE.md) — implementing a host, profile
  by profile, with the package calls that do the work.
- [`docs/SIGNING.md`](docs/SIGNING.md) — sign, pin, rotate, recover.
- [`docs/runtimes/`](docs/runtimes/) — runtime profiles (`posix`, `hermes`,
  `openclaw`, `claude-code`). Adding a runtime = adding a profile document.
- [`examples/graph-memory/`](examples/graph-memory/) — a complete worked
  example with `posix`, `hermes` and `claude-code` targets and standalone
  lifecycle scripts. It is a neutral spec fixture (the conformance tests use
  it); the real, published package lives in
  [mintbot-ai/graph-memory](https://github.com/mintbot-ai/graph-memory)
  (`mintbot.ai/graph-memory`), released with `axp release`.
- [`CHANGELOG.md`](CHANGELOG.md).

## Reference implementation: the `axp` package

This repo ships a runtime-neutral Python reference implementation —
validation, JCS canonicalization, ed25519 signing with TOFU pinning, target
selection — plus the `axp` CLI. No hard dependencies: signing uses the
`cryptography` package when importable and falls back to the `openssl` CLI.

```bash
pip install -e .            # or: pip install -e .[dev] for tests

# publisher side — a release is three commands
axp init --publisher ext.example.com --name my-ext --description "…"
axp keygen --out signing.key            # prints the ed25519:… public form
axp release agent-extension.json --bump patch \
    --artifact dist/my-ext.tar.gz --key signing.key
# (release = set version, follow version-in-URL, fill real sha256s,
#  stamp published_at/valid_until, sign, validate — in one step;
#  add --prev-key old.key for a key-rotation release)
axp verify agent-extension.json --artifact dist/my-ext.tar.gz   # the file you are about to upload?
axp keydir --publisher ext.example.com --key ed25519:…@my-ext \
    -o agent-extension-keys.json        # serve at /.well-known/agent-extension-keys.json

# host side
axp validate agent-extension.json
axp verify agent-extension.json --pinned ed25519:…          # against the pinned key
axp verify agent-extension.json --keydir agent-extension-keys.json   # listed by the publisher?
axp target agent-extension.json --runtime hermes --runtime posix --runtime-version hermes=0.20.0
```

Host authors: read [docs/HOST-GUIDE.md](docs/HOST-GUIDE.md) and reuse
`PinStore.decide()/commit()` (the §8 trust decision), `validate` /
`select_target`, and the `axp.updates` / `axp.versions` rules instead of
reimplementing them — the conformance suite then covers your host too.

## Conformance

`conformance/` is an executable check of the SPEC §11 host profiles (Core +
Trusted). Run it against the reference implementation with `pytest
conformance/`, or against your own host by implementing the three-method
adapter — see [conformance/README.md](conformance/README.md).

## Status

**Draft v0.4** — v0.3 made the core runtime-neutral, v0.4 hardened trust
(publisher key directory, transactional pinning) and update semantics. Field
names may still change before v1.0; open questions are at the end of
`SPEC.md`. CI runs the suite on Python 3.10 and 3.13, with and without the
`cryptography` wheel.

## Contributing

Issues and pull requests welcome — especially new runtime profiles. Core
changes go through `SPEC.md` + schema + example together, with a CHANGELOG
entry.

## License

MIT — see [LICENSE](LICENSE).
