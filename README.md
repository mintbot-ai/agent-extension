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

- [`SPEC.md`](SPEC.md) — the specification (draft v0.3).
- [`schema/agent-extension.schema.json`](schema/agent-extension.schema.json) —
  JSON Schema for validating manifests.
- [`docs/SIGNING.md`](docs/SIGNING.md) — sign, pin, rotate.
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
#  stamp published_at/valid_until, sign, validate — in one step)

# host side
axp validate agent-extension.json
axp verify agent-extension.json --pinned ed25519:…
axp target agent-extension.json --runtime hermes --runtime posix
```

Host authors: reuse `axp.signing.PinStore` (the §8 trust state machine) and
`axp.manifest.validate` / `select_target` instead of reimplementing them.

## Conformance

`conformance/` is an executable check of the SPEC §11 host profiles (Core +
Trusted). Run it against the reference implementation with `pytest
conformance/`, or against your own host by implementing the three-method
adapter — see [conformance/README.md](conformance/README.md).

## Status

**Draft v0.3** — the universality revision. Field names may still change
before v1.0; open questions are at the end of `SPEC.md`.

## Contributing

Issues and pull requests welcome — especially new runtime profiles. Core
changes go through `SPEC.md` + schema + example together, with a CHANGELOG
entry.

## License

MIT — see [LICENSE](LICENSE).
