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
  lifecycle scripts.
- [`CHANGELOG.md`](CHANGELOG.md).

## Status

**Draft v0.3** — the universality revision. Field names may still change
before v1.0; open questions are at the end of `SPEC.md`. A reference host
library + conformance suite (`conformance/`) is the next deliverable.

## Contributing

Issues and pull requests welcome — especially new runtime profiles. Core
changes go through `SPEC.md` + schema + example together, with a CHANGELOG
entry.

## License

MIT — see [LICENSE](LICENSE).
