# Agent Extension Protocol (AXP)

A runtime-neutral standard for **describing** a packaged agent capability
(memory backends, tools, services, skills…) and **installing, updating, and
verifying** it on a specific agent runtime — Hermes, OpenClaw, or others.

AXP is an **envelope, not a package manager.** It does not replace a
runtime's own install machinery; it delegates to it. AXP is the common
description layer every runtime can be generated from or mapped onto — the
role OCI image manifests play across container runtimes, or OpenAPI plays
across HTTP servers.

## What AXP gives you

1. **Abstract description** (`identity` / `provides` / `requires` /
   `permissions`) — what the extension offers, runtime-independent.
2. **Per-runtime targets** (`targets[]`) — concrete install recipes for each
   platform it supports (delivery method, lifecycle hooks, component map).
3. **Safe updates** — semver + channels (`stable`/`beta`/`alpha`/`dev` +
   custom), three update sources (`github`/`feed`/`direct`, all auto-updating),
   monotonic version progression, and freshness (`valid_until`) for freeze
   resistance.
4. **Signing & trust** — ed25519 detached signatures with Trust-On-First-Use
   key pinning, "updates only from the same key," and a simple no-brick key
   rotation path. Signing is optional but recommended; unsigned extensions
   install with a clear warning.
5. **Graceful degradation** — every shell target ships a standalone,
   idempotent `install.sh` (plus `uninstall`/`upgrade`/`health`) that runs on
   a host with zero AXP support. The security layer lives in the AXP-aware
   host; a hand-run install opts out of it, exactly like any `curl | bash`.

## Layout

- [`SPEC.md`](SPEC.md) — the full draft specification (v0.2).
- [`schema/agent-extension.schema.json`](schema/agent-extension.schema.json) —
  JSON Schema for validating manifests.
- [`docs/SIGNING.md`](docs/SIGNING.md) — how to sign, pin, and rotate keys.
- [`examples/graph-memory/`](examples/graph-memory/) — a complete worked
  example (temporal graph memory on FalkorDB) exercising every component type,
  with a full manifest and standalone lifecycle scripts.

## Status

**Draft v0.2** — the core shape is stable; field names may still change before
v1.0. Open questions are tracked at the end of [`SPEC.md`](SPEC.md).

## License

MIT — see [LICENSE](LICENSE).
