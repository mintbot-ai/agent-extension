# Agent Extension Protocol (AXP)

A runtime-neutral standard for **describing** a packaged agent capability
(memory backends, tools, services, skills…) and **installing** it on a
specific agent runtime — Hermes, OpenClaw, or others.

AXP is an **envelope, not a package manager.** It does not replace a
runtime's own install machinery; it delegates to it. AXP is the common
description layer every runtime can be generated from or mapped onto — the
role OCI image manifests play across container runtimes, or OpenAPI plays
across HTTP servers.

## Two layers

1. **Abstract description** (`identity` / `provides` / `requires` /
   `permissions`) — what the extension offers, runtime-independent.
2. **Per-runtime targets** (`targets[]`) — concrete install recipes for each
   platform it supports (delivery method, lifecycle hooks, component map).

See [`SPEC.md`](SPEC.md) for the full draft (v0.1), the JSON Schema in
[`schema/`](schema/), and a worked example in
[`examples/graph-memory/`](examples/graph-memory/).

## Status

**Draft v0.1** — for discussion. Field shapes may change before v1.0.

## License

MIT — see [LICENSE](LICENSE).
