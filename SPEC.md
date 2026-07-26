# Agent Extension Protocol (AXP) — SPEC v0.1 (DRAFT)

> Status: **draft, for discussion.** Not yet implemented. Names and field
> shapes are expected to change before v1.0.

## 1. Purpose

A single, runtime-neutral way to **describe** a packaged agent capability
(a "graph memory", an email tool, a smart-home bridge…) *and* to **install**
it on a specific agent runtime — Hermes, OpenClaw, or others.

The protocol is an **envelope, not a new package manager.** It does not
replace a runtime's own install machinery; it delegates to it. AXP's job is
to be the common description layer that every runtime can be generated from
or mapped onto — the same role an OCI image manifest plays across container
runtimes, or OpenAPI plays across HTTP servers.

Two design goals:

1. A **general, portable description** of what the extension provides
   (works regardless of which agent framework reads it).
2. **Concrete, per-platform install steps** for each runtime it supports.

These map to the two layers below.

## 2. Prior art this builds on

- **Hermes `hermes-integration`** (`install_integration.py`): a *delivery +
  trust* format — publisher-hosted manifest, SHA-256 verification, SSRF
  guard, same-eTLD+1 rule, root-exec install/uninstall, local state file.
  Strong on delivery; has no declarative component model, no `spec_version`,
  no schema, no health/upgrade, no declared permission surface.
- **OpenClaw plugin manifest** (2026.3.x): JSON manifest declaring
  capabilities (channels, tools, hooks, skills, model providers, speech…),
  **manifest-driven security** (a plugin may only touch what it declares),
  and a central signed registry (ClawHub). Already maps Codex/Claude/Cursor
  plugin layouts into its inventory.

AXP is the intersection made explicit and versioned: OpenClaw's *declared
capabilities + permissions* model, plus Hermes's *verified delivery* model,
plus a per-runtime `targets[]` layer so one description installs anywhere.

## 3. The manifest

Discovery mirrors `hermes-integration`, superset-compatible:

1. `<link rel="agent-extension" href="…">` in the landing page `<head>`, else
2. `https://<domain>/.well-known/agent-extension.json`.

A host that only understands `hermes-integration` can still read the
`targets[]` entry whose `runtime` is `hermes` — its `delivery` block is
byte-compatible with today's manifest (§6), so migration needs no flag day.

### 3.1 Top-level shape

```jsonc
{
  "spec_version": "0.1",
  "kind": "agent-extension",

  "identity": { … },      // §4.1 — who/what this is
  "provides": { … },      // §4.2 — LAYER 1: abstract capability description
  "requires": { … },      // §4.3 — abstract needs (runtime, deps, resources)
  "permissions": { … },   // §4.4 — declared access surface (enforced by host)

  "targets": [ … ]        // §5   — LAYER 2: concrete per-runtime install recipes
}
```

An extension is **describable** as long as it has `identity` + `provides`.
It is **installable on runtime X** only if a matching `targets[]` entry
exists; otherwise the host says "no target for X" instead of guessing.

## 4. Layer 1 — abstract description (runtime-neutral)

### 4.1 `identity`

| field          | req | notes                                              |
|----------------|-----|----------------------------------------------------|
| `name`         | ✔   | slug `[a-z0-9][a-z0-9_-]*`; filesystem/registry key |
| `version`      | ✔   | semver                                             |
| `display_name` | ✔   | human label                                        |
| `description`  | ✔   | one paragraph                                       |
| `author`       |     | name / org                                         |
| `license`      |     | SPDX id                                            |
| `homepage`     |     | URL                                                |

### 4.2 `provides` — the capability description

Every component is *declared* here in runtime-neutral terms. How each maps to
a concrete artifact on a given runtime lives in that runtime's `targets[]`
entry (`component_map`, §5). Referenced files (`*_ref`) are paths inside the
delivered artifact.

```jsonc
"provides": {
  "skills":   [ { "name": "graph-memory", "summary": "…", "path": "skills/graph-memory/" } ],
  "tools":    [ { "name": "memory_query", "summary": "…", "input_schema_ref": "schemas/memory_query.json" } ],
  "services": [ { "name": "falkordb", "kind": "daemon", "summary": "graph store", "endpoint": "tcp://127.0.0.1:6379" } ],
  "memory":   [ { "name": "graph", "kind": "graph", "summary": "temporal knowledge graph", "schema_ref": "schemas/graph.md" } ],
  "cron":     [ { "name": "nightly-compaction", "schedule": "0 4 * * *", "summary": "…" } ],
  "persona":  [ { "fragment_ref": "persona/graph-memory.md" } ],
  "config":   { "schema_ref": "schemas/config.schema.json", "secrets": ["FALKOR_PASSWORD"] }
}
```

`memory.kind` ∈ `graph | vector | kv | relational`. `services.kind` ∈
`daemon | oneshot | sidecar`. All arrays optional; omit what you don't ship.

### 4.3 `requires`

```jsonc
"requires": {
  "extensions": [ "some-other-ext >= 1.0" ],   // hard deps on other AXP extensions
  "resources":  { "disk_mb": 250, "ram_mb": 200 }
}
```

Runtime-version constraints are **per target** (§5), not here — the same
extension may need different minimums on different runtimes.

### 4.4 `permissions` — declared, enforced

Aligns with OpenClaw's manifest-driven security and fills the
`hermes-integration` gap. The host shows this at install time for consent and
(where the runtime supports it) enforces it.

```jsonc
"permissions": {
  "network_egress": ["api.example.com:443"],   // hostnames/ports it may reach
  "filesystem":     ["state:rw"],               // "state" = its own namespace only
  "root":           true,                        // needs root during install
  "reason":         "runs a local FalkorDB daemon and reaches api.example.com for embeddings"
}
```

`filesystem` uses logical scopes, not raw paths: `state:rw` = the extension's
own `…/ext/<name>/` namespace; `config:r`; `skills:rw`. A request for
anything outside declared scopes is a manifest error.

## 5. Layer 2 — `targets[]` (concrete per-runtime install recipes)

Each entry says: *on this runtime, of this version, install me this way.*

```jsonc
{
  "runtime": "hermes",              // "hermes" | "openclaw" | …
  "runtime_version": ">= 2026.6",

  "delivery": { … },                // how the bytes arrive + are trusted (runtime-specific)
  "lifecycle": {                    // scripts/hooks, relative to the delivered artifact
    "install":   "install.sh",
    "upgrade":   "upgrade.sh",      // receives $AXP_FROM_VERSION
    "uninstall": "uninstall.sh",
    "health":    "healthcheck.sh"   // exit 0 = healthy; host surfaces green/red
  },
  "component_map": {                // binds Layer-1 declarations to on-disk reality here
    "tools":    "plugins/graph_memory/",
    "skills":   "skills/",
    "services": "systemd:falkordb-graphmem.service"
  }
}
```

`upgrade` and `health` are the two lifecycle hooks the current Hermes format
lacks; both are optional but recommended.

### 5.1 Hermes target `delivery`

Byte-compatible with today's `hermes-integration` manifest so the existing
installer can consume it via a thin adapter:

```jsonc
"delivery": {
  "method": "hermes-integration",
  "install_url": "https://ext.example.com/graph-memory-hermes.tar.gz",
  "install_sha256": "…",
  "uninstall_command": "/opt/graph-memory/uninstall.sh",
  "requires_oauth": null            // existing optional capability hint
}
```

### 5.2 OpenClaw target `delivery`

Delegates to ClawHub's signed-registry model (sideloading is disabled since
2026.3.22):

```jsonc
"delivery": {
  "method": "clawhub",
  "package": "graph-memory",
  "min_registry_version": "2026.3.22",
  "signature_ref": "clawhub"        // signature verified by ClawHub, not us
}
```

A runtime the extension doesn't support simply has no entry — honest and
inspectable, never a broken half-install.

## 6. Backwards compatibility & migration

- **Reading:** current `install_integration.py` learns one new step —
  "if the doc has `kind: agent-extension`, pull `targets[]` where
  `runtime == hermes` and read its `delivery` block; else treat the whole doc
  as a legacy manifest." Everything downstream (SHA-256, SSRF, same-origin,
  2FA, state file) is unchanged.
- **Writing:** a publisher can serve *both* files during transition
  (`hermes-integration.json` and `agent-extension.json`); the well-known
  paths don't collide.
- **Schema:** ship `agent-extension.schema.json` (JSON Schema) next to this
  spec so publishers validate before publishing and the host validates on
  fetch. See [`schema/agent-extension.schema.json`](schema/agent-extension.schema.json).

## 7. Worked example — the graph-memory extension

The reference extension that exercises every component type. See the full
manifest in [`examples/graph-memory/agent-extension.json`](examples/graph-memory/agent-extension.json).
It declares a `service` (FalkorDB), a `memory` backend (temporal graph),
two `tools` (`memory_write` / `memory_query`), a `skill`, and a `config`
schema — and a single Hermes `target` delivered via the existing
`hermes-integration` pipeline.

## 8. Open questions (to resolve before v1.0)

1. **Registry model.** Hermes is decentralized (publisher-hosted + SHA-256);
   OpenClaw is centralized+signed (ClawHub). Does AXP mandate signatures, or
   leave trust to each target's `delivery.method`? (Current draft: the latter.)
2. **Enforcement vs declaration.** `permissions` is always *declared*; how
   much each runtime *enforces* varies. Do we tier this ("declared" vs
   "enforced") so a host can tell the user which guarantees it actually gives?
3. **Config handoff.** Should the host render `config.schema` into a panel
   form and pass values to `install.sh` via env, or does each `install.sh`
   own its own prompting? (Draft leans: host renders, passes via env.)
4. **`component_map` verbs.** Is a per-runtime string map enough, or do some
   runtimes need richer per-component install directives?
