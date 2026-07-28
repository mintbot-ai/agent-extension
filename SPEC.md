# Agent Extension Protocol (AXP) — SPEC v0.2 (DRAFT)

> Status: **draft, for review.** The core shape is stable; field names may still
> change before v1.0. v0.2 adds the full **updates, channels, signing, key
> rotation, freshness, permission tiers** and **standalone-install** model.

## 1. Purpose

A single, runtime-neutral way to **describe** a packaged agent capability
(a graph memory, an email tool, a smart-home bridge…) *and* to **install,
update, and verify** it on a specific agent runtime — Hermes, OpenClaw, or
others.

AXP is an **envelope, not a package manager.** It does not replace a runtime's
own install machinery; it delegates to it. AXP is the common description layer
every runtime can be generated from or mapped onto — the role OCI image
manifests play across container runtimes, or OpenAPI plays across HTTP servers.

Four design goals:

1. A **general, portable description** of what the extension provides, readable
   by any framework.
2. **Concrete, per-platform install recipes** for each runtime it supports.
3. **Safe updates**: versioned, channelled, signed, monotonic, freeze-resistant.
4. **Graceful degradation**: a manifest an AXP-aware host verifies fully must
   *also* install by hand on a host with zero AXP support (§9).

## 2. Prior art this builds on

- **Hermes `hermes-integration`** (`install_integration.py`): a *delivery +
  trust* format — publisher-hosted manifest, SHA-256 verification, SSRF guard,
  same-eTLD+1 rule, root-exec install/uninstall, local state file. Strong on
  delivery; no declarative component model, no `spec_version`, no schema, no
  health/upgrade, no signing, no declared permission surface.
- **OpenClaw plugin manifest** (2026.3.x): JSON manifest declaring capabilities
  (channels, tools, hooks, skills, model providers, speech…), **manifest-driven
  security** (a plugin may only touch what it declares), and a central signed
  registry (ClawHub).
- **TUF / The Update Framework** and **minisign/signify**: the signing,
  freshness (timestamp/expiry), and key-rotation ideas in §7–8 are deliberately
  a small, self-hostable subset of TUF, using minisign-style ed25519 rather
  than a full role hierarchy.

AXP is the intersection made explicit and versioned: OpenClaw's *declared
capabilities + permissions*, Hermes's *verified decentralized delivery*, and a
TUF-lite *update + signing* layer — with a per-runtime `targets[]` layer so one
description installs anywhere.

## 3. The manifest

Discovery mirrors `hermes-integration`, superset-compatible:

1. `<link rel="agent-extension" href="…">` in the landing page `<head>`, else
2. `https://<domain>/.well-known/agent-extension.json`.

A host that only understands `hermes-integration` can still read the `targets[]`
entry whose `runtime` is `hermes` — its `delivery` block is byte-compatible with
today's manifest (§6), so migration needs no flag day.

### 3.1 Top-level shape

```jsonc
{
  "spec_version": "0.2",
  "kind": "agent-extension",

  "identity":    { … },   // §4.1 — who/what this is
  "provides":    { … },   // §4.2 — LAYER 1: abstract capability description
  "requires":    { … },   // §4.3 — abstract needs (deps, resources)
  "permissions": { … },   // §4.4 — declared access surface + enforcement tier

  "release":     { … },   // §7   — this version's channel, artifact, freshness
  "updates":     { … },   // §7.1 — where newer versions are found
  "signing":     { … },   // §8   — publisher key(s), rotation, policy
  "signature":   "…",     // §8.2 — detached ed25519 sig over the canonical manifest

  "targets":     [ … ]    // §5   — LAYER 2: concrete per-runtime install recipes
}
```

An extension is **describable** with just `identity` + `provides`. It is
**installable on runtime X** only if a matching `targets[]` entry exists;
otherwise the host says "no target for X" instead of guessing. `release`,
`updates`, `signing`, and `signature` are what turn a one-shot install into a
managed, verifiable lifecycle.

## 4. Layer 1 — abstract description (runtime-neutral)

### 4.1 `identity`

| field          | req | notes                                              |
|----------------|-----|----------------------------------------------------|
| `name`         | ✔   | slug `[a-z0-9][a-z0-9_-]*`; filesystem/registry key |
| `version`      | ✔   | semver — the sole ordering authority for updates    |
| `display_name` | ✔   | human label                                        |
| `description`  | ✔   | one paragraph                                       |
| `author`       |     | name / org                                         |
| `license`      |     | SPDX id                                            |
| `homepage`     |     | URL                                                |

### 4.2 `provides` — the capability description

Every component is *declared* here in runtime-neutral terms. How each maps to a
concrete artifact on a given runtime lives in that runtime's `targets[]` entry
(`component_map`, §5). Referenced files (`*_ref`) are paths inside the delivered
artifact.

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

### 4.4 `permissions` — declared, with an enforcement tier

Aligns with OpenClaw's manifest-driven security and fills the
`hermes-integration` gap. The host shows this at install time for consent and,
where it can, enforces it. Because runtimes differ in *how much* they can
actually sandbox, every permission set carries an explicit **enforcement tier**
so the host can tell the user which guarantees it really provides — never imply
an enforcement it does not perform.

```jsonc
"permissions": {
  "network_egress": ["api.example.com:443"],   // hostnames/ports it may reach
  "filesystem":     ["state:rw"],               // logical scopes, not raw paths
  "root":           true,                        // needs root during install
  "reason":         "runs a local FalkorDB daemon; reaches api.example.com for embeddings"
}
```

`filesystem` uses logical scopes: `state:rw` = the extension's own
`…/ext/<name>/` namespace; `config:r`; `skills:rw`. A request outside declared
scopes is a manifest error.

**Enforcement tiers** (the host reports the tier it will apply, per target — see
`targets[].enforcement`):

- `declared` — the manifest states the surface; the host shows it for consent
  but does **not** technically constrain the extension (it runs with the
  host's own privileges). Honesty only. This is where Hermes sits today.
- `advisory` — the host wraps some access with best-effort checks (e.g. an
  egress allowlist proxy) that reduce but do not guarantee containment.
- `enforced` — the host runs the extension under a real sandbox (namespaces,
  seccomp, cgroups, per-scope mounts) so an undeclared access *fails*.

A host MUST NOT advertise a higher tier than it implements. The declared
`permissions` block is identical across tiers; only the *guarantee* differs.

## 5. Layer 2 — `targets[]` (concrete per-runtime install recipes)

Each entry says: *on this runtime, of this version, install me this way — and
here is how far I can be sandboxed here.*

```jsonc
{
  "runtime": "hermes",              // "hermes" | "openclaw" | …
  "runtime_version": ">= 2026.6",
  "enforcement": "declared",        // §4.4 tier this runtime provides for this ext

  "delivery": { … },                // how the bytes arrive + are trusted (runtime-specific)

  "lifecycle": {                    // scripts/hooks, relative to the delivered artifact
    "install":   "install.sh",      // REQUIRED, standalone-runnable — see §9
    "upgrade":   "upgrade.sh",      // receives $AXP_FROM_VERSION
    "uninstall": "uninstall.sh",
    "health":    "healthcheck.sh"   // exit 0 = healthy; host surfaces green/red
  },

  "component_map": {                // §5.2 — binds Layer-1 declarations to on-disk reality
    "skills":   "skills/",
    "tools":    "plugins/graph_memory/",
    "services": {                   // rich form: what + how, not just where
      "unit": "systemd:falkordb-graphmem.service",
      "actions": ["daemon-reload", "enable", "start"],
      "restart": "on-failure",
      "health": "redis-cli -p 6379 ping"
    }
  }
}
```

`upgrade` and `health` are the two lifecycle hooks the current Hermes format
lacks; both are optional but recommended. `install` and `uninstall` are
required. Every listed hook MUST satisfy the standalone rule in §9.

### 5.1 Hermes / OpenClaw `delivery`

Hermes — byte-compatible with today's `hermes-integration` manifest:

```jsonc
"delivery": {
  "method": "hermes-integration",
  "install_url": "https://ext.example.com/graph-memory-hermes.tar.gz",
  "install_sha256": "…",
  "uninstall_command": "/opt/graph-memory/uninstall.sh",
  "requires_oauth": null
}
```

OpenClaw — delegates to ClawHub's signed registry:

```jsonc
"delivery": { "method": "clawhub", "package": "graph-memory", "min_registry_version": "2026.3.22", "signature_ref": "clawhub" }
```

A runtime the extension doesn't support simply has no entry — honest and
inspectable, never a broken half-install.

### 5.2 `component_map` — string or rich object

Each component binding is **either** a plain string (`"skills/"` — "it's here,
the install script does the rest") **or** a rich object describing *what to do*,
not just *where it is*. Both forms are valid for every component; pick per
component. The rich form is what lets a future AXP-aware host manage a component
directly (enable/disable a service, re-link a skill, re-register a tool) without
re-running the whole install script.

Common rich-object fields (all optional; component-specific):

- `services`: `unit`, `actions` (`daemon-reload`/`enable`/`start`/`stop`),
  `restart`, `health`, `stop_timeout_s`.
- `tools`: `module`, `register` (entrypoint), `unregister`.
- `skills`: `dir`, `link` (`copy`/`symlink`).
- `cron`: `unit`, `schedule`.

The string form is sugar for `{ "dir": "<string>" }` (or `{ "unit": … }` for a
`systemd:`-prefixed string). Rich fields a host doesn't understand are ignored,
not fatal — so a richer manifest still installs on a simpler host.

## 6. Backwards compatibility & migration

- **Reading:** current `install_integration.py` learns one new step — "if the
  doc has `kind: agent-extension`, pull `targets[]` where `runtime == hermes`
  and read its `delivery` block; else treat the whole doc as a legacy
  manifest." Everything downstream (SHA-256, SSRF, same-origin, 2FA, state
  file) is unchanged. Signature/updates are additive: a host that ignores them
  behaves exactly like today.
- **Writing:** a publisher can serve both files during transition; the
  well-known paths don't collide.
- **Schema:** `schema/agent-extension.schema.json` (JSON Schema) validates
  manifests before publishing and on fetch.

## 7. Releases, channels & updates

### 7.0 `release` — this manifest's own version metadata

```jsonc
"release": {
  "channel": "stable",                 // §7.2
  "published_at": "2026-07-28T10:00:00Z",
  "valid_until": "2026-08-27T10:00:00Z", // §7.4 freshness / freeze resistance
  "changelog": "https://ext.example.com/graph-memory/CHANGELOG.md#0-2-0",
  "artifact": {                        // the actual bytes this version ships
    "url": "https://ext.example.com/graph-memory-0.2.0.tar.gz",
    "sha256": "…"
  }
}
```

The `artifact.sha256` is the anchor the signature ultimately protects (§8.2):
sign the manifest → bind `version` + `channel` + `valid_until` + `sha256`
together in one signed unit.

### 7.1 `updates` — where a newer version is found

Three source kinds; **all three support automatic update.** The client's job is
always the same: resolve the source to a *candidate manifest*, compare
`identity.version` to the installed one, and if strictly higher (and policy
allows), fetch `release.artifact` and apply.

```jsonc
"updates": {
  "source": { "kind": "github", "repo": "mintbot-ai/graph-memory" },
  // OR   { "kind": "feed",   "url": "https://ext.example.com/graph-memory/feed.json" },
  // OR   { "kind": "direct", "url": "https://ext.example.com/.well-known/agent-extension.json" },
  "check": "daily",        // §7.3 — client-owned cadence; default daily
  "policy": "auto"          // §7.5 — auto | notify | pin | off
}
```

- **`github`** — versions come from Releases/tags (`vX.Y.Z`), the artifact is a
  release asset, and the signature travels in the release (asset or manifest
  asset). Discovery is free: list releases, take the newest that outranks the
  installed version on the tracked channel.
- **`feed`** — a publisher-hosted JSON listing available versions (each entry:
  `version`, `channel`, `manifest_url`, `valid_until`). Use when you don't want
  GitHub. The client reads the feed, picks the best candidate, fetches that
  entry's manifest.
- **`direct`** — a single stable URL that always serves the *current* manifest.
  The client re-fetches it on schedule, reads `identity.version`, and updates
  when it rose. So `direct` auto-updates too — the version lives in the
  manifest behind one fixed URL rather than in a version list.

### 7.2 Channels — ordered core + free custom

Ordered core enum (a host tracking `beta` also accepts `stable`):

```
dev  >  alpha  >  beta  >  stable      // left = least stable, more frequent
```

A host preference of "track up to `beta`" accepts `stable` and `beta`, never
`alpha`/`dev`. `stable` is the default channel and the default a host tracks.
Publishers MAY also use **custom named channels** (`"lts"`, `"canary-mart"`);
these are opaque strings that do **not** auto-order — a host only receives a
custom channel's releases if it explicitly tracks that exact name.

### 7.3 Update-check cadence

Who checks and how often is **the client's decision**. `updates.check` is a
publisher *hint* (`hourly`/`daily`/`weekly`/`manual`); the host may honor,
override, or ignore it. **Default: once per day**, plus an on-demand "check
now". On Hermes this is a host-owned daily cron, not something each extension
schedules.

### 7.4 Monotonicity & freeze resistance

- **Monotonic:** auto-update only ever moves to a **strictly higher** semver on
  the tracked channel. This alone defeats replay-to-older (a re-served old
  manifest simply isn't "newer", so nothing happens). Interactive downgrade is
  a separate, explicit user action — the user sees the version and chooses.
- **Freeze/rollback resistance:** monotonicity does *not* catch an attacker who
  freezes you at your current version by always serving your current (validly
  signed) manifest, hiding that a security fix exists. The defense is
  **freshness**: `release.valid_until` is inside the signed manifest, so a host
  that refuses manifests older than their `valid_until` (with a sane clock and
  a grace window) notices it is being held back and can warn. `valid_until` is
  RECOMMENDED for signed extensions; publishers simply re-sign on their release
  cadence to keep it moving.

### 7.5 Per-extension update policy

The host stores, per installed extension, one of:

- `auto` — apply qualifying updates automatically (default).
- `notify` — tell the user, apply on approval.
- `pin=X.Y.Z` — stay on exactly this version; never auto-update.
- `off` — never check.

`updates.policy` in the manifest is the publisher's *suggested default*; the
user's stored choice always wins.

## 8. Signing & trust

### 8.1 Model — ed25519 + Trust On First Use

Signing is **ed25519** (minisign-style: no CA, no PKI, self-hostable, same
family as the publisher's SSH keys). One publisher key per extension in v0.2
(multi-signer / m-of-n is a post-v1 extension point, deliberately out now).

- **First install (TOFU):** the host verifies the manifest signature against the
  key embedded in `signing.public_key`, then **pins** that key into the
  extension's local state.
- **Every later update:** the candidate manifest MUST verify against the
  **pinned** key (or a validly rotated successor, §8.3). An update that fails
  this is rejected — this is exactly the "updates only from the same key" rule.

This is what makes a central signed registry unnecessary: per-publisher key
pinning gives the "same key" guarantee in a fully decentralized way. (An
OpenClaw target still delegates to ClawHub's registry signatures; a Hermes
target uses TOFU. The trust root is per-target.)

### 8.2 What is signed, and where

- **Scope:** the signature covers the **canonical serialization of the whole
  manifest with the `signature` field removed** (canonicalization: JCS /
  RFC 8785). Because the manifest contains `release.artifact.sha256`, signing
  the manifest transitively binds the artifact bytes, the version, the channel,
  and `valid_until` into one signed unit — covers all the bits, no separate
  artifact signature needed.
- **Location:** the signature is **inline**, in the top-level `signature` field
  (base64 ed25519). One `.well-known/agent-extension.json` file carries
  everything; no sidecar `.minisig` to fetch or lose.

```jsonc
"signing": {
  "public_key": "ed25519:BASE64KEY",     // pinned on first install (TOFU)
  "key_id": "graph-memory-2026",          // human label for the current key
  "next_key": null                          // §8.3 rotation announcement
},
"signature": "BASE64_ED25519_SIG_OVER_CANONICAL_MANIFEST"
```

### 8.3 Key rotation — simple, no brick

"Updates only from the same key" creates a foot-gun: a lost or compromised key
would lock out all future updates. Rotation fixes it without a CA:

1. **Announce ahead:** a normal release sets `signing.next_key` to the new
   public key while still being signed by the **current** (pinned) key. The
   host records the announced successor but keeps trusting the current key.
2. **Rotate:** the first release under the new key is a **rotation release** —
   it is **dual-signed**: signed by the old (pinned) key *and* by the new key,
   and its `signing.public_key` is the new key. The host verifies the old-key
   signature (satisfies "same key"), confirms the new key matches the
   previously announced `next_key`, verifies the new-key signature, then
   **re-pins** to the new key.
3. **After:** subsequent releases are signed by the new key alone.

```jsonc
// rotation release carries both signatures
"signing": { "public_key": "ed25519:NEWKEY", "key_id": "graph-memory-2027", "next_key": null },
"signature":      "SIG_BY_NEW_KEY",
"signature_prev": "SIG_BY_OLD_PINNED_KEY"    // present only on rotation releases
```

A fully lost key (no advance `next_key` announced) cannot self-rotate — that
falls back to manual re-trust (a fresh TOFU the user must explicitly confirm),
which is the correct, safe behavior.

### 8.4 Unsigned extensions

Signing is **optional but strongly recommended**. If an extension ships no
`signing`/`signature`:

- The host **installs it, but warns clearly**: "This extension is unsigned —
  updates cannot be cryptographically tied to the publisher," and suggests the
  publisher sign it.
- **Ratchet:** once an extension has been installed *signed*, the host MUST NOT
  silently accept a later *unsigned* manifest for it (downgrade-to-unsigned is
  treated as a trust break needing explicit user action).

## 9. Standalone install (mandatory fallback)

Every shell-based target MUST ship install scripts that run **with zero AXP
support**. This is a hard requirement, not a nicety: it guarantees one manifest
serves both a verifying AXP host and a bare machine.

**Requirements for `lifecycle.install` (and `uninstall`, and `upgrade`/`health`
if present):**

1. **Standalone-runnable.** `./install.sh` (or `curl -fsSL <url> | bash`)
   performs the entire installation on a host that has never heard of AXP. No
   AXP daemon, no host helper, may be assumed present.
2. **Idempotent.** Re-running must converge, not duplicate or break (safe to run
   twice, safe to re-run after a partial failure).
3. **Env-or-default config.** An AXP-aware host renders `provides.config.schema`
   into a form and passes values via environment variables (decision: host
   renders, §4.2). The script MUST also work when those env vars are absent —
   by using sane defaults or prompting interactively on a TTY. So the same
   script is driven by the host *or* by a human.
4. **Self-contained.** It fetches its own dependencies; it does not rely on the
   host having staged anything beyond the delivered artifact.

**Trust boundary — stated plainly so no one is misled:** the security layer
(signature verification, permission consent, TOFU pinning, freshness checks) is
a property of the **AXP-aware host**, not of the script. Running `install.sh` by
hand deliberately opts out of all of it — exactly like any `curl | bash`. The
signature protects the *managed* path; it does not and cannot protect a manual
run. The spec says this out loud so a hand-installer knows what they are
giving up.

## 10. Worked example

See [`examples/graph-memory/`](examples/graph-memory/): the full manifest
(`agent-extension.json`) exercising every component type, `release`/`updates`/
`signing` blocks, a rich `component_map`, and a standalone, idempotent
`install.sh` that reads config from env with defaults.

## 11. Open questions (to resolve before v1.0)

1. **Multi-signer / m-of-n.** v0.2 is single-key. When do we add threshold
   signing, and does it reuse `signing` or a new block?
2. **Config handoff transport.** Env vars are the v0.2 answer; do secrets need a
   safer channel than env (file descriptor, tmpfile with 0600) to avoid `ps`/
   env leakage?
3. **Enforcement negotiation.** If a host offers only `declared` but the
   extension's `permissions.reason` implies it really wants `enforced`, should
   install warn, block, or proceed silently? (Draft: warn.)
4. **Dependency resolution.** `requires.extensions` declares deps but the spec
   doesn't yet define who resolves/installs them, or how version conflicts
   between two extensions' shared deps are handled.
5. **Feed/GitHub signature placement.** For `github` sources, is the signature
   in the manifest asset enough, or do we also want the git tag GPG-signed?
