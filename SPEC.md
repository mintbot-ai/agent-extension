# Agent Extension Protocol (AXP) — SPEC v0.4 (DRAFT)

> Status: **draft, for review.** v0.3 was the *universality* revision (publisher-
> namespaced identity, the runtime-neutral `posix` target with `archive`
> delivery, the host→script environment contract, host-retained artifacts,
> runtime-neutral permission scopes, MCP servers as a first-class component,
> the forward-compatibility rule, host conformance profiles). v0.4 is the
> *hardening* revision, additive only: the publisher key directory as a
> second trust channel for key rotation and lost-key recovery (§8.5), a
> precise tracked-channel rule (§7.2), freshness guidance that does not
> nag (§7.4), pinned environment semantics (§6.2), and the consent ratchet
> for updates (§7.6). Runtime specifics live in [`docs/runtimes/`](docs/runtimes/).
> Field names may still change before v1.0; see §13 for migrations.

## 1. Purpose

A single, runtime-neutral way to **describe** a packaged agent capability (a
memory backend, an MCP server, a tool, a channel bridge, a service…) *and* to
**install, update, and verify** it on any agent runtime.

AXP is an **envelope, not a package manager.** It does not replace a runtime's
own install machinery; it delegates to it. It is the common description layer
every runtime can be generated from or mapped onto — the role OCI image
manifests play across container runtimes, or OpenAPI across HTTP servers.

Design goals:

1. **Portable description** of what the extension provides, readable by any
   framework, including ones that do not exist yet.
2. **Concrete per-runtime install recipes**, plus a **baseline recipe every
   POSIX host can execute** without knowing the runtime at all.
3. **Safe updates**: versioned, channelled, signed, monotonic, freeze-resistant.
4. **Graceful degradation**: a manifest a verifying AXP host installs fully must
   *also* install by hand on a host with zero AXP support (§10).
5. **No vendor in the core.** Nothing in this document requires a particular
   runtime, hosting product, registry, or cloud. Vendor- and runtime-specific
   vocabulary is namespaced (§2.3) and documented in profiles, never in the core.

## 2. Conventions

### 2.1 Terms

- **Extension** — the thing being described and installed.
- **Publisher** — whoever signs and serves the manifest; identified by a DNS
  name (§4.1).
- **Runtime** — the agent framework an extension plugs into (`hermes`,
  `openclaw`, `claude-code`, …) — or `posix` for "any POSIX machine".
- **Host** — the software that reads AXP manifests and performs installs on a
  machine. A host implements one or more runtimes' targets and declares a
  **conformance profile** (§11). A runtime may be its own host; a product may
  host several runtimes.
- **Artifact** — the bytes the publisher ships for a target (usually a tarball
  containing the lifecycle scripts and payload).

RFC 2119 keywords (MUST, SHOULD, MAY) are used normatively.

### 2.2 Versioning of this spec

`spec_version` is `MAJOR.MINOR`. Minor revisions are additive: a host that
understands `0.3` MUST read `0.4` manifests (ignoring fields it does not know,
§2.4). Major revisions may break. A host MUST refuse a manifest whose major it
does not understand with a clear message, never half-parse it.

### 2.3 Namespacing

Three kinds of identifier appear in the manifest, all lowercase:

- **Core identifiers** (component types, scope names, delivery methods,
  runtime ids, permission keys) are bare words defined in this spec, e.g.
  `state`, `archive`, `posix`, `mcp_servers`.
- **Runtime-scoped identifiers** are `<runtime>:<word>`, e.g. `hermes:skills`
  (a filesystem scope only Hermes hosts understand), `openclaw:channels`. A
  host that does not implement `<runtime>` MUST ignore them.
- **Vendor extensions** are `x-<vendor>-<word>` fields or values, e.g.
  `x-acme-billing`. Hosts MUST ignore unknown `x-` entries.

New core identifiers are added only by this spec. Runtime ids are listed in
[`docs/runtimes/README.md`](docs/runtimes/README.md); anyone may register one
by adding a profile document there.

### 2.4 Forward compatibility (normative)

- Unknown **fields** anywhere in the manifest MUST be ignored.
- Unknown **component types** under `provides` and unknown keys under
  `component_map` MUST be ignored (the extension still installs; the host just
  cannot manage that component individually).
- Unknown **values** of *security-relevant* enums — `targets[].enforcement`,
  `updates.policy`, `release.channel` core ordering, permission keys — MUST
  cause a refusal, because guessing would either over-promise or under-warn.
  All other unknown enum values are ignored.
- A host MUST NOT refuse a manifest merely because it contains `x-` or
  `<runtime>:` entries it does not understand.

The JSON Schema in `schema/` encodes these rules (`additionalProperties` is
permissive where this section says "ignore").

## 3. The manifest

### 3.1 Discovery

A host resolves a user-supplied *locator* to a manifest document in this order:

1. A URL whose path ends in `.json` is fetched as the manifest itself.
2. Otherwise, for an `https://<domain>/…` URL or bare domain:
   `<link rel="agent-extension" href="…">` in the landing page `<head>`, else
   `https://<domain>/.well-known/agent-extension.json`.
3. A git repository URL: `agent-extension.json` at the repository root (and
   per-release copies as release assets, §7.1).
4. A local path (`file://…` or a directory): `agent-extension.json` there.

Fetches MUST be HTTPS (or local). The manifest's origin SHOULD match
`identity.publisher` (§4.1); a mismatch is surfaced to the user as a warning
(the signature still decides trust).

Canonical filename everywhere: **`agent-extension.json`**.

### 3.2 Top-level shape

```jsonc
{
  "spec_version": "0.3",
  "kind": "agent-extension",

  "identity":    { … },   // §4.1 — who/what this is (publisher-namespaced)
  "provides":    { … },   // §4.2 — LAYER 1: abstract capability description
  "requires":    { … },   // §4.3 — abstract needs (deps, resources)
  "permissions": { … },   // §4.4 — declared access surface

  "release":     { … },   // §7   — this version's channel, artifact, freshness
  "updates":     { … },   // §7.1 — where newer versions are found
  "signing":     { … },   // §8   — publisher key(s), rotation
  "signature":   "…",     // §8.2 — ed25519 sig over the canonical manifest

  "targets":     [ … ]    // §5   — LAYER 2: concrete per-runtime install recipes
}
```

An extension is **describable** with just `identity` + `provides`. It is
**installable on runtime X** only if a matching `targets[]` entry exists — or a
`posix` entry, which any POSIX host MAY use as the fallback (§5.1). `release`,
`updates`, `signing`, `signature` turn a one-shot install into a managed,
verifiable lifecycle.

## 4. Layer 1 — abstract description (runtime-neutral)

### 4.1 `identity`

| field          | req | notes                                                                 |
|----------------|-----|-----------------------------------------------------------------------|
| `publisher`    | ✔   | DNS name of the publisher, lowercase (`ext.example.com`). Namespace.    |
| `name`         | ✔   | slug `[a-z0-9][a-z0-9_-]*`, ≤ 64 chars                                 |
| `version`      | ✔   | semver — the sole ordering authority for updates                       |
| `display_name` | ✔   | human label                                                           |
| `description`  | ✔   | one paragraph                                                         |
| `author`       |     | name / org                                                            |
| `license`      |     | SPDX id                                                               |
| `homepage`     |     | https URL                                                             |
| `keywords`     |     | free-text tags for catalogues                                         |
| `i18n`         |     | `{ "<lang>": { "display_name", "description" } }` optional translations |

The **extension id** is `<publisher>/<name>`, e.g. `ext.example.com/graph-memory`.
It is what a host keys its state, pinned signing key, dependency resolution and
UI on. Two publishers may both ship a `graph-memory`; they never collide.

### 4.2 `provides` — the capability description

Every component is *declared* here in runtime-neutral terms. How each maps to a
concrete artifact on a given runtime lives in that runtime's `targets[]` entry
(`component_map`, §5.3). `*_ref` fields are paths inside the delivered artifact.

```jsonc
"provides": {
  "mcp_servers": [ { "name": "graph-memory", "transport": "stdio", "summary": "…",
                     "command_ref": "bin/graph-memory-mcp" } ],
  "tools":       [ { "name": "memory_query", "summary": "…", "input_schema_ref": "schemas/memory_query.json" } ],
  "services":    [ { "name": "falkordb", "kind": "daemon", "summary": "graph store", "endpoint": "tcp://127.0.0.1:6379" } ],
  "memory":      [ { "name": "graph", "kind": "graph", "summary": "temporal knowledge graph", "schema_ref": "schemas/graph.md" } ],
  "skills":      [ { "name": "graph-memory", "summary": "…", "path": "skills/graph-memory/" } ],
  "prompts":     [ { "name": "graph-memory", "fragment_ref": "prompts/graph-memory.md" } ],
  "channels":    [ { "name": "matrix", "summary": "Matrix messaging bridge" } ],
  "model_providers": [ { "name": "acme-llm", "summary": "…" } ],
  "hooks":       [ { "name": "pre-reply", "event": "pre_reply", "summary": "…" } ],
  "cron":        [ { "name": "nightly-compaction", "schedule": "0 4 * * *", "summary": "…" } ],
  "config":      { "schema_ref": "schemas/config.schema.json", "secrets": ["FALKOR_PASSWORD"] }
}
```

Core component types and their required fields:

| type              | required            | notes                                                        |
|-------------------|---------------------|--------------------------------------------------------------|
| `mcp_servers`     | `name`, `transport` | `transport` ∈ `stdio \| http \| sse`; `command_ref` (stdio) or `url` (http/sse). The portable tool surface — any MCP-capable runtime can use it. |
| `tools`           | `name`              | runtime-native tools; `input_schema_ref` (JSON Schema)        |
| `services`        | `name`, `kind`      | `kind` ∈ `daemon \| oneshot \| sidecar`; `endpoint`           |
| `memory`          | `name`, `kind`      | `kind` ∈ `graph \| vector \| kv \| relational`                |
| `skills`          | `name`              | instruction packs; `path`                                     |
| `prompts`         | `name`              | system-prompt / persona fragments; `fragment_ref` (was `persona` in v0.2) |
| `channels`        | `name`              | messaging / IO channels                                       |
| `model_providers` | `name`              | LLM / embedding / speech providers                            |
| `hooks`           | `name`, `event`     | lifecycle hooks; `event` is a runtime-profile vocabulary       |
| `cron`            | `name`, `schedule`  | 5-field cron                                                   |
| `config`          | —                   | `schema_ref` (JSON Schema of config), `secrets` (names)        |

All optional; omit what you don't ship. Unknown types are ignored (§2.4);
vendor types use `x-` (e.g. `x-acme-dashboards`).

### 4.3 `requires`

```jsonc
"requires": {
  "extensions": [ { "id": "ext.example.com/some-other-ext", "version": ">=1.0 <2" } ],
  "resources":  { "disk_mb": 250, "ram_mb": 200 },
  "commands":   [ "docker", "systemctl" ]    // binaries the install expects on PATH (hint for preflight)
}
```

**Version constraint grammar** (used here, in `runtime_version`, and in
`platforms`): a space-separated list of comparators, all of which must hold:
`>=X`, `>X`, `<=X`, `<X`, `=X`, `^X` (same major), `~X` (same major.minor).
Versions are compared segment-wise numerically, so both semver (`1.4.0`) and
calver (`2026.6`) work. Pre-release tags compare lower than the release.

Runtime-version constraints are per target (§5), not here. Dependency
*resolution* (who installs `requires.extensions`) is host behaviour defined in
§11 (Managed profile); v0.3 only requires the host to refuse when a hard dep is
missing and tell the user which one.

### 4.4 `permissions` — declared access surface

The host shows this at install time for consent and, where it can, enforces it.
Because runtimes differ in *how much* they can sandbox, each target carries an
**enforcement tier** (§5) so the host can say which guarantees it really gives.

```jsonc
"permissions": {
  "network_egress":  ["api.example.com:443"],      // host[:port]; "*.example.com" wildcard allowed
  "network_ingress": ["127.0.0.1:6379/tcp"],       // listeners it opens: [addr:]port/proto
  "filesystem":      ["state:rw", "config:r"],     // logical scopes, not raw paths
  "secrets":         ["FALKOR_PASSWORD"],          // secret names it needs the host to hand over
  "root":            true,                          // install/upgrade/uninstall need root
  "reason":          "runs a local FalkorDB daemon; reaches api.example.com for embeddings"
}
```

`reason` MAY instead be an object keyed by permission (`{ "root": "…",
"network_egress": "…" }`). An absent `permissions` block is an *empty*
declaration, not a blank cheque.

**Filesystem scopes** are logical, so the same manifest means the same thing
on every host. Core scopes:

| scope       | meaning                                                        |
|-------------|----------------------------------------------------------------|
| `state`     | the extension's own durable data dir (`AXP_STATE_DIR`)          |
| `cache`     | the extension's own disposable cache dir (`AXP_CACHE_DIR`)      |
| `config`    | the runtime's configuration (read it / register itself)         |
| `secrets`   | the runtime's secret store (only ever `:r`; write via `config`) |
| `workspace` | the agent's working files / documents                           |
| `system`    | anything outside the above (package install, `/etc`, units) — implies `root` |

Runtime-specific scopes are namespaced: `hermes:skills:rw`,
`claude-code:plugins:rw`. Mode is `:r` or `:rw`. A host ignores scopes it does
not know (they can never *widen* access) and tells the user it did so.

**Enforcement tiers** (per target, `targets[].enforcement`):

- `declared` — the manifest states the surface; the host shows it for consent
  but does **not** technically constrain anything.
- `advisory` — the host constrains *part* of the lifecycle (typically the
  install/upgrade/uninstall scripts: egress allow-list, read-only tree except
  declared scopes) but not the extension's runtime code.
- `enforced` — the host runs the extension's runtime code under a real sandbox
  so an undeclared access *fails*.

A host MUST NOT advertise a higher tier than it implements, MUST report the
tier it actually applied in the install record, and SHOULD record *why* it
downgraded (e.g. "root requested → filesystem not sandboxed", "no systemd →
declared"). The declared `permissions` block is identical across
tiers; only the guarantee differs.

## 5. Layer 2 — `targets[]` (concrete per-runtime install recipes)

Each entry says: *on this runtime, of this version, on these platforms, install
me this way — and here is how far I can be sandboxed here.*

```jsonc
{
  "runtime": "posix",                 // §5.1 runtime id
  "runtime_version": ">=0.18",        // §4.3 grammar, in the runtime's own version scheme; omit for posix
  "platforms": ["linux/amd64", "linux/arm64"],   // GOOS/GOARCH style; omit = any
  "enforcement": "declared",          // §4.4 tier the publisher *expects* this runtime to provide

  "delivery": { "method": "archive", "url": "https://…/graph-memory-0.3.0.tar.gz", "sha256": "…" },  // §5.2

  "lifecycle": {                      // paths relative to the unpacked artifact (§6)
    "install":   "install.sh",        // REQUIRED, standalone-runnable — §10
    "upgrade":   "upgrade.sh",        // receives AXP_FROM_VERSION
    "uninstall": "uninstall.sh",      // REQUIRED
    "health":    "healthcheck.sh"     // exit 0 = healthy
  },

  "component_map": { … }              // §5.3
}
```

The host picks the **first** target whose `runtime` it implements, whose
`runtime_version` constraint its runtime version satisfies (§4.3 grammar; a
host that does not know its runtime version cannot refuse on it) and whose
`platforms` include the machine. If none matches but a `posix` target does, a
POSIX host MAY use it (§5.1). If nothing matches the host says "no target for
this runtime" — and names which entries it skipped and why — never guesses.

### 5.1 Runtime ids and the `posix` baseline

Core runtime ids: **`posix`** (any POSIX machine; no runtime knowledge needed)
plus the registered runtimes in [`docs/runtimes/`](docs/runtimes/) (`hermes`,
`openclaw`, `claude-code`, …). Unregistered runtimes use reverse-DNS ids
(`com.example.myagent`).

A **`posix` target** is the universality guarantee: it MUST use `delivery.method:
"archive"` and shell lifecycle scripts that satisfy §10, and it MUST NOT assume
any runtime beyond a POSIX shell, `tar`, and the §6 environment contract.
Publishers SHOULD ship a `posix` target whenever the extension can be useful
without runtime integration (services, MCP servers, CLIs). Runtime-specific
targets then add the integration (register the MCP server, link skills, …).

### 5.2 `delivery` methods

| method               | fields                                  | who must support it                              |
|----------------------|-----------------------------------------|--------------------------------------------------|
| `archive`            | `url` (https), `sha256`, `format` (`tar.gz` default, `zip`) | **every host** (Core profile, §11) |
| `hermes-integration` | v0.2 Hermes block (`install_url`, `install_sha256`, `uninstall_command`, `requires_oauth`) | Hermes hosts; treated as `archive` + Hermes extras (see profile) |
| `clawhub`            | `package`, `min_registry_version`       | OpenClaw hosts (registry-delegated trust)        |
| `x-…` / reverse-DNS  | anything                                | that vendor                                      |

`archive` is deliberately minimal: bytes + digest. Trust comes from the
signature over the manifest that contains the digest (§8). Registry-delegated
methods (`clawhub`) carry their own trust root; the host reports which root it
relied on.

### 5.3 `component_map` — string or rich object

Each binding is **either** a plain string (`"skills/"` — "it's here, the
install script does the rest") **or** a rich object describing *what to do*.
The rich form lets a host manage a component directly (enable/disable a
service, re-register an MCP server) without re-running the whole install.

Common rich-object fields (all optional; component-specific):

- `mcp_servers`: `command` (argv, relative to the install prefix), `env`,
  `url`, `register` (`auto` = host registers it in the runtime's MCP config).
- `services`: `unit` (`systemd:<name>`, `launchd:<label>`, `supervisor:<name>`),
  `actions` (`daemon-reload`/`enable`/`start`/`stop`), `restart`, `health`.
- `tools`: `module`, `register`, `unregister`.
- `skills`: `dir`, `link` (`copy`/`symlink`).
- `cron`: `unit`, `schedule`.

String sugar: `"skills/"` ≡ `{ "dir": "skills/" }`; `"systemd:x.service"` ≡
`{ "unit": "systemd:x.service" }`. Unknown fields are ignored (§2.4).

## 6. Host ↔ script contract

This section is what makes lifecycle scripts portable across hosts. It is
normative for every host that runs shell lifecycle hooks.

### 6.1 The host retains the artifact

After a successful install the host MUST keep the **unpacked artifact** of the
installed version at a stable location (`AXP_ARTIFACT_DIR`) for as long as the
extension is installed. `upgrade`, `uninstall` and `health` are always run from
there — a publisher never has to copy its own scripts somewhere to find them
later, and an uninstall works even if the publisher's site is gone. On upgrade
the host unpacks the new artifact to a fresh dir, runs the **new** version's
`upgrade` hook with `AXP_FROM_VERSION` set, and only then replaces the retained
artifact.

### 6.2 Environment

The host runs each hook with its working directory set to the unpacked
artifact and the following variables set. A script MUST work when **none** of
them are set (§10), using the listed defaults.

| variable              | set on       | meaning / default when unset                                  |
|-----------------------|--------------|---------------------------------------------------------------|
| `AXP_SPEC_VERSION`    | all          | the spec version the HOST implements (`0.4`) — not the manifest's |
| `AXP_HOST`            | all          | `<host-id>/<host-version>` (`mintbot/2026.8`, `axp-cli/0.4.0`) |
| `AXP_RUNTIME`         | all          | runtime id of the chosen target (`posix`, `hermes`, …)         |
| `AXP_RUNTIME_VERSION` | all          | runtime version if known                                       |
| `AXP_ENFORCEMENT`     | all          | tier actually applied to this run (`declared\|advisory\|enforced`) |
| `AXP_HOOK`            | all          | `install \| upgrade \| uninstall \| health`                     |
| `AXP_EXT_ID`          | all          | `<publisher>/<name>`                                          |
| `AXP_EXT_PUBLISHER`   | all          | publisher DNS name                                            |
| `AXP_EXT_NAME`        | all          | name slug                                                     |
| `AXP_EXT_VERSION`     | all          | version being installed / run                                 |
| `AXP_FROM_VERSION`    | upgrade      | previously installed version                                   |
| `AXP_PREFIX`          | all          | suggested install prefix; default `/opt/<name>` (root) or `~/.local/opt/<name>` |
| `AXP_STATE_DIR`       | all          | durable data dir (scope `state`); default `/var/lib/axp/<publisher>/<name>` or `~/.local/state/axp/<publisher>/<name>` |
| `AXP_CACHE_DIR`       | all          | disposable cache dir (scope `cache`); default `$XDG_CACHE_HOME/axp/<publisher>/<name>` |
| `AXP_ARTIFACT_DIR`    | all          | the unpacked artifact the running hook belongs to: the staging dir during `install`/`upgrade` (retention happens after success, §6.1), the retained dir for `uninstall`/`health`; default = script's own dir |
| `AXP_CONFIG_FILE`     | install, upgrade | path to a 0600 **dotenv-format** file with the user's config values incl. secrets (§6.3); unset = use defaults / prompt |
| `AXP_PURGE`           | uninstall    | `1` = also delete `AXP_STATE_DIR`; default `0` (keep user data)  |
| `AXP_NONINTERACTIVE`  | all          | `1` = never prompt (host-driven run); default unset (may prompt on a TTY) |

Hosts MAY add `AXP_<RUNTIME>_*` variables described in their runtime profile
(e.g. `AXP_HERMES_HOME`). Scripts MUST NOT require them unless the target is
that runtime.

### 6.3 Configuration and secrets handoff

A host that renders `provides.config.schema_ref` into a form hands the values
over in **one file** (`AXP_CONFIG_FILE`, mode 0600, on a private tmpfs where
available, deleted after the hook returns) in dotenv format — `KEY=VALUE` per
line, keys are the schema's property names upper-snake-cased unless the schema
property sets `x-env`. Scripts read it with `set -a; . "$AXP_CONFIG_FILE"; set +a`.

Secrets (`provides.config.secrets`, `permissions.secrets`) MUST travel only
through that file — never through the process environment, which is readable
via `ps`/`/proc`. Non-secret values MAY additionally be exported as env for
convenience. Scripts MUST still work with no file at all (defaults or TTY
prompt, §10).

### 6.4 Exit codes and output

- `install`/`upgrade`/`uninstall`: exit 0 = success; non-zero = failure; the
  host shows the last lines of stderr/stdout to the user. Exit **75**
  (`EX_TEMPFAIL`) means "retry later" (e.g. a dependency download failed).
- `health`: exit 0 = healthy, 1 = unhealthy, 2 = unknown/degraded. Stdout MAY
  carry a one-line human status; if it begins with `{` it is a JSON object
  (`{"status":"ok","detail":"…"}`) hosts MAY render.
- Scripts MUST be idempotent (§10).

## 7. Releases, channels & updates

### 7.0 `release`

```jsonc
"release": {
  "channel": "stable",
  "published_at": "2026-07-28T10:00:00Z",
  "valid_until": "2026-08-27T10:00:00Z",   // §7.4 freshness
  "changelog": "https://ext.example.com/graph-memory/CHANGELOG.md#0-3-0",
  "artifact": { "url": "https://…/graph-memory-0.3.0.tar.gz", "sha256": "…" }  // canonical bytes of this version
}
```

`release.artifact` is the canonical artifact the signature anchors (§8.2).
Targets whose `delivery` is `archive` MAY reference the same URL+digest or a
per-runtime artifact; either way every digest in the manifest is inside the
signed unit.

### 7.1 `updates` — where a newer version is found

```jsonc
"updates": {
  "source": { "kind": "github", "repo": "acme/graph-memory" },
  // OR   { "kind": "feed",   "url": "https://ext.example.com/graph-memory/feed.json" },
  // OR   { "kind": "direct", "url": "https://ext.example.com/.well-known/agent-extension.json" },
  "check": "daily",
  "policy": "auto"         // publisher's suggested default; user's stored choice wins
}
```

- **`github`** — releases tagged `v<version>`; the release MUST attach
  `agent-extension.json` (the signed manifest for that version) as an asset,
  and the artifact(s) as further assets. The repo root SHOULD carry the current
  `agent-extension.json` too (§3.1 step 3). Any forge with the same release
  shape MAY use `kind: "forge"` with `url` (the API base) — `github` is the
  common case, not a dependency.
- **`feed`** — publisher-hosted JSON:
  `{ "id": "<publisher>/<name>", "versions": [ { "version", "channel",
  "manifest_url", "valid_until" } ] }`.
- **`direct`** — a fixed URL that always serves the current manifest.

The client's job is the same for all three: resolve to a candidate manifest,
verify it (§8), compare `identity.version` on the tracked channel, apply if
strictly higher and policy allows.

### 7.2 Channels

Ordered core enum `dev > alpha > beta > stable` (left = less stable). A host
tracking `beta` accepts `beta` and `stable`. `stable` is the default. Custom
channels (`lts`, `canary`) are opaque: delivered only to hosts that track that
exact name.

The **tracked channel** is host state, recorded at install from the installed
release's `release.channel` (or the user's choice) and preserved across
updates. It is NOT the channel of whatever release happens to be installed:
a host tracking `beta` that applies a `stable` release keeps tracking `beta`
and keeps offering betas afterwards.

### 7.3 Cadence

`updates.check` (`hourly|daily|weekly|manual`) is a hint. Cadence is the
host's decision; default daily plus an on-demand check.

### 7.4 Monotonicity & freshness

- Auto-update only ever moves to a **strictly higher** version on the tracked
  channel. Downgrade is an explicit, interactive user action.
- `release.valid_until` inside the signed manifest defeats freeze attacks: a
  host that sees its installed manifest expire (beyond a grace window it
  chooses, e.g. 7 days) warns that it may be held back. It is **optional**
  and a *warning*, never a block. Publishers who set it commit to shipping a
  fresh manifest before it lapses, so windows SHOULD be generous (≥ 90 days;
  tooling defaults to 180) unless releases are frequent. A host SHOULD raise
  the warning when the manifest first expires and then no more than about
  once a month while it stays expired — a nightly nag trains users to ignore
  the one warning that matters. A *candidate* manifest that is already
  expired is refused (it is not a valid release any more).

### 7.5 Per-extension policy

Stored by the host per extension id: `auto` | `notify` | `pin=X.Y.Z` | `off`.
The manifest's `updates.policy` is the starting value shown at install; the
user's stored choice always wins afterwards.

### 7.6 Updates and consent (the ratchet)

Consent is given to a permission surface, not to a publisher. A Managed host
MUST NOT apply an update whose `permissions` widen what the user approved —
new egress hosts or ports, new listeners, new or broader filesystem scopes
(`state:r` → `state:rw`), new secrets, or `root` — without a fresh consent,
not even on a user-triggered "update now". Narrowing never needs consent.
Coverage rules: a bare `host` covers every port of that host; `*.example.com`
covers every host under it (not the apex); an ingress entry without an
address covers every address; `rw` covers `r`. The reference implementation
(`axp.updates.permissions_widened`) is normative for these rules.

## 8. Signing & trust

### 8.1 Model — ed25519 + Trust On First Use

Signing is ed25519 (minisign-style: no CA, no PKI, self-hostable). One key per
extension in v0.3 (m-of-n is post-v1). First install verifies against
`signing.public_key` and **pins** it under the extension id; every later
manifest MUST verify against the pinned key or a valid rotation (§8.3).

A host MAY additionally ship **trust anchors** (an org-wide allow-list of
publisher keys, or a registry key) and refuse TOFU for unknown keys — that is a
host policy layered on top, not part of the manifest.

### 8.2 What is signed, and how keys are written

- **Scope:** JCS (RFC 8785) canonicalization of the whole manifest with
  `signature` and `signature_prev` removed. Because the manifest contains every
  artifact digest, the signature binds bytes, version, channel and
  `valid_until` into one unit.
- **Key format:** `ed25519:<base64 of the 32 raw public-key bytes>`. Raw bytes,
  not SPKI/DER — every ed25519 library consumes them directly; for OpenSSL
  prepend the 12-byte SPKI prefix `302a300506032b6570032100` (see
  [`docs/SIGNING.md`](docs/SIGNING.md)).
- **Signature:** base64 of the 64-byte ed25519 signature, inline in `signature`.

```jsonc
"signing": { "public_key": "ed25519:…", "key_id": "graph-memory-2026", "next_key": null },
"signature": "…"
```

### 8.3 Key rotation — announce, then dual-sign

1. A normal release sets `signing.next_key` (still signed by the pinned key).
2. The first release under the new key is dual-signed: `signature` by the new
   key, `signature_prev` by the old pinned key, `signing.public_key` = new key
   (must equal the announced `next_key`). The host verifies both, then re-pins.
3. Later releases are signed by the new key alone.

A key lost without an announced successor cannot self-rotate; recovery is an
explicit user re-trust (fresh TOFU). That is the safe outcome.

### 8.4 Unsigned extensions

Install with a clear warning. **Ratchet:** once installed signed, a later
unsigned manifest for the same id MUST NOT be accepted silently.

### 8.5 The publisher key directory (second channel)

TOFU plus announce-then-dual-sign has one weak spot: whoever steals the
current signing key can announce a successor and rotate every host to a key
they control. And a publisher who *loses* the key has no path back except
asking every user to re-trust by hand. Both are fixed by a second channel the
attacker must also control — the publisher's own domain.

A publisher SHOULD serve
**`https://<publisher>/.well-known/agent-extension-keys.json`**:

```jsonc
{
  "publisher": "ext.example.com",
  "keys": [
    { "public_key": "ed25519:…", "key_id": "graph-memory-2026",
      "extensions": ["graph-memory"],   // optional: restrict to these names
      "revoked": false }
  ]
}
```

A Trusted host SHOULD fetch it (HTTPS, same SSRF rules as any fetch) whenever
a manifest's key differs from the pinned key, and then:

- **Rotation** (§8.3, dual-signed, announced): accepted only if the new key is
  listed. A stolen key alone no longer moves the pin.
- **Recovery** (no announcement): if the directory lists the new key and no
  longer lists the pinned key, the manifest verifies against the new key, and
  the host has the user's explicit permission, the host MAY re-pin. This is
  never silent — it is the interactive re-trust §8.3 requires, with the
  publisher's domain vouching instead of the user guessing. If the directory
  still lists the pinned key, the situation is a compromise, not a recovery:
  refuse.
- **First use**: a host MAY consult the directory and refuse to pin a key it
  does not list (strict mode).

If the directory is unreachable the host MUST NOT guess: treat the rotation
as *deferred* (retry on the next check, keep the old pin) rather than either
accepting or permanently refusing. A publisher without a directory gets the
§8.3 behaviour unchanged. The directory is fetched from the publisher domain
of the *installed record*, never from a URL inside the candidate manifest.

## 9. Trust boundary of the manifest origin

The signature proves *who published*; the origin proves *where it came from*.
A host SHOULD warn when the manifest origin's registrable domain differs from
`identity.publisher`, and MUST refuse an `archive` whose `url` is `http://`.
Where the origin can never be the publisher's own — a code forge such as
GitHub (§3.1 step 3), a CDN — the origin proves nothing about identity, so a
host SHOULD require a signed manifest there and refuse an unsigned one: only
the signature (and, on first use, the key directory of §8.5) ties the document
to `identity.publisher`. The consent prompt SHOULD name the foreign origin so
the user can confirm that the repository or site really belongs to the
publisher.
Hosts SHOULD apply SSRF protections (no private/link-local addresses) to every
fetch they make on a user's behalf. Same-origin rules for artifacts are host
policy (the digest, not the origin, is what is trusted).

## 10. Standalone install (mandatory fallback)

Every shell-based target MUST ship lifecycle scripts that run **with zero AXP
support**:

1. **Standalone-runnable.** `./install.sh` (or `curl -fsSL <url> | bash`)
   performs the entire installation. No AXP host may be assumed present.
2. **Idempotent.** Re-running converges.
3. **Env-or-default config.** Works with `AXP_CONFIG_FILE` / `AXP_*` from a
   host *and* with none of them (sane defaults, or a TTY prompt unless
   `AXP_NONINTERACTIVE=1`).
4. **Self-contained.** Fetches its own dependencies; those fetches are network
   egress and MUST be declared in `permissions.network_egress` (a sandboxing
   host will otherwise block them — the publisher's own artifact host is
   always allowed).

**Trust boundary:** signature verification, consent, pinning and freshness are
properties of the **host**. A hand-run `install.sh` opts out of all of them,
exactly like any `curl | bash`. The spec says so out loud so a hand-installer
knows what they give up.

## 11. Host conformance profiles

A host declares the highest profile it fully implements (and reports it in
`AXP_HOST` documentation and its install records). Each profile includes the
ones before it.

| profile       | MUST                                                                                       |
|---------------|--------------------------------------------------------------------------------------------|
| **Core**      | read v0.x manifests per §2.4; select a target (§5, incl. `posix` fallback); support `archive`; verify sha256; run lifecycle hooks with the §6 contract; retain the artifact (§6.1); show `permissions` for consent before any script runs; record the install (id, version, digest, enforcement actually applied). |
| **Trusted**   | verify signatures (§8), pin on first use under the extension id, enforce the same-key rule, rotation, the unsigned ratchet, and `valid_until` warnings; SHOULD consult the publisher key directory on rotation (§8.5) and defer when it is unreachable. |
| **Managed**   | resolve all three `updates.source` kinds; track the channel as host state (§7.2); per-extension policy; monotonic apply with `upgrade` + `AXP_FROM_VERSION`; the consent ratchet (§7.6); run `health` after install/upgrade and on a schedule; evaluate `runtime_version` and `requires.extensions` with the §4.3 grammar and refuse when a hard dependency is missing, naming it. |
| **Sandboxed** | apply at least the `advisory` tier to lifecycle hooks derived from `permissions` (egress allow-list incl. resolvers and the publisher's hosts; read-only tree except declared scopes, install prefix, state/cache); report downgrades honestly; `enforced` for runtime code where the runtime allows it. |

A conformance test-suite lives in `conformance/` (see repo README); a host
claiming a profile SHOULD pass it.

## 12. Runtime profiles

Everything runtime-specific — the runtime id, its `delivery` extras, its
namespaced scopes and env variables, how `component_map` entries are realised,
which enforcement tier it can offer — lives in one document per runtime under
[`docs/runtimes/`](docs/runtimes/):

- [`posix.md`](docs/runtimes/posix.md) — the baseline (normative).
- [`hermes.md`](docs/runtimes/hermes.md) — Hermes / `hermes-integration`.
- [`openclaw.md`](docs/runtimes/openclaw.md) — OpenClaw / ClawHub.
- [`claude-code.md`](docs/runtimes/claude-code.md) — Claude Code (MCP + plugins).

Adding a runtime = adding a profile document. The core spec does not change.

## 13. Migration

### v0.3 → v0.4 (additive)

No manifest field changed meaning. New, all optional: the publisher key
directory (§8.5) at a well-known URL; hosts gain the tracked-channel rule
(§7.2), the freshness cadence (§7.4) and the consent ratchet (§7.6). A v0.3
manifest is a valid v0.4 manifest; `spec_version: "0.3"` stays valid.

### v0.2 → v0.3

| v0.2                                   | v0.3                                                                 |
|----------------------------------------|----------------------------------------------------------------------|
| `identity.name` global                  | `identity.publisher` + `name`; id is `<publisher>/<name>`             |
| `provides.persona`                      | `provides.prompts` (`persona` still read as an alias)                 |
| `requires.extensions: ["x >= 1.0"]`     | `[{ "id": "pub/x", "version": ">=1.0" }]`                              |
| `filesystem: ["skills:rw"]`             | `["hermes:skills:rw"]` (core scopes: state/cache/config/secrets/workspace/system) |
| `delivery.method: hermes-integration` only | `archive` is the baseline; `hermes-integration` is a Hermes-profile method |
| `uninstall_command` (absolute path)     | host retains the artifact; `lifecycle.uninstall` runs from `AXP_ARTIFACT_DIR` |
| implicit env                            | §6 contract (`AXP_*`), `AXP_CONFIG_FILE` for config + secrets        |
| key format ambiguous                    | raw 32-byte ed25519, base64                                           |
| unknown fields: unspecified             | §2.4 forward-compat rule                                               |
| —                                       | `network_ingress`, `secrets`, `platforms`, `mcp_servers`, `channels`, `model_providers`, `hooks`, conformance profiles |

A v0.3 host reads v0.2 manifests: missing `publisher` → derived from the
manifest origin's registrable domain (and flagged as derived); `persona` →
`prompts`; bare `skills:*` scope → `hermes:skills:*` when the runtime is Hermes.

## 14. Open questions (to resolve before v1.0)

1. **Multi-signer / m-of-n** and organisational trust anchors — same `signing`
   block or a new one?
2. **Dependency resolution** order, shared-dep conflicts, and whether a host may
   auto-install `requires.extensions` from their publishers.
3. **Enforcement negotiation** — if a manifest's `reason` implies it needs
   `enforced` but the host only offers `declared`, warn or block? (Draft: warn.)
4. **Non-POSIX hosts** (Windows): a `lifecycle` variant with PowerShell
   scripts, or leave to runtime profiles?
5. **Registry/catalogue** discovery (`axp://<publisher>/<name>` → well-known
   lookup) — useful, but must stay optional so the decentralised path remains
   the default.
