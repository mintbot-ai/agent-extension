# Agent Extension Protocol (AXP) — SPEC v0.5 (DRAFT)

> Status: **draft, for review.** v0.3 was the *universality* revision (publisher-
> namespaced identity, the runtime-neutral `posix` target with `archive`
> delivery, the host→script environment contract, host-retained artifacts,
> runtime-neutral permission scopes, MCP servers as a first-class component,
> the forward-compatibility rule, host conformance profiles). v0.4 was the
> *hardening* revision, additive only: the publisher key directory as a
> second trust channel for key rotation and lost-key recovery (§8.5), a
> precise tracked-channel rule (§7.2), freshness guidance that does not
> nag (§7.4), pinned environment semantics (§6.2), and the consent ratchet
> for updates (§7.6). Runtime specifics live in [`docs/runtimes/`](docs/runtimes/).
> v0.5 adds optional isolated panel views (§4.2.1), managed-service
> enable/disable hooks (§6.5) and commerce: signed entitlements, key roles
> and entitlement-gated artifacts, without any payment handling (§14).
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

`spec_version` is `MAJOR.MINOR`. Minor revisions preserve existing manifests.
A host MUST NOT refuse a manifest solely because its minor version is newer:
it ignores unknown fields and component types subject to the closed-vocabulary
exceptions in §2.4. New entries in closed vocabularies can require a host
upgrade: pre-0.5 reference validators and schemas reject `enable` / `disable`
lifecycle hooks rather than ignoring them (§13). Major revisions may break.
A host MUST refuse a manifest whose major it does not understand with a clear
message, never half-parse it.

### 2.3 Namespacing

Three kinds of identifier appear in the manifest, all lowercase:

- **Core identifiers** (component types, scope names, delivery methods,
  runtime ids, permission keys) are bare words defined in this spec, e.g.
  `state`, `archive`, `posix`, `mcp_servers`.
- **Runtime-scoped identifiers** are `<runtime>:<word>`, e.g. `hermes:skills`
  (a filesystem scope only Hermes hosts understand), `openclaw:channels`. A
  host that does not implement `<runtime>` MUST ignore them, except in closed
  vocabularies (§2.4).
- **Vendor extensions** are `x-<vendor>-<word>` fields or values, e.g.
  `x-acme-billing`. Hosts MUST ignore unknown `x-` entries except in closed
  vocabularies (§2.4).

New core identifiers are added only by this spec. Runtime ids are listed in
[`docs/runtimes/README.md`](docs/runtimes/README.md); anyone may register one
by adding a profile document there.

### 2.4 Forward compatibility (normative)

- Unknown **fields** MUST be ignored except for the closed permission-key and
  lifecycle-hook vocabularies below.
- `targets[].lifecycle` is a closed vocabulary: unknown hook keys MUST cause
  refusal, including `x-` and `<runtime>:` hook names. In 0.5 the allowed keys
  are `install`, `upgrade`, `uninstall`, `health`, `enable`, and `disable`;
  only `install` and `uninstall` are required. Hook keys name executable
  lifecycle actions, not opaque metadata. This exception preserves the
  reference validator and schema's existing refusal behavior.
- Unknown **component types** under `provides` and unknown keys under
  `component_map` MUST be ignored (the extension still installs; the host just
  cannot manage that component individually).
- Unknown **values** of *security-relevant* enums — `targets[].enforcement`,
  `updates.policy`, `release.channel` core ordering, permission keys — MUST
  cause a refusal, because guessing would either over-promise or under-warn.
  All other unknown enum values are ignored.
- Outside closed vocabularies, a host MUST NOT refuse a manifest merely
  because it contains `x-` or `<runtime>:` entries it does not understand.

The JSON Schema in `schema/` encodes these rules (`additionalProperties` is
permissive where this section says "ignore").

## 3. The manifest

### 3.1 Discovery

A host resolves a user-supplied *locator* to a manifest document in this order:

1. A URL whose path ends in `.json` is fetched as the manifest itself.
2. Otherwise, for an `https://<domain>/…` URL or bare domain:
   `<link rel="agent-extension" href="…">` in the landing page `<head>`, else
   `https://<domain>/.well-known/agent-extension.json`.
3. A git repository URL: the newest release's `agent-extension.json` asset
   (§7.1) — the `latest` release, else the release listing so that a
   repository whose newest release is a pre-release resolves to it — and
   only then `agent-extension.json` at the repository root. `…/tree/<ref>`
   and `…/releases/tag/<tag>` pin one document. Only an absent document
   moves a host on to the next candidate; a repository is never the
   publisher's origin, so the document MUST be signed (§8).
4. A local path (`file://…` or a directory): `agent-extension.json` there.

Fetches MUST be HTTPS (or local). The manifest's origin SHOULD match
`identity.publisher` (§4.1); a mismatch is surfaced to the user as a warning
(the signature still decides trust).

Canonical filename everywhere: **`agent-extension.json`**.

A manifest is a small document: publishers SHOULD keep it under 64 KiB
(hosts MAY refuse larger ones — the reference host does). Large payloads such
as schemas or prompt fragments belong in the artifact, referenced by path.

### 3.2 Top-level shape

```jsonc
{
  "spec_version": "0.5",
  "kind": "agent-extension",

  "identity":    { … },   // §4.1 — who/what this is (publisher-namespaced)
  "provides":    { … },   // §4.2 — LAYER 1: abstract capability description
  "requires":    { … },   // §4.3 — abstract needs (deps, resources)
  "permissions": { … },   // §4.4 — declared access surface

  "release":     { … },   // §7   — this version's channel, artifact, freshness
  "updates":     { … },   // §7.1 — where newer versions are found
  "signing":     { … },   // §8   — publisher key(s), rotation
  "signature":   "…",     // §8.2 — ed25519 sig over the canonical manifest

  "commerce":    { … },   // §14  — optional: the extension is sold (entitlements, plans, gated delivery)

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
  "settings_section": { "title": "Graph memory", "summary": "Remembers people, projects and decisions across conversations." },
  "config":      { "schema_ref": "schemas/config.schema.json", "secrets": ["FALKOR_PASSWORD"] }
}
```

Core component types and their required fields:

| type              | required            | notes                                                        |
|-------------------|---------------------|--------------------------------------------------------------|
| `mcp_servers`     | `name`, `transport` | `transport` ∈ `stdio \| http \| sse`; `command_ref` (stdio) or `url` (http/sse); `auth` (http/sse — endpoint access, below). The portable tool surface — any MCP-capable runtime can use it. |
| `tools`           | `name`              | runtime-native tools; `input_schema_ref` (JSON Schema)        |
| `services`        | `name`, `kind`      | `kind` ∈ `daemon \| oneshot \| sidecar`; `endpoint`; `auth` (endpoint access, below) |
| `panel_views`     | `name`, `title`, `service`, `path`, `capabilities` | isolated host UI; optional `icon`; see §4.2.1 |
| `settings_section` | `title`, `summary` | one object, not a list: the extension's own section in the host's settings; optional `icon`, `views`, `localized`; see §4.2.2 |
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

**Endpoint access.** An `mcp_servers` entry with `transport: http | sse` and a
`services` entry with an `endpoint` MAY carry an `auth` object saying how a
client authenticates at that endpoint:

```jsonc
"mcp_servers": [ { "name": "mintbot", "transport": "http", "url": "http://127.0.0.1:8650/mcp",
                   "auth": { "scheme": "bearer", "token_file": "state:token" } } ]
```

| field        | required     | meaning                                                                 |
|--------------|--------------|-------------------------------------------------------------------------|
| `scheme`     | yes          | `bearer` — the client sends `Authorization: Bearer <token>`. An unknown scheme is ignored (§2.4): the host then shows the endpoint without a credential. |
| `token_file` | for `bearer` | `state:<relative path>` — the file below the extension's own `AXP_STATE_DIR` that holds the token. The extension creates it (typically in `install`); it is never part of the artifact or the manifest. Only the `state` scope is allowed: a credential is the extension's durable data. |

An absent `auth` means the endpoint takes no credential, or one the host
cannot know about. A host that understands `auth` MAY read the token file —
as the privileged host itself, never through a lifecycle hook — in order to
(a) register an `http`/`sse` MCP server in its runtime's MCP config with the
header filled in, and (b) show the owner, on an authenticated surface only,
how to connect an external client: the endpoint, the token and a ready-made
client entry (`mcpServers.<name>` with `url` and `headers.Authorization`). It
MUST treat the value as a secret: never log it, never write it into the
install record or an update report, never hand it to a caller that is not the
authenticated owner. A missing or empty token file is reported as such
("token not created yet"), never invented. `auth` says nothing about who may
*reach* the endpoint: the listener is still declared in
`permissions.network_ingress`, and a loopback endpoint stays loopback — the
host may explain how to tunnel to it, it MUST NOT expose it on its own.

**Direct access (host option).** The owner MAY ask the host to publish one
bearer-authenticated endpoint (`auth.scheme: bearer`) on the host's own
authenticated HTTPS origin, so a client reaches it from anywhere without a
tunnel. The decision is the owner's, never the extension's or the host's:
the manifest cannot request it, and a host offering it MUST

- keep it off by default and require an explicit per-endpoint choice by the
  owner (or a principal the host trusts as the owner), made on an
  authenticated surface, next to a plain statement that the endpoint then
  answers anyone on the internet who presents its token — the token alone
  stands between the internet and the host;
- relay to the loopback listener without changing it: the extension keeps
  listening on loopback, the token file stays the extension's, and the host
  MUST NOT alter `permissions.network_ingress`, the install record's consent
  or the extension's own view of its endpoint;
- demand the endpoint's bearer token on every request and on every WebSocket
  upgrade, compare it to the token file in constant time *before* anything
  reaches the extension, and answer a missing or wrong token with `401` and
  nothing else — no health route, no error body that names the extension;
- forward nothing of its own: no host credential, cookie, session or
  forwarded-identity header reaches the extension, and the host's own
  authentication MUST NOT be accepted in place of the token;
- send `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and keep
  the token out of logs, install records and update reports as §4.2 has it;
- stop relaying at once when the owner switches it off, when the extension is
  disabled or uninstalled, or when the token file is missing or empty (fail
  closed, never fall back to an unauthenticated relay);
- record the choice on its own install record (host-owned state, not the
  manifest) so it survives updates and is shown wherever the host shows how
  to connect to the endpoint.

The path under which the host publishes the endpoint is the host's; the
reference host uses `/ext/<extension>/<component>`. A host MUST say, wherever
it shows the connection settings, whether direct access is on and which
address a client is to use. A host that does not offer direct access is
conformant: the rule above — a loopback endpoint stays loopback unless the
owner says otherwise — is the whole of it.

### 4.2.1 `panel_views` — optional isolated host UI

A panel view declares an application served by an extension service, not an
arbitrary URL. It does not grant access to the host UI, filesystem, or APIs.
A supporting host MAY offer it alongside its conversation UI and in a
fullscreen presentation. This component is optional: hosts without support
MUST ignore it and MUST NOT expose its service or manufacture a direct link.

```json
"panel_views": [{
  "name": "desktop", "title": "Desktop", "icon": "monitor",
  "service": "desktop", "path": "/desktop/",
  "capabilities": ["pin", "fullscreen"]
}]
```

- `name`, `title`, `service`, `path`, and `capabilities` are REQUIRED; `icon`
  is optional. `title` and `icon`, when present, are non-empty strings.
  Hosts MUST render titles as text, never markup. `icon` is a host-interpreted
  hint, never executable markup or a URL to fetch; unknown hints use a fallback.
- View names MUST be unique within the extension. `name` and `service` use
  `[a-z0-9][a-z0-9_-]*`, at most 64 characters, with no trailing whitespace.
  `service` MUST match exactly one `provides.services[].name`.
- The referenced service's `endpoint` MUST be `http://127.0.0.1:<port>` or
  `http://[::1]:<port>`, with an optional final `/`. The explicit decimal port
  MUST be 1–65535 (one to five digits). No hostname, alternate IP spelling,
  userinfo, query, fragment, whitespace, or other path is allowed. This
  restriction applies only to services referenced by panel views.
- `path` is the upstream root-relative entry path, e.g. `/desktop/` or `/`.
  It MUST use unencoded ASCII URI path characters: letters, digits, `/`,
  and `._~!$&'()*+,;=:@-`. It MUST NOT contain repeated slashes, `.` or `..`
  segments, backslashes, whitespace, control characters, query or fragment.
  Percent escapes are deliberately disallowed, including double encoding,
  to avoid traversal/slash ambiguity between proxy and upstream decoders.
  Validators MUST reject rather than normalize invalid values.
- `capabilities` MUST be a list of strings (possibly empty). `pin` means the
  host may offer a view pinned beside conversation; `fullscreen` means it may
  offer an expanded presentation. Unknown strings MUST be ignored, not cause
  rejection or grant extra privileges. These are presentation hints, not
  permission grants or a requirement to implement a particular layout.

**Host-owned transport.** A supporting host MUST use an authenticated,
view-scoped HTTP/WebSocket prefix mount; it MUST NOT accept a browser-selected
upstream URL. The host resolves the service and path from the installed,
validated manifest. It MUST retain authority over routing, redirects and
WebSocket upgrades, never follow a redirect to a different origin or outside
the permitted view subtree. Derive that subtree syntactically from the
validated entry path: a path ending in `/` is its own subtree; otherwise
use everything through its last `/` (its parent directory). Do not infer
directory status from a filename extension, upstream response or redirect.

| Entry path | Permitted asset/WebSocket subtree |
|------------|-----------------------------------|
| `/` | `/` |
| `/desktop` | `/` |
| `/desktop/` | `/desktop/` |
| `/desktop/index.html` | `/desktop/` |

Thus `/desktop` is an entry document with the service root as its subtree,
not shorthand for `/desktop/`. Publishers wanting confinement to `/desktop/`
MUST declare the trailing slash or an entry document beneath it. The entry
path itself is unchanged; deriving the subtree does not append a slash or
rewrite the initial upstream request. `/` grants the referenced service's root.
Packages MUST use relative URLs within that subtree or be prefix-aware;
hosts need not rewrite application source. Query strings on application
requests are distinct from manifest paths; hosts MUST remove host credentials
from them before any forwarding.

**Isolation and credentials.** Extension HTML is untrusted. Hosts MUST isolate
it from their own document origin and privileged APIs. A browser host SHOULD
use a sandboxed iframe with `allow-scripts` but without `allow-same-origin`,
or an equivalently isolated origin. Pin/fullscreen MUST preserve this isolation.
Owner/member credentials MUST NOT appear in iframe URLs (the application can
read its own location), HTML, messages, logs, or upstream requests. Extensions
receive no host login/session/API tokens. A host MAY instead mint an opaque,
short-lived, revocable capability scoped to the authenticated principal,
installed extension and one view, usable only at that view's proxy prefix.
This capability conveys no other host authority. The host strips the prefix
and capability before forwarding; never pass it to the service.

Authenticate capability issuance using the host's normal authenticated,
CSRF-protected UI. Check capability validity, expiry, principal authorization
and the enabled install on EVERY request and WebSocket upgrade. Ignore host
cookies/Authorization at capability-route ingress, strip them before upstream
forwarding, and never allow upstream cookies or authentication challenges to
alter the host session. A sandbox may send `Origin: null`; accept it (and
supply the minimal necessary CORS response) only for a valid scoped capability,
not as a general CORS exemption. Use `Referrer-Policy: no-referrer` and
`Cache-Control: no-store` on issuance and proxy responses; redact capabilities
from logs. Revocation, expiry, principal access loss, disable and uninstall
MUST revoke access and close existing WebSockets, not just reject new ones.

A service MAY use the existing `auth: {scheme: bearer, token_file: state:...}`
contract. The host reads the extension-owned token securely within its state
scope and injects it only on the upstream hop, replacing any client header.
Missing/empty token files or unsupported auth schemes MUST fail closed for
panel proxying; never fall back to forwarding owner credentials. Ordinary
endpoint display rules above are unchanged. Panel views are the explicit,
authenticated exception to the rule against exposing loopback endpoints.

The reference `validate_panel_views(provides)` checks declaration structure,
reference uniqueness, path, origin and existing bearer-file syntax without
mutation or I/O, returning detached view dictionaries (`[]` when absent) or
raising `PanelViewError`. It lives in the standalone stdlib-only
`axp/panel_views.py`; whole-manifest validation translates its errors to
`ManifestError`. Hosts MUST implement the transport/isolation/lifecycle rules;
passing validation alone does not make a proxy secure. Schema-only validation
cannot check cross-component references or their endpoint restrictions.

### 4.2.2 `settings_section` — optional section in the host's settings

An extension MAY ask for one section of its own in the host's settings: the
place where the user reads, in plain words, what the extension does for them,
switches it on or off and opens its views. The host renders the section and
owns its controls; the extension supplies only text and references, never
markup, scripts or URLs. The component is optional: hosts without support
ignore it, and the extension stays manageable wherever the host lists its
extensions.

```json
"settings_section": {
  "title": "Agent desktop",
  "summary": "A shared desktop for you and your agent, right in your browser.",
  "icon": "monitor",
  "views": ["desktop"],
  "localized": {
    "et": { "title": "Agendi töölaud", "summary": "Jagatud töölaud sulle ja sinu agendile otse brauseris." }
  }
}
```

- `title` (REQUIRED, at most 60 characters) names the section. `summary`
  (REQUIRED, at most 400 characters) says what the extension does for the
  user, not how it works: permissions, ports and install steps belong to the
  consent card (§4.4). Both are plain text without control characters; hosts
  render them as text, never markup.
- `icon` is optional: a host-interpreted hint, as for a panel view.
- `views` is optional: names of panel views (§4.2.1) the host offers from the
  section, each naming a declared view at most once.
- `localized` is optional: an object keyed by BCP 47 language tag (`et`,
  `pt-BR`), each value carrying a `title` and/or a `summary` under the same
  rules. A host picks the closest match for the user's language and falls
  back to the base strings. A host that curates an extension MAY show its own
  translations instead.
- Unknown fields are retained, not interpreted (§2.4).

**Host-owned controls.** A supporting host binds the section to the
extension's lifecycle:

- An on/off switch. Off disables the extension (§6.5): its components stop
  and its data stays. On enables it again. The switch never uninstalls and
  never widens permissions.
- A host MAY show the section of an extension it offers but has not installed
  yet. Switching that on starts the normal installation: the user sees and
  approves the consent card (§4.4) before anything is downloaded or run.
  Showing a section MUST NOT download, install or start anything.
- Entries that open the listed views, with their declared presentation
  capabilities.

A host MAY give each section its own entry or route in its settings
navigation, or group sections under one heading for extensions.
Configuration an extension needs beyond on/off belongs in a panel view under
that view's isolation rules; a settings section grants no access to the host
UI.

**Management and use are different places.** A host that lists its
installed extensions (switch, update policy, update, remove) SHOULD keep that
list to management and put the use of an extension — its views, its endpoint
connection settings (§4.2 *Endpoint access*, *Direct access*), its direct
connection guidance — in the extension's own section. The list entry of an
extension declaring a section SHOULD link to that section ("Open <title>");
an extension declaring views but no section MAY open them from its list
entry; an extension declaring neither has no interface to open and gets no
such link. Connection settings and credentials MUST NOT be shown from the
management list of a host that offers sections.

The reference `validate_settings_section(provides)` checks the declaration
and its view references without I/O, returning a detached copy (`None` when
absent) or raising `SettingsSectionError`. Like `axp/panel_views.py`, its
module `axp/settings_section.py` is standalone and stdlib-only, so a host can
vendor it; whole-manifest validation translates its errors to `ManifestError`.

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
`>=X`, `>X`, `<=X`, `<X`, `=X`, `^X`, `~X`. `^X` keeps the first non-zero
segment fixed (npm semantics: `^1.2` = `>=1.2 <2`, `^0.2.3` = `>=0.2.3 <0.3`);
`~X` keeps everything but the second segment fixed (`~1.2.3` = `>=1.2.3 <1.3`,
`~1` = `>=1 <2`). Versions are compared segment-wise numerically, so both
semver (`1.4.0`) and calver (`2026.6`) work; a missing trailing segment counts
as zero. Pre-release tags compare lower than the release. The reference
implementation (`axp.versions`) is normative for this grammar.

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
  "network_egress":  ["api.example.com:443"],      // host[:port]; "*.example.com" wildcard; "*" = any host
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

**Egress entries** are `host[:port]`. `*.example.com` covers every host under
`example.com` (not the apex). A bare `*` (or `*:443`) declares egress to *any*
host (on that port): the open internet, for an extension that is a browser or
a workstation rather than a client of a few services. It is a permission like
any other — shown for consent as the widest grant there is, and widening to it
needs fresh consent (§7.6) — but a host that filters egress by name has
nothing to filter against a port-less `*`. Such a host MUST NOT run a proxy
that admits everything and report it as containment: it leaves that
extension's network open, keeps whatever else it enforces, and records the
network half as not enforced (`docs/HOST-GUIDE.md`, "Runtime containment").
`*:443` can still be filtered by port.

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
  so an undeclared access *fails*. "Runtime code" is decided per component:
  the processes the host launches itself (`services` bound with `command` or
  a `unit`, stdio `mcp_servers`) can be contained on any host with a process
  sandbox; code loaded *into* the agent process (`tools`, `hooks`, `channels`,
  `model_providers`, `memory`) only if the runtime can isolate it. The install
  record carries the tier per component; the extension-level tier is the
  weakest tier among its runtime components.

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

A host MAY cap the artifact it downloads and what it unpacks to (the reference
host stops at 64 MiB / 512 MiB) and MUST refuse archives whose members escape
the extraction root. Publishers SHOULD keep the artifact small — lifecycle
scripts, schemas, small payloads — and let `install` fetch heavy dependencies
(§10: those fetches are declared egress).

### 5.3 `component_map` — string or rich object

Each binding is **either** a plain string (`"skills/"` — "it's here, the
install script does the rest") **or** a rich object describing *what to do*.
The rich form lets a host manage a component directly (enable/disable a
service, re-register an MCP server) without re-running the whole install.

Common rich-object fields (all optional; component-specific):

- `mcp_servers`: `command` (argv, relative to the install prefix), `env`,
  `url`, `register` (`auto` = host registers it in the runtime's MCP config).
  Without `command` a host falls back to the component's `command_ref`
  (§4.2), resolved inside the retained artifact.
- `services`: **either** `command` (argv, relative to the install prefix —
  the host owns the process: it writes and manages the unit itself, and the
  install script MUST NOT start the daemon) **or** `unit`
  (`systemd:<name>`, `launchd:<label>`, `supervisor:<name>` — a unit the
  install script created; the host may re-affirm `actions`
  `daemon-reload`/`enable`/`start`/`stop` and, on a Sandboxed host, attach
  containment to it). Plus `env` (extra environment), `restart`
  (`always`/`on-failure`/`no`; default `on-failure`), `health`.
- `tools`: `module`, `register`, `unregister`.
- `skills`: `dir`, `link` (`copy`/`symlink`).
- `cron`: `unit`, `schedule`.

String sugar: `"skills/"` ≡ `{ "dir": "skills/" }`; `"systemd:x.service"` ≡
`{ "unit": "systemd:x.service" }`. Unknown fields are ignored (§2.4).

When `provides` lists **several** components of one kind, the binding is an
object keyed by component name instead (`"services": { "store": { "command":
["bin/store"] }, "indexer": "systemd:indexer.service" }`); with a single
component the unkeyed form binds to it directly.

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
| `AXP_SPEC_VERSION`    | all          | the spec version the HOST implements (`0.5`) — not the manifest's |
| `AXP_HOST`            | all          | `<host-id>/<host-version>` (`mintbot/2026.8`, `axp-cli/0.5.0`) |
| `AXP_RUNTIME`         | all          | runtime id of the chosen target (`posix`, `hermes`, …)         |
| `AXP_RUNTIME_VERSION` | all          | runtime version if known                                       |
| `AXP_ENFORCEMENT`     | all          | tier actually applied to this run (`declared\|advisory\|enforced`) |
| `AXP_HOOK`            | all          | `install \| upgrade \| uninstall \| health \| enable \| disable`                     |
| `AXP_EXT_ID`          | all          | `<publisher>/<name>`                                          |
| `AXP_EXT_PUBLISHER`   | all          | publisher DNS name                                            |
| `AXP_EXT_NAME`        | all          | name slug                                                     |
| `AXP_EXT_VERSION`     | all          | version being installed / run                                 |
| `AXP_FROM_VERSION`    | upgrade      | previously installed version                                   |
| `AXP_PREFIX`          | all          | suggested install prefix; default `/opt/<name>` (root) or `~/.local/opt/<name>` |
| `AXP_STATE_DIR`       | all          | durable data dir (scope `state`); default `/var/lib/axp/<publisher>/<name>` or `~/.local/state/axp/<publisher>/<name>` |
| `AXP_CACHE_DIR`       | all          | disposable cache dir (scope `cache`); default `$XDG_CACHE_HOME/axp/<publisher>/<name>` |
| `AXP_ARTIFACT_DIR`    | all          | the unpacked artifact the running hook belongs to: the staging dir during `install`/`upgrade` (retention happens after success, §6.1), the retained dir for `uninstall`/`health`/`enable`/`disable`; default = script's own dir |
| `AXP_CONFIG_FILE`     | install, upgrade | path to a 0600 **dotenv-format** file with the user's config values incl. secrets (§6.3); unset = use defaults / prompt |
| `AXP_PURGE`           | uninstall    | `1` = also delete `AXP_STATE_DIR`; default `0` (keep user data)  |
| `AXP_NONINTERACTIVE`  | all          | `1` = never prompt (host-driven run); default unset (may prompt on a TTY) |
| `AXP_ENTITLEMENT_FILE` | all, while an entitlement is held | the current entitlement document (§14.8): a **stable** 0600 JSON file rewritten on renewal and removed on expiry; unset = no entitlement held |

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

- `install`/`upgrade`/`uninstall`/`enable`/`disable`: exit 0 = success; non-zero = failure; the
  host shows the last lines of stderr/stdout to the user. Exit **75**
  (`EX_TEMPFAIL`) means "retry later" (e.g. a dependency download failed).
- `health`: exit 0 = healthy, 1 = unhealthy, 2 = unknown/degraded. Stdout MAY
  carry a one-line human status; if it begins with `{` it is a JSON object
  (`{"status":"ok","detail":"…"}`) hosts MAY render.
- Scripts MUST be idempotent (§10).
- Under a read-only tree an `uninstall` hook can empty `AXP_PREFIX` but not
  unlink the prefix itself (its parent is read-only), so the idiomatic
  `rm -rf "$AXP_PREFIX"` exits non-zero after removing everything it
  installed. Hosts MUST treat a non-zero `uninstall` exit that leaves the
  prefix empty (or gone) as success and remove the empty prefix themselves;
  any other non-zero exit is the publisher's failure. Hooks SHOULD not rely
  on this: `find "$AXP_PREFIX" -mindepth 1 -delete` exits 0 either way.

### 6.5 Optional enable / disable

`lifecycle.enable` and `lifecycle.disable` are OPTIONAL artifact-relative hook
paths for runtime-neutral managed-service activation/deactivation. They run
from the retained artifact with the same environment, containment, timeout,
output and exit-code rules as other hooks; `AXP_HOOK` identifies the action.
They MUST be idempotent and MUST preserve installed files and durable data.
They are not replacements for install/uninstall and MUST NOT require a
particular service manager. A host may manage services via `component_map`
without these hooks; absent hooks do not prevent host-owned activation.

Declaring either hook requires a host whose lifecycle vocabulary supports
0.5. Older reference validators/schemas reject the whole manifest, even if
the hook is in a target the host would not select. See §13 for compatibility.

On disable, the host MUST first persist the disabled state, revoke all panel
capabilities/proxy routes, and close active WebSockets, then stop its managed
services and invoke the optional disable hook. Hook failure MUST NOT restore
proxy access; report any service that failed to stop. On enable, run the
optional enable hook, start host-managed services and check readiness before
issuing new view capabilities. Failure MUST leave the view inaccessible. Old
capabilities MUST NOT become valid again after re-enable, reinstall or update.
Uninstall similarly revokes access before invoking extension code. A disabled
extension stays disabled across restart and update; hooks MUST NOT accidentally
reactivate it. Hosts without secure lifecycle/proxy support MUST leave views
unexposed, even when the rest of the extension installs successfully.

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

**A published version is immutable.** Once a manifest for `identity.version`
X has been served (or attached to a release), the bytes — and therefore the
digests — of X MUST NOT change. Hosts key retained artifacts, "already
installed" checks and the strictly-higher update rule on the version and
would never notice a silent re-cut. Fix a mistake by publishing a higher
version; only a version that was never served may be re-cut.

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
  expired is refused (it is not a valid release any more); the grace window
  softens only the warning about the *installed* manifest, never a
  candidate. The same once-then-monthly cadence SHOULD apply to a
  persistently failing update source.

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
covers every host under it (not the apex); `*` covers every host (`*:443`
every host on that port); an ingress entry without an address covers every
address; `rw` covers `r`. The reference implementation
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

Tooling: `axp sign --key NEW --prev-key OLD` (or `axp release … --key NEW
--prev-key OLD`) writes the dual-signed release; `signature_prev` is never
carried over to a later re-signed document.

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
      "roles": ["manifest"],            // optional: what the key signs; absent = manifest only (§14.3)
      "revoked": false }
  ]
}
```

Every rule in this section concerns keys in the `manifest` role — an entry
without `roles`, or one listing it. Keys listed only with the `entitlement`
role (§14.3) are not manifest keys: they never satisfy a rotation, a
recovery or a first-use check, however genuinely the publisher lists them.

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

### 9.1 Unmanaged installs (host option)

A repository with **no** manifest at all is outside this protocol. A host MAY
still install it — as an *unmanaged install* — provided it (a) never routes a
manifest that failed §8 or §9 there, (b) shows the user, before anything is
placed or run, that no publisher identity, declared permissions, signed
updates or lifecycle hooks exist, (c) pins a commit and never applies a
change unattended, (d) keeps the record visibly distinct from extensions and
outside the trust store, and (e) tells the user when the repository starts
publishing a manifest, so the unmanaged copy can be replaced by the real
extension. The host guide describes the reference behaviour.

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
| **Sandboxed** | apply at least the `advisory` tier to lifecycle hooks derived from `permissions` (egress allow-list incl. resolvers and the publisher's hosts; read-only tree except declared scopes, install prefix, state/cache); report downgrades honestly; contain the runtime components the host launches itself (`services`, stdio `mcp_servers`) with the same derived surface and report them `enforced`; in-process components stay `advisory` unless the runtime can isolate them. |

**Commerce** (§14) is an optional capability a host MAY add on top of
Trusted or higher, not a profile: hold a host key, verify entitlements
against the issuer directory with the `entitlement` role, support import and
SHOULD support checkout + refresh, fetch gated artifacts with a
presentation, hand `AXP_ENTITLEMENT_FILE` to hooks, disable on expiry after
the grace window, and honour `updates_until`. A host that advertises it
SHOULD pass `conformance/test_commerce.py`.

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

### v0.4 → v0.5 (new optional fields; activation-hook compatibility boundary)

Add optional `provides.panel_views` (§4.2.1), `provides.settings_section`
(§4.2.2) and optional lifecycle `enable` /
`disable` (§6.5). Existing manifests without these fields remain valid.
`provides.panel_views` is an additive component: hosts that do not support
views ignore their declarations and MUST NOT expose them.
`provides.settings_section` is additive too: hosts that do not render
settings sections ignore it, and pre-0.5 validators skip it as an unknown
component type (§2.4). *Direct access* (§4.2) is a host option that no
manifest field controls: existing manifests and hosts are unaffected.

Commerce (§14) is additive: the optional top-level `commerce` block,
`targets[].delivery.auth`, the key directory's `roles` and the
`AXP_ENTITLEMENT_FILE` variable are all ignored by hosts that predate them,
and a key directory entry without `roles` means exactly what it meant
before. The one consequence a publisher must know: a pre-commerce host
installs a `commerce.entitlement: required` extension without any
entitlement, and the only thing that stops it is an entitlement-gated
artifact (§14.4), whose fetch such a host attempts plainly and sees refused
with the server's status. Hosts MUST NOT strip `delivery.auth` from a
signed manifest.

Activation hooks require a host upgrade to 0.5 (or an explicit backport of
the 0.5 lifecycle vocabulary and activation semantics). The pre-0.5 reference
validator and schema accept only `install`, `upgrade`, `uninstall`, and
`health` in `targets[].lifecycle`; they reject the entire manifest if any
target declares `enable` or `disable`. They do not silently ignore these
hooks. Changing `spec_version` alone does not bypass that closed vocabulary.
Publishers needing older-host compatibility MUST omit activation hooks from
that manifest and use existing install/uninstall or host-owned component
management; a panel-only declaration without the new hooks can still be
ignored by older hosts. Hosts MUST NOT strip hooks from a signed manifest
to make it validate. Vendoring only the panel helper does not upgrade the
host's whole-manifest lifecycle validator or activation implementation.

Unknown capability strings are retained but not interpreted. The reference
package and new publisher skeletons use 0.5; the signed 0.4 sample-memory
fixture remains unchanged, and the separate unsigned panel-view example
illustrates the new fields. Validators recognizing panel_views must apply its
semantic checks in addition to the JSON Schema.

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

## 14. Commerce — entitlements (optional)

An extension may be sold. AXP does **not** handle payment: no prices are
computed, no checkout is run, no money moves through anything this document
defines. Whoever sells the extension — the publisher, or a marketplace the
publisher names — collects the money however they like and then signs one
small document: the **entitlement**, proof that one host may use the
extension. This section defines that proof, how a host checks it, how a host
obtains it, and how a publisher who does not want to hand out code before
payment keeps the artifact behind it. Everything reuses §8: JCS + ed25519 and
the publisher key directory. A host that verifies manifests verifies
entitlements with the same code and the same trust root.

Support is an optional **capability** on top of the Trusted profile (§11);
hosts that lack it ignore `commerce` under §2.4. The consequences of that
are spelled out honestly in §14.9.

### 14.1 The `commerce` block

```jsonc
"commerce": {
  "entitlement": "required",            // required | optional
  "plans": [                            // display only — a host computes nothing from these
    { "id": "pro-monthly", "kind": "subscription", "period": "month",
      "price": { "amount": 500, "currency": "EUR" }, "title": "Pro, monthly" },
    { "id": "lifetime",    "kind": "one_time", "price": { "amount": 4900, "currency": "EUR" },
      "updates_months": 12 },
    { "id": "trial",       "kind": "trial", "days": 14 }
  ],
  "checkout_url": "https://ext.example.com/paid-tool/buy",          // §14.5
  "refresh_url":  "https://api.ext.example.com/axp/entitlements",   // §14.5, optional
  "issuers":      ["ext.example.com"],                              // default: the publisher
  "grace_days":   7                                                 // §14.6, default 7
}
```

| field | req | meaning |
|-------|-----|---------|
| `entitlement` | ✔ | `required`: a commerce-capable host installs and enables the extension only while it holds a valid entitlement. `optional`: the extension installs and runs freely; an entitlement unlocks paid features inside it (the host still offers purchase, import and renewal). |
| `plans[]` | | What is for sale, for the consent card and catalogues. `id` (slug, what an entitlement's `plan` names), `kind` ∈ `one_time \| subscription \| trial` (an unknown kind is shown as-is and not interpreted, §2.4), `title`, `price` (`amount` in minor units as an integer — JCS forbids floats — and an ISO 4217 `currency`), `period` ∈ `month \| year` (subscription, required), `days` (trial, required), `updates_months` (one-time: how long new releases are covered; absent = all). |
| `checkout_url` | | https; where a host sends the user to buy (§14.5). |
| `refresh_url` | | https; the issuer endpoint a host asks for a new or renewed entitlement (§14.5). |
| `issuers[]` | | DNS names whose key directories may vouch for entitlement keys for this extension (§14.3). Default `[identity.publisher]`. A publisher who lets a marketplace sell for them lists it here. |
| `grace_days` | | How long past `valid_until` the host keeps the extension running while renewal is attempted (§14.6). Default 7. |

The three plan kinds cover the usual models and their combination: a
subscription (use and updates for a period, renewed), a one-time purchase
(use for ever, updates for a window — the "perpetual licence with a year of
updates" model — or all updates when `updates_months` is absent), and a trial
(use for a few days). The plan is a label; what the host enforces is the
entitlement's two dates (§14.2), nothing else.

### 14.2 The entitlement document

```jsonc
{
  "kind": "agent-extension-entitlement",
  "spec_version": "0.5",
  "extension": "ext.example.com/paid-tool",      // the id it is for
  "holder": "ed25519:…",                         // the host key it is bound to (§14.4)
  "plan": "lifetime",
  "serial": "EX-2026-0001",                      // issuer-unique; renewal and revocation refer to it
  "issuer": "ext.example.com",                   // whose key directory lists the signing key
  "issued_at": "2026-10-16T10:00:00Z",
  "valid_until": null,                           // end of the right to USE; null = perpetual
  "updates_until": "2027-10-16T10:00:00Z",       // releases published after this are not covered; null = all
  "signing": { "public_key": "ed25519:…", "key_id": "issuing-2026" },
  "signature": "…"                               // ed25519 over the JCS document minus `signature`
}
```

All fields except `spec_version` and `signing.key_id` are required;
`valid_until` and `updates_until` are required *as keys* and may be `null`.
The signature is computed exactly like a manifest's (§8.2): JCS of the
document with `signature` removed, ed25519, base64. A subscription sets both
dates to the period end; a one-time purchase sets `valid_until: null` and
`updates_until` to the end of its window; a trial sets `valid_until` to the
trial end. Everything else — seats, invoices, customer ids — is the issuer's
business and MAY ride along as `x-` fields (ignored by hosts, covered by the
signature).

The schema is [`schema/agent-extension-entitlement.schema.json`](schema/agent-extension-entitlement.schema.json);
`axp entitlement issue` writes one, `axp.entitlements.issue` is the library call.

### 14.3 Trust: issuers and key roles

An entitlement is trusted when **all** of the following hold:

1. `extension` is the id being installed and `holder` is this host's own
   key (§14.4).
2. `issuer` is one of the manifest's `commerce.issuers` (default: the
   publisher). The manifest is signed and pinned, so a publisher's choice of
   who may sell for them is as trustworthy as the manifest itself.
3. `signing.public_key` is listed in the **issuer's** key directory
   (`https://<issuer>/.well-known/agent-extension-keys.json`, §8.5) with the
   role `entitlement`, and — if the entry carries `extensions` — for this
   extension.
4. `signature` verifies against that key.
5. The dates allow it (§14.6).

**Key roles.** Key directory entries gain an optional `roles` list:

```jsonc
{ "public_key": "ed25519:MANIFEST…", "extensions": ["paid-tool"] },                           // no roles = manifest only
{ "public_key": "ed25519:ISSUING…",  "extensions": ["paid-tool"], "roles": ["entitlement"] }  // signs entitlements only
```

An entry **without** `roles` is a manifest-signing key and nothing else —
every existing directory keeps its exact meaning. An entitlement key MUST
be listed with `roles` containing `entitlement`, and a host MUST NOT accept
it for anything the `manifest` role governs (rotation, recovery, first-use
strict mode) unless that role is listed too. This separation is the point:
the issuing key lives on a server that signs at every purchase, the manifest
key stays offline. A stolen issuing key can mint entitlements until it is
revoked in the directory; it can never move a host's pin. Publishers SHOULD
keep the two roles on two keys. The reference
`axp.signing.parse_key_directory(…, role=…)` implements the filter and is
normative.

In a **marketplace's** directory the `extensions` scope may use full ids
(`"ext.example.com/paid-tool"`), since the extensions it issues for are not
its own; a bare name always means the directory publisher's own extension.

An unreachable issuer directory follows the §8.5 rule: a host MUST NOT
guess. For an install it reports the directory as unreachable and retries;
for the periodic re-check of an entitlement it already accepted it keeps the
last decision (hosts SHOULD cache the directory alongside the entitlement).

### 14.4 The host key and the presentation; gated delivery

A commerce-capable host holds one ed25519 **host key** per installation
(`axp keygen`), generated once, never shared. Its public form is the
`holder` an entitlement is bound to, and it is the host's identity towards
issuers and artifact servers. One agent, one key: an owner with two agents
asks the issuer for a second entitlement (or a transfer) — the protocol does
not copy entitlements between machines.

The host proves possession of that key with a **presentation**: a short-lived
document, bound to the exact URL it is sent to, signed by the host key, and
carrying the entitlement when it has one:

```jsonc
{
  "kind": "agent-extension-presentation",
  "spec_version": "0.5",
  "holder": "ed25519:…",                                   // the host key
  "extension": "ext.example.com/paid-tool",
  "audience": "https://ext.example.com/paid-tool-1.0.0.tar.gz",   // the exact URL being requested
  "issued_at": "…", "expires_at": "…",                      // ≤ 300 s apart
  "nonce": "…",
  "entitlement": { … },                                     // absent when asking for one (§14.5)
  "signature": "…"                                          // by the host key, JCS minus `signature`
}
```

It travels as an HTTP request header:

```
Authorization: AXP-Entitlement <base64url of the JCS presentation, no padding>
```

A server MUST check, in this order: the scheme; `audience` equals the URL it
serves, byte for byte; the time window (`expires_at` not past, `issued_at`
not in the future, lifetime ≤ 300 s, a few minutes of clock skew allowed);
the presentation signature against `holder`; then — only then — the embedded
entitlement (§14.3) with the issuer keys *that server* trusts, and that the
entitlement's `holder` and `extension` are the presentation's. A failed
presentation is `401`; a good presentation with a missing, invalid or
expired entitlement is `402`; a valid entitlement that does not cover the
requested release (§14.7) is `403`. The reference
`axp.entitlements.verify_presented_entitlement` is that check; `axp
entitlement inspect` runs it from the command line.

**Gated delivery.** A publisher who will not release code before payment
marks the target:

```jsonc
"delivery": { "method": "archive", "url": "https://…/paid-tool-1.0.0.tar.gz", "sha256": "…",
              "auth": { "scheme": "entitlement" } }
```

The **manifest stays public** — discovery, the consent card, the strictly-
higher update rule and the pinned signature all need it, and it contains
nothing but the description and the digests. Only the **bytes** are gated:
the host fetches the artifact with the header above (audience = the
`delivery.url`) and the server releases them only against a valid
entitlement. The sha256 in the signed manifest still binds the bytes, so a
gated artifact is verified exactly like a public one. A manifest with an
entitlement-gated target MUST carry a `commerce` block (a host could not
otherwise obtain what the server will demand); the reference validator
refuses one that does not. An unknown `auth.scheme` is ignored (§2.4): the
host fetches plainly and reports what the server answers. `release.artifact`
MAY point at the same gated URL; `axp verify --artifact` is unaffected since
it works on local bytes.

### 14.5 Obtaining an entitlement

A commerce-capable host MUST support **import** — the user hands it the
entitlement document (a file, a paste); this is the universal fallback and
the whole of the flow for a publisher who sells by e-mail — and SHOULD
support the two automated paths below.

**Checkout.** The host opens `commerce.checkout_url` for the user with these
query parameters appended: `axp_extension` (the id), `axp_holder` (the host
key, URL-encoded) and, when the host has a place the issuer can return the
user to, `axp_return`. The issuer binds the purchase to that holder. How the
purchase is paid for is between the user and the issuer.

**Refresh.** With `commerce.refresh_url` present, the host `POST`s a
presentation to it (audience = the `refresh_url`): without an entitlement to
ask for one after a purchase or to claim a trial, with its current
entitlement to renew it. The issuer verifies the presentation (§14.4), looks
up what that holder bought, and answers `200` with a fresh entitlement
document as the JSON body, `402` with a JSON body that MAY carry a
`checkout_url` when nothing is owed yet to that holder, `403` when the
presented entitlement was revoked (§14.6), or `404` for an unknown extension.
A host polls the refresh endpoint after checkout at a gentle cadence (and on
"I have paid"), and for a subscription starts renewal attempts a few days
before `valid_until`; once a minute for the first ten minutes after opening
checkout and daily thereafter is a reasonable shape.

A host that offers a web surface MAY accept the entitlement on `axp_return`
(`?entitlement=<base64url JSON>`); it MUST still verify it exactly as an
imported one. In every path the host verifies (§14.3) before it stores, and
stores verified entitlements in host-owned state keyed by extension id
(`axp.entitlements.EntitlementStore` is the reference).

### 14.6 Lifetime: validity, grace, disable, revocation

`valid_until` is the end of the right to use. From `issued_at` to
`valid_until` (inclusive; a few minutes of clock skew tolerated) the
entitlement is **valid**. For `grace_days` after it the entitlement is in
**grace**: still accepted, the host SHOULD be renewing (§14.5) and MAY tell
the user once. After that it is **expired**. A commerce-capable host then:

- for `entitlement: required`, treats the extension as it treats a user's
  *disable* (§6.5): persists the state, revokes views and routes, stops its
  managed services, runs the `disable` hook — and keeps the installed files
  and durable data. It MUST NOT uninstall. A renewed or imported entitlement
  re-enables it the same way (§6.5 enable).
- for `entitlement: optional`, removes the entitlement handoff (§14.8) and
  leaves the extension running; the extension itself decides what is locked.

The user is told once when an entitlement expires and then no more than
about monthly (the §7.4 cadence) — and *before* it expires when the host
knows renewal is failing.

**Revocation.** An issuer revokes by `serial`: its `refresh_url` answers
`403` for a presentation carrying that entitlement, and its artifact server
refuses it. A host that refreshes periodically therefore learns of a
revocation (chargeback, abuse) without a revocation list; one that does not
learns at the next gated download. Revoking the *issuing key* (`revoked:
true` in the directory) invalidates every entitlement it signed; the issuer
re-issues under a new key through `refresh_url`.

### 14.7 Updates and `updates_until`

A host applying an update to an extension with `commerce` checks, before it
downloads, that the candidate's `release.published_at` is not after the
entitlement's `updates_until` (`axp.entitlements.covers_release`). A release
that is not covered is **not applied**; the installed version keeps running
(a perpetual `valid_until`) and the host shows the update with the way to
extend the entitlement instead of an error. A release without
`published_at` cannot be placed and counts as covered — the gate a publisher
controls is the artifact server; a publisher selling update windows stamps
the date, which `axp release` does. A gated artifact server MUST apply the
same rule (`403`, §14.4). The consent ratchet (§7.6) and the strictly-higher
rule (§7.4) are unchanged.

### 14.8 What the extension sees

| variable | set on | meaning |
|----------|--------|---------|
| `AXP_ENTITLEMENT_FILE` | all hooks, while an entitlement is held | path to the current entitlement document (JSON, mode 0600, readable by the hooks and by the components the host launches). Unlike `AXP_CONFIG_FILE` it is **stable** for as long as the entitlement is held: the host rewrites it in place on renewal and removes it on expiry, so a running service can re-read it. Unset = no entitlement (free install of an `optional` extension, or a host without this capability). |

An extension that enforces anything itself verifies that file against the
issuer key it knows (the same five checks as §14.3, with the host's key as
`holder` taken from the document — it has no other), and MUST keep working
when the variable is unset on a host that does not implement this section,
within whatever its `optional`/`required` policy allows. After importing or
renewing an entitlement the host runs the extension's `enable` hook if it
declares one (idempotent by §6.5), so a service can pick the change up.

### 14.9 What this is, and is not

An entitlement is a **verifiable receipt**, not copy protection. A publisher
who ships a public artifact and relies on the host's check has exactly what
§10 says a hand-run `install.sh` gives: nothing, on a host that opts out or
predates this section — such a host ignores `commerce` and installs. The
protections a publisher actually controls are, in order of strength: gated
delivery (§14.4 — unentitled machines never receive the code), the
extension's own verification of `AXP_ENTITLEMENT_FILE` (§14.8), and
server-side components that check the presentation themselves. The host's
check exists for the **user**: a clear consent card with the price, no
surprise shutdowns, renewals that just happen, and one place to see what
they own — and for honest publishers, who get all of that for free.

What AXP defines here is small on purpose: one signed document, one header,
one key role, two dates. Prices, taxes, invoices, refunds, seats, teams and
every payment rail stay outside the protocol, where they belong.

## 15. Open questions (to resolve before v1.0)

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
   the default. A public catalogue exists at <https://axp.cat>: it lists only
   manifests that pass §2–§8 (validator, signature, publisher binding) and is
   a convenience for discovery, never a requirement for installation.
6. **Entitlement transfer** (§14.4) — moving an entitlement to a new host
   key (a re-installed agent) is left to the issuer's `refresh_url` today; a
   standard "transfer" request signed by both host keys would let a host do it
   without the issuer knowing the user. Also: should a host be allowed to hold
   several entitlements for one extension (seat + add-on)?
