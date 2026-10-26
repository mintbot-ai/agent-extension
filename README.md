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

**Public home and catalog: [axp.cat](https://axp.cat).** An introduction to
the standard and the open catalog of packages that pass it - every listing
is a manifest the reference validator accepts, signed, and bound to its
publisher. Browse at [axp.cat/catalog](https://axp.cat/catalog); list your
own at [axp.cat/submit](https://axp.cat/submit) (`axpcat check <locator>`
runs the same gate locally). This repository holds the specification and
the reference implementation.

## What AXP gives you

1. **Portable description** — `identity` (publisher-namespaced) / `provides`
   (MCP servers, tools, services, memory, skills, prompts, channels, model
   providers, hooks, cron, config, optional panel views) / `requires` / `permissions`.
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
   `advisory` / `enforced`) the host really applies, host conformance
   profiles (Core / Trusted / Managed / Sandboxed), and a reference Linux
   sandbox recipe for lifecycle scripts (transient systemd units + a
   name-based egress proxy — see below).
7. **Forward compatibility** — unknown fields and component types are ignored
   by rule except for closed permission-key and lifecycle-hook vocabularies;
   vendor extensions are `x-` namespaced, runtime extras are `<runtime>:`
   namespaced outside those closed vocabularies. Declaring `enable`/`disable`
   requires a 0.5-capable host; older validators reject those hooks.
8. **Commerce without payments** — an extension may be sold (one-time,
   subscription, both, trial). AXP defines only the receipt: a signed
   *entitlement* bound to the host's key, verified against the publisher's
   key directory with a separate `entitlement` key role, presented in an
   `Authorization: AXP-Entitlement` header to fetch an artifact the publisher
   keeps behind payment. No prices computed, no checkout run, no money moved
   by the protocol; an issuer MAY let an agent pay its `402` by itself over a
   rail such as [x402](https://x402.org), never required —
   see [`docs/COMMERCE.md`](docs/COMMERCE.md).

## Layout

- [`SPEC.md`](SPEC.md) — the specification (draft v0.5).
- [`schema/agent-extension.schema.json`](schema/agent-extension.schema.json) —
  JSON Schema for manifests;
  [`schema/agent-extension-keys.schema.json`](schema/agent-extension-keys.schema.json)
  for the publisher key directory (§8.5);
  [`schema/agent-extension-entitlement.schema.json`](schema/agent-extension-entitlement.schema.json)
  for entitlements (§14).
- [`docs/HOST-GUIDE.md`](docs/HOST-GUIDE.md) — implementing a host, profile
  by profile, with the package calls that do the work.
- [`docs/SIGNING.md`](docs/SIGNING.md) — sign, pin, rotate, recover.
- [`docs/PUBLISHER-WORKFLOW.md`](docs/PUBLISHER-WORKFLOW.md) — runnable templates,
  offline readiness, safe local packing, project defaults and diagnostic codes.
- [`docs/COMMERCE.md`](docs/COMMERCE.md) — selling an extension: issuing
  entitlements, gating the artifact, checking inside the extension.
- [`docs/runtimes/`](docs/runtimes/) — runtime profiles (`posix`, `hermes`,
  `openclaw`, `claude-code`). Adding a runtime = adding a profile document.
- [`examples/sample-memory/`](examples/sample-memory/) — a complete worked
  example (`ext.example.com/sample-memory`, a fictional publisher) with
  `posix`, `hermes` and `claude-code` targets and standalone lifecycle
  scripts. It is the spec's fixture: the tests, the conformance suite and CI
  all load it, and it verifies out of the box with the deliberately public
  `example-signing.key` next to it. Real extensions live in their own
  repositories — e.g. [mintbot-ai/graph-memory](https://github.com/mintbot-ai/graph-memory)
  (`mintbot.ai/graph-memory`), released with `axp release`.
- [`examples/panel-view/`](examples/panel-view/) — unsigned draft 0.5 declaration
  example with an authenticated loopback service and pin/fullscreen view.
- [`examples/paid-tool/`](examples/paid-tool/) — a sold extension (§14):
  signed manifest with a `commerce` block and an entitlement-gated target,
  a key directory separating the manifest key from the issuing key, and an
  entitlement issued to the example host key; all keys deliberately public.
- [`CHANGELOG.md`](CHANGELOG.md).

## Reference implementation: the `axp` package

This repo ships a runtime-neutral Python reference implementation —
validation, JCS canonicalization, ed25519 signing with TOFU pinning, target
selection — plus the `axp` CLI. Signing uses the optional `cryptography`
package when importable and falls back to the `openssl` CLI. Python 3.10 also
installs `tomli` for project configuration; newer Python uses its standard library.

```bash
pip install -e .            # or: pip install -e .[dev] for tests

# publisher side — legacy manifest-only scaffold (supply your own package files)
axp init --publisher ext.example.com --name my-ext --description "…"
axp keygen --out signing.key            # prints the ed25519:… public form
axp release agent-extension.json --bump patch \
    --artifact dist/my-ext.tar.gz --key signing.key
# (release = set version, follow version-in-URL, fill real sha256s,
#  stamp published_at/valid_until, sign, validate — in one step;
#  add --prev-key old.key for a key-rotation release)
axp verify agent-extension.json --artifact dist/my-ext.tar.gz   # the file you are about to upload?
axp resolve https://github.com/you/my-ext   # after publishing: the document a host installs, signature + key directory checked
axp resolve https://github.com/you/my-ext --installed 1.2.0 --tracked stable   # what a host on 1.2.0 would update to
axp keydir --publisher ext.example.com --key ed25519:…@my-ext \
    -o agent-extension-keys.json        # serve at /.well-known/agent-extension-keys.json

# host side
axp validate agent-extension.json
axp verify agent-extension.json --pinned ed25519:…          # against the pinned key
axp verify agent-extension.json --keydir agent-extension-keys.json   # listed by the publisher?
axp target agent-extension.json --runtime hermes --runtime posix --runtime-version hermes=0.20.0

# selling (SPEC 14) — issuer, host and artifact-server side
axp keydir --publisher ext.example.com --key ed25519:…@my-ext --entitlement-key ed25519:…@my-ext -o agent-extension-keys.json
axp entitlement issue --key issuing.key --issuer ext.example.com --extension ext.example.com/my-ext \
    --holder ed25519:HOST… --plan pro --valid-days 31 -o entitlement.json
axp entitlement verify entitlement.json --manifest agent-extension.json --holder ed25519:HOST…
axp entitlement present entitlement.json --host-key host.key --audience https://…/my-ext-1.2.0.tar.gz
axp entitlement inspect "AXP-Entitlement …" --audience https://…/my-ext-1.2.0.tar.gz --keydir agent-extension-keys.json
```

Host authors: read [docs/HOST-GUIDE.md](docs/HOST-GUIDE.md) and reuse
`PinStore.decide()/commit()` (the §8 trust decision), `validate` /
`select_target`, `axp.repository.resolve` (the §3.1 repository walk behind
your own HTTP client), and the `axp.updates` / `axp.versions` rules instead of
reimplementing them — the conformance suite then covers your host too.

### Runnable projects and local readiness

```sh
axp init --template skill --publisher extensions.your-domain.com \
  --name hello --description "A greeting skill" --dir hello
cd hello
axp check                         # draft: expected exit 1 before packing/signing
axp pack                          # explicit allowlist from generated axp.toml
axp keygen --out ../hello-signing.key
axp release agent-extension.json --key ../hello-signing.key
axp check --format json           # local static readiness, not remote certification
```

Templates: `skill`, `cli`, `mcp`, `service`. Omitting `--template` preserves
legacy init. `axp.toml` can supply artifact and signing-key **path** defaults;
CLI flags override them. No build commands are executed and nothing is uploaded.
`validate` means structurally valid; `check` distinguishes a draft from a locally
publish-ready package and provides actionable diagnostic codes. Full limits,
security guards, config precedence and manual upload steps are in the
[publisher workflow](docs/PUBLISHER-WORKFLOW.md).

## Conformance

`conformance/` is an executable check of the SPEC §11 host profiles (Core +
Trusted). Run it against the reference implementation with `pytest
conformance/`, or against your own host by implementing the three-method
adapter — see [conformance/README.md](conformance/README.md).

## Sandboxing lifecycle scripts

Declared permissions are only worth something if a host can enforce them.
The Sandboxed profile ([docs/HOST-GUIDE.md](docs/HOST-GUIDE.md#sandboxed--enforcing-what-was-declared),
[docs/runtimes/posix.md](docs/runtimes/posix.md)) is a concrete Linux recipe,
running in production on the mintbot host:

- every supported lifecycle hook (including optional `enable` / `disable`) runs as a
  **transient systemd unit** (`systemd-run --wait --pipe --collect`) with
  `ProtectSystem=strict`, `PrivateTmp` and `ReadWritePaths` limited to the
  install prefix, the staging dir, `AXP_STATE_DIR`, `AXP_CACHE_DIR` and the
  declared `filesystem: …:rw` scopes;
- **egress is filtered by name, not by address**: `IPAddressDeny=any` plus
  one loopback address where a small host-run allow-list proxy listens; the
  unit reaches the network only through `HTTPS_PROXY`, and the proxy admits
  `CONNECT host:port` solely for the declared `network_egress` entries
  (wildcards included) and the publisher's own hosts. DNS, raw sockets and
  services bound to `127.0.0.1` are unreachable from the hook. A port-less
  `*` (egress to any host) is the one declaration no proxy can narrow: the
  network half is then off for that extension and recorded as such;
- the tier actually applied (`advisory`, or `declared` when systemd is
  missing or `root: true` turns the filesystem half off) and every downgrade
  reason are recorded in the install record and shown on the consent card.

The same derived surface is applied to what the extension **runs**, not only
to its scripts: `services` become host-owned hardened systemd units (or a
drop-in on the unit the install script created), stdio `mcp_servers` are
registered as `systemd-run --pipe` wrappers so every server process the
runtime spawns is contained, and each extension gets its own egress proxy
address. Those components are reported `enforced`; one that refuses to start
under full containment keeps the half it can live with (`advisory`) and runs
bare (`declared`) only when neither works — every step recorded.
What no host can reach is code loaded *into* the agent process (a Hermes
plugin's tools, hooks, channels) — that stays `advisory`, and the consent
card says which is which. The sandbox lives in the host (systemd is a host
concern), not in the runtime-neutral `axp` package; the guide has everything
needed to reproduce it.

## Status

**Draft v0.5** — v0.3 made the core runtime-neutral, v0.4 hardened trust
and updates, and v0.5 adds optional isolated panel views, managed-service
enable/disable hooks and commerce (signed entitlements, key roles, gated
artifacts). Field
names may still change before v1.0; open questions are at the end of
`SPEC.md`. CI runs the suite on Python 3.10 and 3.13, with and without the
`cryptography` wheel.

## Contributing

Issues and pull requests welcome — especially new runtime profiles. Core
changes go through `SPEC.md` + schema + example together, with a CHANGELOG
entry.

## License

MIT — see [LICENSE](LICENSE).
