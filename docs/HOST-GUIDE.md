# Implementing an AXP host

This is the practical companion to SPEC §11 (conformance profiles): what a
host — an agent runtime, a hosting product, a CLI — has to do to install AXP
extensions, in the order the profiles stack. Every step names the piece of
the reference `axp` package that already does the work; reuse it (vendor the
module or `pip install axp`) rather than re-deriving the rules from prose.
The conformance suite (`conformance/`) is the acceptance test for each step.

```
Core ──► Trusted ──► Managed ──► Sandboxed
 install   verify +    updates +   lifecycle scripts
 + consent pin         health      behind a sandbox
```

## Core — install with consent

1. **Discover** the manifest (SPEC §3.1): `agent-extension.json` at the URL,
   the `<link rel="agent-extension">`, `/.well-known/agent-extension.json`,
   or a repository root. HTTPS only; apply your SSRF rules to every fetch.
   For a repository locator take the newest release's
   `agent-extension.json` asset — `releases/latest`, then the release
   listing so a pre-release on a less stable channel is found (the same
   document the `github` update source reads, so install and update pin the
   same key and version) — and only then the root file; only an absent
   document moves the walk on, never a fetch error. `axp.repository.resolve`
   is that walk with your `fetch` (and, if you normalise manifests, your
   `parse`) plugged in; `NoManifest` is the one failure you may answer with
   another path such as an unmanaged install, `Unsigned` the refusal. A repository is never the
   publisher's own origin, so require a signature there and show the
   foreign origin on the consent card (SPEC §9).
2. **Validate** and pick the target:

   ```python
   from axp import validate, select_target, ManifestError

   summary = validate(manifest, origin="ext.example.com")   # origin only derives a v0.2 publisher
   target, runtime = select_target(
       manifest,
       runtimes=("myruntime", "posix"),          # your ids, posix last for the §5.1 fallback
       runtime_versions={"myruntime": "2.3.0"},  # lets runtime_version constraints apply
   )
   ```

   `validate` implements the §2.4 forward-compatibility rule for you: unknown
   fields and component types pass, unknown security-relevant enum values
   raise `ManifestError` with the field named.
3. **Show consent** before anything runs (§4.4): egress hosts, listeners,
   filesystem scopes, secrets, `root`, the publisher's reasons, the signature
   state, the starting update policy, and — honestly — which enforcement tier
   *you* will apply. Nothing is downloaded or executed until the user agrees.
4. **Fetch the artifact**, verify its sha256 against the manifest, unpack it
   to a staging directory, and run `lifecycle.install` with the §6.2
   environment. Minimum set worth getting right: `AXP_HOOK`, `AXP_EXT_ID`,
   `AXP_EXT_VERSION`, `AXP_PREFIX`, `AXP_STATE_DIR`, `AXP_CACHE_DIR`,
   `AXP_ARTIFACT_DIR` (the staging dir during install), `AXP_NONINTERACTIVE=1`,
   `AXP_SPEC_VERSION` (**your** spec version), `AXP_HOST=<id>/<version>`.
5. **Retain the artifact** after success (§6.1) and write an install record:
   id, version, digest, channel tracked, the permissions consented to, and
   the enforcement tier actually applied. `uninstall` / `health` later run
   from the retained copy.
6. **Uninstall** runs `lifecycle.uninstall` from the retained artifact with
   `AXP_PURGE=0` unless the user asked to delete data. Tear your own units
   and registrations down first; a hook that exits non-zero with its prefix
   empty has done its job (§6.4 — the strict tree denied it the final
   `rmdir`), so remove the prefix and finish. Any other hook failure after
   your teardown must not leave a record that claims the extension still
   runs — mark it, and let a reinstall of the same artifact run the hooks
   again instead of answering "already installed".

Conformance: `pytest conformance/test_core.py` with your adapter.

## Report installation and readiness separately

An install hook exiting successfully proves installation completed, not that the
capability is usable. As a host UX convention (not new manifest fields or a new
conformance requirement), return installation success separately from a readiness
assessment after installation and on an already-installed request:

- Check required configuration using host-verifiable bindings. Report confirmed
  missing names, never values. A declaration alone does not prove absence:
  bindings the host cannot inspect remain `unknown`, not `needs_configuration`.
- Check runtime registration against the intended component, not merely an
  occupied registry key. Authenticated endpoints also need a usable credential
  binding in the runtime; a token file alone is insufficient.
- Reuse bounded service probes and the retained, consented health hook under the
  existing containment rules. Missing or failed checks never count as success.
- Keep assessment observational: do not reinstall, restart services, rewrite
  registration or repair credentials as a side effect. A health hook is still
  publisher code and must retain its existing timeout and sandbox.
- Present a concise status and next action. For example: `ready`,
  `needs_configuration`, `unhealthy`, `disabled`, or `unknown`. Keep detailed
  categorical checks available without copying raw publisher output, exception
  text or denied request URLs, which can contain secrets.

Host readiness is distinct from the CLI's offline `axp check`: the latter tests
local release inputs, not a running installation. Neither is a general security
certification. Preserve existing response fields when adding these host results.

## Optional panel views (AXP 0.5)

Upgrade whole-manifest validation and activation handling to 0.5 before
accepting manifests with `lifecycle.enable` / `lifecycle.disable`. Pre-0.5
reference validators and schemas reject these keys in any target; they do
not ignore them. The lifecycle object remains closed (§2.4). Vendoring only
`axp/panel_views.py` is insufficient. Without the new hooks, older hosts can
ignore the panel component and install the rest, but MUST NOT expose views.

Panel support is a host feature, not a new runtime or an iframe URL supplied
by an extension. Validate the whole manifest before installation; hosts which
need to re-check persisted declarations can also call:

```python
from axp import PanelViewError, validate_panel_views
views = validate_panel_views(manifest["provides"])  # list[dict]; raises PanelViewError
```

The standalone `axp/panel_views.py` module is stdlib-only and can be byte-vendored
without other package modules. Its helper returns detached copies of declared
views (or `[]` when absent), preserves unknown fields/capability strings, and
raises its own `PanelViewError(ValueError)`. Whole-manifest `validate` translates
that into `ManifestError`. The helper performs no network calls, routing, token
reads or capability filtering. Preserve unknown fields for signing; interpret only `pin` and
`fullscreen` in the UI. Resolve `service` to its single declared service, not
to an arbitrary request parameter. Only referenced services need the strict
HTTP literal-loopback origin; other AXP service protocols remain unchanged.
Display the panel/service exposure on the consent surface. Do not expose views
on a host that cannot implement the isolation and revocation requirements.

### Isolated capability proxy

1. Issue an unpredictable, short-lived capability only from the normal
   authenticated and CSRF-protected host UI. Store its principal, extension
   install generation, view and expiry server-side. A prefix such as
   `/views/<opaque-capability>/` is illustrative, not prescribed by AXP.
2. Embed only that restricted prefix in a sandboxed iframe with
   `sandbox="allow-scripts"` (no `allow-same-origin`). Owner/member credentials
   must never occur in its `src`: sandboxed scripts can read their own URL.
   Use the same isolated frame in pin and fullscreen modes. Grant no host API
   authority through `postMessage`; validate messages against frame identity.
3. Check expiry, principal authorization, install generation and enabled state
   on every HTTP request and WebSocket upgrade. Maintain live socket ownership
   so revocation/expiry/access loss closes already-open sockets. A restart
   should invalidate ephemeral capabilities, never silently extend them.
4. Ignore host cookies and Authorization at the capability endpoint. Strip
   them, capability prefixes, host credential query parameters and identifying
   headers before upstream forwarding. Build an allowlist of forwarded
   headers; do not blindly copy client, proxy or WebSocket handshake headers.
   Upstream Authorization, if needed, comes only from the extension's
   `state:` bearer file. Resolve it beneath that extension's state root without
   following escaping symlinks; a missing, empty or unsafe file fails closed.
   Strip upstream Set-Cookie and other host-session-affecting headers. Never
   leak upstream bearer tokens or general host tokens to application HTML.
5. Support the sandbox's `Origin: null` and required CORS preflights ONLY at
   the valid scoped capability route. Do not enable wildcard credentialed CORS
   on the host API. WebSocket handshakes require the same capability checks;
   `Origin: null` by itself is never authorization.
6. Fix the upstream origin from the validated service and confine application
   requests to the view subtree (SPEC §4.2.1): a trailing-slash entry is its
   own subtree; otherwise take its parent through the last `/`. In particular,
   `/desktop` derives `/`, while `/desktop/` and `/desktop/index.html` derive
   `/desktop/`. Do not guess directory status or change the entry path.
   Reject malformed/encoded
   traversal and absolute URLs before joining paths; do not follow upstream
   redirects to a new origin or outside that subtree. Applications must use
   relative asset/WebSocket URLs or explicitly support prefix mounting.
7. Use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; redact
   capability URLs in access/error logs and telemetry. The browser application
   necessarily sees its own restricted capability, so keep its authority and
   lifetime minimal. The upstream service must not receive it.

The proxy is deliberately a host responsibility; `axp` is a runtime-neutral
validator and signing library, not an HTTP server. Never embed the raw
loopback endpoint in the UI or open its listening port to the network.

### Activation and secure disable

Support the optional `enable`/`disable` hooks using the same retained artifact,
`AXP_HOOK`, environment, timeout and containment as install hooks. Hooks need
not call systemd; use whatever managed-service implementation the host has.
A `component_map.services.command` remains host-owned: hooks do not start a
second copy. Preserve disabled state across restarts and upgrades.

Disable/uninstall ordering: persist disabled/revoked state → revoke capabilities
and close sockets → stop managed services → invoke the optional disable or
uninstall hook. A hook error never reopens access. Enable ordering: optional
enable hook → start managed services → readiness check → allow new capability
issuance. Failure stays closed. Do not reuse tickets across enable/update/
reinstall; old sessions must not attach to a different installation.

### Host integration acceptance checklist

`pytest conformance/test_panel_views.py` checks 0.5 declarations, not a live
proxy. The host's own HTTP/browser tests MUST additionally verify:

- unauthenticated and cross-principal issuance fails; invalid, expired,
  revoked and wrong-view capabilities fail on HTTP AND WebSockets;
- HTTP assets and a real WebSocket round trip work under the mounted prefix;
- owner/member cookies, Authorization and credential query values never reach
  the upstream; only the declared service bearer token does;
- frame scripts cannot read the parent DOM/cookies or call privileged host APIs;
  iframe URLs contain no owner/member credentials;
- `Origin: null` succeeds only with the scoped capability; arbitrary null-origin
  requests are rejected; cache/referrer headers and log redaction are enforced;
- redirects/path tricks cannot change the origin or escape the subtree;
- disable/uninstall/expiry/access loss close existing sockets immediately;
  hook failure stays revoked; re-enable never resurrects old capabilities;
- hosts without support expose neither a panel nor a direct service link.

## Trusted — signatures, pinning, rotation

The trust decision is a pure function over (manifest, pin state, key
directory); persist its result only after the install succeeded, so a failed
download or hook never leaves a pin behind.

```python
from axp import PinStore, parse_key_directory, key_directory_url

store = PinStore(state_dir / "pins.json")
ext_id = summary["ext_id"]

directory_keys = None
if store.pinned_key(ext_id) not in (None, manifest["signing"]["public_key"]):
    # Key differs from the pin: the publisher key directory (§8.5) is required.
    document = fetch_json(key_directory_url(summary["publisher"]))   # your fetch; 404 -> None
    if document is None:
        directory_keys = None            # publisher has none: classic §8.3 rules
    elif document is UNREACHABLE:
        defer()                          # never guess: keep the old pin, retry later
    else:
        directory_keys = parse_key_directory(document, publisher=summary["publisher"], name=summary["name"])

decision = store.decide(ext_id, manifest, directory_keys=directory_keys,
                        allow_recovery=user_explicitly_re_trusted)
if not decision.accepted:
    refuse(decision.reason)              # action tells you why: refuse | recover
... download, verify digest, run install ...
store.commit(ext_id, decision)
```

What the decision enforces for you: first-use pinning, "updates only from the
same key", announce → dual-signed rotation (only to a directory-listed key
when the directory was consulted), the signed→unsigned ratchet, and the
`recover` outcome that a host may only accept with the user's explicit
re-trust. `verify_manifest` alone is enough for a consent-card preview — it
never writes.

Conformance: `pytest conformance/test_trusted.py` (implement the optional
`evaluate_trust_with_directory` adapter method to run the §8.5 case).

## Managed — updates, health, policy

```python
from axp import is_newer, channel_accepts, is_expired, parse_policy, permissions_widened

candidate = resolve_source(record["updates"]["source"])      # github / forge / feed / direct
if not channel_accepts(record["tracked_channel"], candidate["release"]["channel"]):
    skip()
if not is_newer(candidate_version, record["version"]) or is_expired(candidate):
    skip()
if permissions_widened(record["permissions"], candidate["permissions"]):
    ask_for_consent_again()                                  # §7.6: never auto-apply a wider surface
```

Rules that are easy to get wrong, all encoded in `axp.updates` /
`axp.versions`:

- **Tracked channel is host state** (§7.2). Record it at install; installing
  a `stable` release does not stop a `beta` tracker from tracking beta.
- **Strictly higher only** (§7.4); pre-releases sort below their release;
  calver and semver share one ordering (`axp.versions.compare`).
- **Freshness** (§7.4): warn once when the installed manifest expires, then
  at most monthly; refuse an already-expired *candidate*.
- **Policy strings** (§7.5): `auto | notify | pin=X.Y.Z | off` — the stored
  user choice always wins over the manifest's `updates.policy`.
- **Dependencies** (§4.3): refuse an install/update whose
  `requires.extensions` are unmet, and refuse to update or remove an
  extension that something installed still constrains — name the edge.
- **Apply** = trust decision → download → sha256 → the NEW artifact's
  `upgrade` hook with `AXP_FROM_VERSION` (fallback: its idempotent `install`)
  → replace the retained artifact, commit the pin, rewrite the record.
  Any failure before the last step leaves the previous version fully intact.
  Apply the very manifest you checked — one fetch per pass, and no window in
  which the source can change between the decision and the apply.
- **A re-install is an upgrade.** When the user installs another version of
  an extension that is already installed, run the new artifact's `upgrade`
  hook with `AXP_FROM_VERSION` (downgrades included — that is the explicit
  interactive action §7.4 reserves for the user) and keep their stored
  update policy; show that effective policy on the consent card.
- **Errors are not nags.** Report a failing update source once, then at most
  monthly or when the message changes (the §7.4 cadence); a read-only
  "check now" reports everything and records nothing.
- **Uninstall keeps data** unless the user asks to purge: `AXP_PURGE=1` for
  the hook, then remove the state / cache / retained-artifact tree.
- **Health** (§6.4): run `lifecycle.health` from the retained artifact after
  every apply and on your schedule; exit 0/1/2 = ok/unhealthy/unknown, first
  stdout line is the status text.

## Sandboxed — enforcing what was declared

The `advisory` tier means: lifecycle scripts are constrained to the declared
surface, runtime code is not. A workable Linux recipe (the mintbot host does
exactly this; see `docs/runtimes/posix.md`):

- Run each hook as a transient systemd unit (`systemd-run --wait --pipe
  --collect`), `ProtectSystem=strict` + `PrivateTmp`, with `ReadWritePaths`
  for the install prefix, the staging dir, `AXP_STATE_DIR`, `AXP_CACHE_DIR`
  and the declared `:rw` scopes. `root: true` turns the filesystem half off
  (say so on the consent card).
- Filter egress **by name**, not address: `IPAddressDeny=any` +
  `IPAddressAllow=<one loopback address>` where a small allow-list proxy of
  yours listens, and point the unit at it via `HTTPS_PROXY`/`HTTP_PROXY`.
  The proxy admits `CONNECT host:port` only for declared `network_egress`
  entries (wildcards included) plus the publisher's own hosts, resolves names
  itself, and refuses names that resolve to internal ranges. Address-based
  allow-lists break on CDNs and cannot express wildcards; a whole-loopback
  allowance exposes every local service. `IPAddressAllow` cannot restrict
  ports either: services bound to a wildcard address (`0.0.0.0` / `::`) stay
  reachable through the proxy's address, so bind local control services to
  `127.0.0.1` explicitly.
- A port-less `*` in `network_egress` (any host, §4.4) leaves nothing to
  filter by name. Do not run a proxy that admits everything and call it
  containment: leave the network half off for that extension, keep the
  filesystem half, and record `network: false` with a note, so the consent
  card and the install record say what is true. `*:443` still goes through
  the proxy (any host, that port only), and the proxy keeps refusing names
  that resolve to internal ranges.
- Record the tier you actually applied and every downgrade reason in the
  install record and on the consent card. Never report `enforced` unless
  runtime code is contained too.

**Runtime containment** — the same derived surface applied to what the
extension *runs*, not only to its scripts. The mintbot host does this for the
components it launches itself:

- `services` bound with `command` become a **host-owned** unit
  (`mintbot-ext-<publisher>-<name>-svc-<service>.service`, `ExecStart` = argv
  under the prefix, `Restart` from the map, `AXP_*` + `HOME=$AXP_STATE_DIR`
  in the environment). `services` bound with `unit: systemd:<x>` get a
  drop-in (`<x>.service.d/50-axp-sandbox.conf`) with the same properties on
  the unit the install script created. Properties: `ProtectSystem=strict`,
  `ProtectHome=read-only` (strict alone leaves `/root` writable),
  `PrivateTmp`, `NoNewPrivileges`, `ReadWritePaths=-<prefix|state|cache|scopes>`
  (the leading `-` so a scope that does not exist yet cannot fail the unit),
  `IPAddressDeny=any` + `IPAddressAllow` for the proxy address, declared IP
  literals and the extension's own loopback listeners (`network_ingress`),
  `PrivateDevices`, `ProtectKernel*`, `RestrictAddressFamilies`, an empty
  capability set (`CAP_NET_BIND_SERVICE` only for a listener below 1024).
- stdio `mcp_servers` are registered in the runtime's MCP config as a
  `systemd-run --wait --pipe --collect --property=… -- <argv>` wrapper, so
  every server process the runtime spawns is contained; `http`/`sse` servers
  are URL entries and get no tier (the host runs no process). When such an
  entry (or a `services` entry with an `endpoint`) declares `auth` (SPEC
  4.2, "Endpoint access"), the host reads the token file below the
  extension's state scope itself — as root, after `install` has run, never
  through a hook — fills the `Authorization` header into the runtime's MCP
  entry, and can show the owner a "connect a client" card (endpoint, token,
  ready-made client entry) on an authenticated surface only. The token is a
  secret: keep it out of the install record, update reports and logs; a
  missing file is reported as "token not created yet", never invented.
  `auth` does not widen reachability — a loopback listener stays loopback.
- Each extension with named egress gets its **own** proxy unit
  (`DynamicUser`, deterministic `127.7.7.<n>` per extension id) so that
  `IPAddressAllow` of one extension never opens another's proxy.
- A component that refuses to start under full containment goes down a
  **ladder**, not off a cliff: the host retries with the filesystem half
  alone, then the network half alone, and only then bare — keeping whatever
  the daemon can live with (`advisory`) before giving up (`declared`). Each
  rung is booked in the record ("network containment released, filesystem
  containment kept") and the extension's tier is the weakest of its
  components — never silently. Uninstall tears units, drop-ins, the proxy
  and the MCP entries down; an upgrade tears down what the new version no
  longer provides.
- What this cannot reach: code loaded into the agent process (`tools`,
  `hooks`, `channels`, …). Those stay `advisory`, and the consent card says
  so.

## Commerce — entitlements and gated artifacts (optional, SPEC §14)

Resolve grace as an explicit local override, else the validated manifest's
`commerce.grace_days`, else 7. Preserve zero; reject negative policy values.
`validate()` keeps its existing commerce-summary shape, so read grace from
the validated input manifest as below. The CLI verify/inspect commands do
this automatically with `--manifest`; `--grace-days` overrides it.

Key-directory roles protect only role-aware readers. Upgrade every reader
that uses a directory for manifest trust before adding entitlement-only
online keys there; an older reader may silently treat them as manifest keys.

A host that installs sold extensions adds one key, one store and four checks
on top of Trusted. Nothing here touches money: the issuer collected it and
signed an *entitlement*; the host verifies and presents it.

```python
from axp import (EntitlementStore, holder_from_private, verify_entitlement, covers_release,
                 make_presentation, authorization_header, parse_key_directory)
from axp.signing import ROLE_ENTITLEMENT

host_key = state_dir / "host.key"              # axp keygen once per installation; never leaves the machine
holder = holder_from_private(host_key.read_bytes())
store = EntitlementStore(state_dir / "entitlements.json")

commerce = summary["commerce"]                 # from validate(); None = not sold
if commerce and commerce["entitlement"] == "required":
    entitlement = store.get(ext_id)
    if entitlement is None:
        offer_checkout(commerce)               # §14.5: checkout_url + axp_extension/axp_holder, refresh_url, import
        return
    issuer = entitlement["issuer"]
    document = fetch_json(key_directory_url(issuer))          # the ISSUER's directory, cached next to the entitlement
    issuer_keys = parse_key_directory(document, publisher=issuer, name=ext_id, role=ROLE_ENTITLEMENT)
    verdict = verify_entitlement(entitlement, extension=ext_id, holder=holder,
                                 issuer_keys=issuer_keys, issuers=commerce["issuers"],
                                 grace_days=manifest["commerce"].get("grace_days", 7))
    if not verdict.valid:
        refuse_or_renew(verdict.status, verdict.reason)       # expired -> refresh_url first, then disable (§14.6)
    if not covers_release(entitlement, candidate_manifest):
        show_update_needs_renewal()                           # §14.7: never apply, never nag

headers = {}
if target["delivery"].get("auth", {}).get("scheme") == "entitlement":
    presentation = make_presentation(host_private_key_pem=host_key.read_bytes(),
                                     audience=target["delivery"]["url"], entitlement=entitlement)
    headers["Authorization"] = authorization_header(presentation)   # §14.4; 401/402/403 are the server's answers
artifact = fetch(target["delivery"]["url"], headers=headers)          # then sha256 as always
```

The rules the library encodes for you:

- **Role separation.** `parse_key_directory(..., role=ROLE_ENTITLEMENT)` is
  the only way to obtain issuer keys; the default (manifest) role never
  returns an entitlement-only key and vice versa. A stolen online issuing
  key cannot move a pin — your trust code is unchanged and already safe.
- **Issuers come from the manifest.** Refuse an entitlement whose `issuer`
  is not in `commerce.issuers` *before* fetching anything; never let a
  stranger's directory vouch.
- **Presentations are per request.** Make a fresh one for every fetch; the
  audience is the exact URL and the lifetime is five minutes. Do not cache or
  log the header.
- **Hand it over.** Write the verified entitlement to a stable 0600 file and
  pass its path as `AXP_ENTITLEMENT_FILE` on every hook (§14.8); rewrite on
  renewal, remove on expiry, run `enable` after a renewal.
- **Expiry is a disable, not an uninstall** (§14.6) — the same path your
  disable switch takes, after `grace_days`. Tell the user once, then monthly.
- **Import always works.** A file or paste goes through `verify_entitlement`
  exactly like a refreshed one, then `store.put(ext_id, entitlement)`.
- **Rails are optional.** When `commerce["payment"]` lists `x402` and your
  host has an x402 client (a funded wallet, or a platform that pays on the
  agent's behalf), you MAY settle the refresh endpoint's `402` and repeat the
  POST with the payment header beside the presentation; the `200` is an
  ordinary entitlement. Without a client, treat that `402` exactly like any
  other: offer `checkout_url` and import. Never fail an install because a
  rail is unknown.

Conformance: `pytest conformance/test_commerce.py` (implement the optional
`verify_entitlement` adapter method). `docs/COMMERCE.md` covers the issuer
and artifact-server side.

## Unmanaged installs — the on-ramp for everything else

Most software will never carry a manifest. A host that refuses it outright
sends users straight back to `curl | bash`: no record, no removal, no update
check, no warning at all. A host MAY therefore install a repository that has
**no** `agent-extension.json` as an *unmanaged install* — but only as a
visibly separate class of thing, never as a cheaper way in:

- **Route only the no-manifest case here.** A manifest that exists but fails
  the trust rules (unsigned from a repository, broken signature, wrong
  origin) stays refused. The unmanaged path must never be reachable by simply
  not signing.
- **Lead the consent card with what is missing**, not with what the
  repository claims: no publisher identity or signature, no declared
  permissions (the code runs with the agent's full privileges), unsigned
  updates, no lifecycle hooks. Name what you detected (a plugin, skills, an
  `install.sh` that will run without a sandbox) and the exact commit you pin.
- **Pin a commit; never apply unattended.** `notify` and `off` are the only
  policies — there is nothing that could justify applying what the branch
  serves next without the user. "Update now" is the user's explicit act.
- **Keep the record apart.** `kind: "unmanaged"`, its own badge in every
  list, no entry in the pin store, no dependency edges to or from real
  extensions, and a name collision with an extension is refused in both
  directions (promotion is explicit: remove the unmanaged copy, then install
  the extension with its own consent and trust decision).
- **Report `promotable`** once a month while the repository publishes a
  manifest at its current commit — that is the whole point: the warning is
  the publisher's incentive to adopt the protocol, and the user's one-click
  path to real guarantees.
- **Hand scripts the §6.2 environment anyway** (`AXP_HOOK`, `AXP_EXT_ID`,
  `AXP_STATE_DIR`, …) plus `AXP_UNMANAGED=1`, so an `install.sh` written
  without the contract can adopt it one variable at a time.

The mintbot host implements this in `unmanaged_install.py`: `git ls-remote`
resolves the ref to a commit, the archive of exactly that commit goes
through the same size-capped, SSRF-pinned fetch and hardened extraction as
any artifact, and the tree is classified as a Hermes plugin (`plugin.yaml`),
skills (`SKILL.md` at the root or one level down) or a script (`install.sh`).

## Checklist before claiming a profile

- [ ] `pytest conformance/` passes with `AXP_CONFORMANCE_ADAPTER=<your module>`.
- [ ] A hand-run `install.sh` from the artifact still works (§10) — you did
      not make scripts depend on your host.
- [ ] `AXP_SPEC_VERSION` is *your* version; `AXP_ARTIFACT_DIR` is the running
      hook's own directory.
- [ ] Consent shows every declared dimension, including `network_ingress`
      and `secrets`.
- [ ] A failed download or hook leaves no pin and no half-written record.
- [ ] An unreachable key directory defers instead of accepting or refusing.
