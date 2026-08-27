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
   For a repository locator prefer the latest release's
   `agent-extension.json` asset (the same document the `github` update
   source reads, so install and update pin the same key and version) and
   fall back to the root file; a repository is never the publisher's own
   origin, so require a signature there and show the foreign origin on the
   consent card (SPEC §9).
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
   `AXP_PURGE=0` unless the user asked to delete data.

Conformance: `pytest conformance/test_core.py` with your adapter.

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
  are URL entries and get no tier (the host runs no process).
- Each extension with named egress gets its **own** proxy unit
  (`DynamicUser`, deterministic `127.7.7.<n>` per extension id) so that
  `IPAddressAllow` of one extension never opens another's proxy.
- A component that refuses to start under containment is restarted bare,
  reported `declared` with the reason, and the extension's tier drops with
  it — never silently. Uninstall tears units, drop-ins, the proxy and the
  MCP entries down; an upgrade tears down what the new version no longer
  provides.
- What this cannot reach: code loaded into the agent process (`tools`,
  `hooks`, `channels`, …). Those stay `advisory`, and the consent card says
  so.

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
