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
  allowance exposes every local service.
- Record the tier you actually applied and every downgrade reason in the
  install record and on the consent card. Never report `enforced` unless
  runtime code is contained too.

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
