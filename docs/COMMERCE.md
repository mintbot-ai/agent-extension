# Selling an AXP extension (v0.5, SPEC §14)

Practical companion to §14 of [`../SPEC.md`](../SPEC.md): what a publisher
sets up to sell an extension — one-time, subscription, a combination, or a
trial — and what the two small servers involved (the *issuer* and, optionally,
a *gated artifact server*) have to do. The host side is in
[`HOST-GUIDE.md`](HOST-GUIDE.md#commerce--entitlements-and-gated-artifacts-optional-spec-14).

AXP never touches payment. You sell however you like — Stripe, an invoice, a
marketplace, a handshake. What AXP standardises is the **receipt**: a signed
*entitlement* a host can verify offline against your key directory, and a
**header** the host uses to prove it holds one. That is all a host, an
artifact server or the extension itself ever looks at.

## 1. The shape of the thing

```
 publisher ──signs──▶ manifest (public, as always)      ◀── host reads, pins, consents
 issuer    ──signs──▶ entitlement {extension, holder, dates}   ◀── host verifies, stores, hands to hooks
 host      ──signs──▶ presentation {audience, entitlement}     ──▶ artifact server / issuer verify
```

Grace policy for `axp entitlement verify` and `axp entitlement inspect` is
explicit `--grace-days` first, otherwise `commerce.grace_days` from `--manifest`,
otherwise 7 days. Zero disables grace; negative overrides are usage errors.
Library callers must pass the resolved value themselves; the pure verification
functions do not read manifests.

Three keys, three roles:

| key | lives | signs | listed in your key directory as |
|-----|-------|-------|--------------------------------|
| manifest key | offline | releases | an entry without `roles` (unchanged) |
| **issuing key** | on the server that sells | entitlements | `"roles": ["entitlement"]` |
| host key | on each agent | presentations | nowhere — it is the entitlement's `holder` |

Keep the issuing key on its own: it signs at every purchase, so it is the
exposed one. Listed without the `manifest` role it can never move anyone's
pin even if stolen; you revoke it in the directory and re-issue.

## 2. Publisher: declare what you sell

```bash
axp keygen --out issuing.key                       # the ONLINE key; its public form goes below
axp keydir --publisher ext.example.com \
    --key ed25519:MANIFEST…@paid-tool \
    --entitlement-key ed25519:ISSUING…@paid-tool \
    -o agent-extension-keys.json                   # serve at /.well-known/agent-extension-keys.json
```

In the manifest:

```jsonc
"commerce": {
  "entitlement": "required",                 // or "optional": free install, paid features inside
  "plans": [
    { "id": "pro-monthly", "kind": "subscription", "period": "month", "price": { "amount": 500, "currency": "EUR" } },
    { "id": "lifetime", "kind": "one_time", "price": { "amount": 4900, "currency": "EUR" }, "updates_months": 12 },
    { "id": "trial", "kind": "trial", "days": 14 }
  ],
  "checkout_url": "https://ext.example.com/paid-tool/buy",
  "refresh_url":  "https://api.ext.example.com/axp/entitlements"
}
```

Plans are for the consent card; a host never computes with them. The three
models and their combination are expressed by two dates in the entitlement
you issue:

| plan | `valid_until` | `updates_until` |
|------|---------------|-----------------|
| subscription | period end (renewed) | period end |
| one-time, updates for a year | `null` (for ever) | purchase + 12 months |
| one-time, all updates | `null` | `null` |
| trial | trial end | trial end |

If you do **not** want the code to leave your server before payment, gate the
artifact on the target(s):

```jsonc
"delivery": { "method": "archive", "url": "https://ext.example.com/paid-tool-1.0.0.tar.gz",
              "sha256": "…", "auth": { "scheme": "entitlement" } }
```

The manifest stays public (hosts need it for discovery, consent and update
checks and it contains only the description and digests); the tarball is
released only to a host that presents a valid entitlement (§4 below).
Release with `axp release` as always — it stamps `published_at`, which is
what `updates_until` is compared against.

## 3. Issuer: sign entitlements

After a purchase is confirmed (webhook, manual, whatever), sign one
entitlement for the **holder** the host sent to your checkout page as
`axp_holder` (the host's public key):

```bash
axp entitlement issue --key issuing.key --issuer ext.example.com \
    --extension ext.example.com/paid-tool --holder "ed25519:HOST…" \
    --plan lifetime --updates-days 365 --serial INV-2026-0042 -o entitlement.json
# subscription: --plan pro-monthly --valid-days 31 --updates-days 31
# trial:        --plan trial --valid-days 14
```

In code, `axp.entitlements.issue(...)` does the same. Deliver the document
in any of three ways — all hosts accept an **import** (e-mail the file, show
it on the thank-you page); hosts with a web surface accept it on your
redirect to `axp_return?entitlement=<base64url JSON>`; and hosts poll your
`refresh_url`, which is also how **renewal** works:

```
POST /axp/entitlements
Authorization: AXP-Entitlement <token>        # a presentation, with or without an entitlement inside

200  {…fresh entitlement…}                     # the holder has bought / renewed: here is the current one
402  {"checkout_url": "https://…"}             # nothing owed to this holder yet (or trial already used)
403                                             # the presented entitlement is revoked
404                                             # unknown extension
```

The request is verified with one call:

```python
from axp import verify_presentation, EntitlementError

try:
    presentation = verify_presentation(request.headers["Authorization"], audience=REFRESH_URL)
except EntitlementError:
    return 401                                  # bad scheme, wrong audience, expired, bad signature
holder = presentation["holder"]                 # proven: whoever sent this holds that key
record = purchases.for_holder(holder, presentation["extension"])
if record is None:
    return 402, {"checkout_url": CHECKOUT_URL}
if record.revoked:
    return 403
return 200, issue(extension=…, holder=holder, plan=record.plan, issuer="ext.example.com",
                  private_key_pem=ISSUING_KEY, valid_until=record.period_end, updates_until=record.period_end,
                  serial=record.serial)
```

A host renews a subscription a few days before `valid_until`, so your
endpoint sees one call per period per host. Revocation is nothing more than
answering `403` for that `serial` (and refusing it at the artifact server);
a host that refreshes learns of it on its own.

For a **transfer** (user re-installed their agent → new host key) issue a
new entitlement to the new holder and mark the old serial revoked; the
protocol does not copy entitlements between machines.

### Letting the agent pay by itself: x402 (optional)

The `402` above can double as an [x402](https://x402.org) payment-required
response. x402 is an open protocol in which a server answers `402` with
machine-readable payment requirements (amount, network, payee), the client
signs a stablecoin payment and repeats the request with the payment header,
and a *facilitator* verifies and settles it. Declare it in the manifest —
`"payment": ["x402"]`, and price plans in `USDC` if you like — and put the
x402 middleware in front of the refresh endpoint:

```
POST /axp/entitlements
Authorization: AXP-Entitlement <token>        # the presentation proves the holder …
<x402 payment header>                          # … and the payment, in the same request

402 + x402 payment requirements               # first call: nothing owed yet, here is the price
200 {…entitlement bound to the presentation's holder…}   # after settlement
```

The binding is free: the presentation names the holder and the payment
names the payer, in one request, so there is no checkout page and no
`axp_holder` round trip. A subscription renews by paying the `402` again
when the host refreshes before `valid_until`. The entitlement you return is
the ordinary document — you can put the settlement reference in an `x-`
field for your records.

Keep the other paths. A host that speaks no rail still gets your `402` with
`checkout_url` and still accepts an import, and you must still answer an
unpaid refresh with `200` for a holder who bought elsewhere. x402 is a way to
collect, not a condition for issuing. Metered, per-call pricing of the
extension's own API is also x402's home turf — do it there, inside the
extension, AXP never sees it.

## 4. Gated artifact server

A static host cannot do this; a few lines in any web framework can. On
`GET /paid-tool-1.0.0.tar.gz`:

```python
from axp import verify_presented_entitlement, covers_release

verdict = verify_presented_entitlement(
    request.headers.get("Authorization", ""),
    audience="https://ext.example.com/paid-tool-1.0.0.tar.gz",   # the exact URL in the manifest
    extension="ext.example.com/paid-tool",
    issuer_keys=[ISSUING_PUBLIC_KEY],          # the keys THIS server trusts; the directory is for hosts
)
if verdict.status == "malformed":
    return 401                                 # not a usable presentation
if not verdict.valid:
    return 402                                 # no / invalid / expired entitlement
if not covers_release(verdict.entitlement, {"published_at": "2026-10-16T09:00:00Z"}):
    return 403                                 # bought a year of updates; this release is newer
return send_file("paid-tool-1.0.0.tar.gz")
```

Test it from the command line before a host ever does:

```bash
axp entitlement present entitlement.json --host-key host.key \
    --audience https://ext.example.com/paid-tool-1.0.0.tar.gz --value-only > token
curl -H "Authorization: $(cat token)" https://ext.example.com/paid-tool-1.0.0.tar.gz -o x.tar.gz
axp entitlement inspect @token --audience https://ext.example.com/paid-tool-1.0.0.tar.gz \
    --keydir agent-extension-keys.json            # what your server should have concluded
```

## 5. Inside the extension

A commerce-capable host hands every hook `AXP_ENTITLEMENT_FILE`, a stable
0600 JSON file with the current entitlement (rewritten on renewal, removed on
expiry). An extension that wants to lock features itself reads it and checks
the signature with the issuing public key it ships:

```python
import json, os
from axp import verify_entitlement

path = os.environ.get("AXP_ENTITLEMENT_FILE")
verdict = verify_entitlement(json.load(open(path)), extension="ext.example.com/paid-tool",
                             holder=None, issuer_keys=[ISSUING_PUBLIC_KEY]) if path else None
paid = bool(verdict and verdict.valid)
```

`holder=None` because the extension has no independent knowledge of the
host's key; the host already checked that binding. `axp` is stdlib-only
(ed25519 via `cryptography` or the `openssl` binary), so vendoring
`axp/jcs.py`, `axp/signing.py` and `axp/entitlements.py` is enough.

The extension MUST still start on a host that sets no `AXP_ENTITLEMENT_FILE`
(§10): what it does then — run free, run a trial, refuse politely — is your
`optional`/`required` policy, not the host's problem.

## 6. What you get, honestly

- **Gated delivery** is the strong protection: a machine without an
  entitlement never receives the bytes. It needs a small dynamic server
  instead of a static file.
- **The host's check** keeps honest users honest and gives them a good
  experience: price on the consent card, automatic renewal, no surprise
  shutdowns, a disable (never an uninstall) when a subscription lapses. A
  pre-commerce host ignores it and installs a public artifact for free.
- **The extension's own check** (§5) is the second line for anything that
  runs on the user's machine.

Nothing in this document is copy protection against a determined user with a
shell on their own machine — the same is true of every licence scheme ever
shipped. It is a clean, verifiable receipt and a clean way to say "not
without one"; that is what a protocol can give you.
