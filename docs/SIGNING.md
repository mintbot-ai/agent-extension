# AXP signing, pinning & key rotation (v0.4)

Practical companion to §8 of [`../SPEC.md`](../SPEC.md): how a publisher signs
a manifest, and how a host verifies, pins, and follows key rotation. AXP uses
**ed25519** (minisign-style): no CA, no PKI, self-hostable, runtime-neutral.

## 1. What gets signed

The signature covers the **canonical (JCS / RFC 8785) serialization of the whole
manifest with the `signature` and `signature_prev` fields removed**. Because the
manifest embeds every artifact digest (`release.artifact.sha256` and each
`targets[].delivery.sha256`), signing the manifest transitively binds the
version, channel, `valid_until`, and the artifact bytes into one signed unit —
no separate artifact signature is needed.

The signature is **inline** in the top-level `signature` field: base64 of the
64-byte ed25519 signature.

## 2. Key format (normative)

`signing.public_key` is **`ed25519:<base64 of the 32 raw public-key bytes>`** —
exactly 44 base64 characters after the prefix. Not SPKI/DER, not PEM. Every
ed25519 library (libsodium, Go `crypto/ed25519`, Python `cryptography` /
`PyNaCl`, tweetnacl, ring, …) consumes the raw 32 bytes directly, so a host
in any language verifies without ASN.1 parsing.

For the OpenSSL **CLI** (which wants SPKI), rebuild the SPKI by prepending the
constant 12-byte prefix `302a300506032b6570032100`:

```bash
RAW_B64="…"   # the part after ed25519:
{ printf '302a300506032b6570032100' | xxd -r -p; echo "$RAW_B64" | base64 -d; } \
  | openssl pkey -pubin -inform DER -outform PEM > pub.pem
```

## 3. Publisher: generate a key (once)

```bash
openssl genpkey -algorithm ed25519 -out axp-signing.key          # keep offline / secret
openssl pkey -in axp-signing.key -pubout -outform DER | tail -c 32 | base64
# -> paste after "ed25519:" into signing.public_key
```

```jsonc
"signing": { "public_key": "ed25519:BASE64RAW32", "key_id": "graph-memory-2026", "next_key": null }
```

`key_id` is a human label only; the key bytes are the identity.

## 4. Publisher: sign a release

1. Build the manifest with `signature` / `signature_prev` **absent**.
2. Canonicalize (JCS) and sign the bytes with the private key.
3. Insert the base64 signature as the top-level `signature`.

```bash
# Pseudocode — use any JCS library to canonicalize first.
canonicalize agent-extension.json > canonical.bin
openssl pkeyutl -sign -inkey axp-signing.key -rawin -in canonical.bin | base64 -w0
# -> paste into "signature"
```

Publish the signed manifest as `agent-extension.json` at
`/.well-known/agent-extension.json`, at the repo root, and — for `github` /
`forge` update sources — as a release asset of the `v<version>` release.

## 5. Host: first install (Trust On First Use)

1. Fetch the manifest, lift out `signature` (+ `signature_prev`), canonicalize
   the rest.
2. Verify against `signing.public_key`.
3. On success, **pin** that key under the extension id `<publisher>/<name>`
   alongside the installed version.

```bash
# OpenSSL CLI verify (pub.pem from §2):
echo "$SIGNATURE_B64" | base64 -d > sig.bin
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in canonical.bin -sigfile sig.bin
```

A host MAY carry **trust anchors** (an organisation-wide allow-list of
publisher keys) and refuse TOFU for keys not on it — host policy, not manifest.

## 6. Host: verifying an update

- Canonicalize the candidate manifest (minus signatures), verify `signature`
  against the **pinned** key for that extension id.
- Reject if verification fails — "updates only from the same key".
- Enforce monotonicity: apply only if `identity.version` is strictly higher
  than installed, on the tracked channel.
- If `release.valid_until` is past (beyond the host's grace window), warn: the
  publisher may have stopped signing, or you are being frozen at an old
  version (SPEC §7.4).

## 7. Key rotation (no brick)

1. **Announce** — a normal release, signed by the current pinned key, sets
   `signing.next_key` to the new public key. Hosts record the successor but keep
   trusting the current key.
2. **Rotate** — the first release under the new key is **dual-signed**:
   `signature` by the **new** key, `signature_prev` by the **old pinned** key,
   `signing.public_key` = the new key (must equal the announced `next_key`).
   The host verifies `signature_prev` against the pinned key, checks the
   announcement, verifies `signature` against the new key, then **re-pins**.
3. **After** — releases are signed by the new key alone.

```bash
axp keygen --out new.key                                   # prints ed25519:NEW…
# 1. announce: set signing.next_key = ed25519:NEW… and release as usual
axp release agent-extension.json --bump patch --artifact dist/x.tar.gz --key old.key
# 2. rotate: signing.public_key = ed25519:NEW…, sign with the new key,
#    countersign with the old one (writes signature_prev)
axp release agent-extension.json --bump patch --artifact dist/x.tar.gz --key new.key --prev-key old.key
# 3. afterwards: --key new.key only (a plain re-sign drops signature_prev)
```

List the new key in the key directory (§9) *before* step 2 — a host that
consults the directory refuses a rotation to an unlisted key.

A key lost with **no** `next_key` announced cannot self-rotate — recovery is a
fresh TOFU the user must explicitly confirm. That is the safe outcome.

## 8. Unsigned extensions

Signing is optional but recommended. An unsigned manifest installs with a clear
warning; once an extension has been installed *signed*, a later *unsigned*
manifest for the same id is a trust break needing explicit user action.

## 9. The publisher key directory (SPEC section 8.5)

Serve `https://<publisher>/.well-known/agent-extension-keys.json` listing
every key you currently sign with. `axp keydir` writes it:

```bash
axp keydir --publisher ext.example.com \
  --key ed25519:NEWKEY...@graph-memory \
  --revoked ed25519:OLDKEY... -o agent-extension-keys.json
```

What it buys you:

- **Rotation needs two things**: a release dual-signed by the old key AND the
  new key listed here. Someone who only stole your signing key cannot move
  users' pins.
- **Lost key**: list the new key, drop (or mark `revoked`) the old one, sign
  the next release with the new key. Hosts see "directory vouches for the
  new key, not the pinned one" and offer the user a re-trust (`recover`) —
  interactive, never silent. No rotation ceremony possible, no manual
  re-install on every machine.
- **First install (strict hosts)**: a host may refuse to pin a key you do not
  list.

Keep the directory on the publisher domain itself (the one in
`identity.publisher`); hosts fetch it from there, never from a URL inside a
manifest.
