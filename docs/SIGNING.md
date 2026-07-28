# AXP signing, pinning & key rotation

This is the practical companion to §8 of [`../SPEC.md`](../SPEC.md). It shows a
publisher how to sign a manifest, and a host how to verify, pin, and follow key
rotation. AXP uses **ed25519** (minisign-style): no CA, no PKI, self-hostable.

## 1. What gets signed

The signature covers the **canonical (JCS / RFC 8785) serialization of the whole
manifest with the `signature` and `signature_prev` fields removed**. Because the
manifest embeds `release.artifact.sha256`, signing the manifest transitively
binds the version, channel, `valid_until`, and the artifact bytes into one
signed unit — no separate artifact signature is needed.

The signature is **inline** in the top-level `signature` field (base64 ed25519).

## 2. Publisher: generate a key (once)

```bash
# Any ed25519 keypair works. Example with `age-keygen`-style or raw openssl:
openssl genpkey -algorithm ed25519 -out axp-signing.key
openssl pkey -in axp-signing.key -pubout -outform DER \
  | tail -c 32 | base64        # -> the value after "ed25519:" in signing.public_key
```

Keep `axp-signing.key` offline/secret. Put the base64 public key in the
manifest:

```jsonc
"signing": { "public_key": "ed25519:BASE64PUB", "key_id": "graph-memory-2026", "next_key": null }
```

## 3. Publisher: sign a release

1. Build the manifest with `signature`/`signature_prev` **absent**.
2. Canonicalize (JCS) and sign the bytes with the private key.
3. Insert the base64 signature as the top-level `signature`.

```bash
# Pseudocode — use any JCS lib to canonicalize first.
canonicalize agent-extension.json > canonical.bin
openssl pkeyutl -sign -inkey axp-signing.key -rawin -in canonical.bin \
  | base64 -w0     # -> paste into "signature"
```

Publish the manifest at `/.well-known/agent-extension.json` (and/or as a release
asset for `github` update sources).

## 4. Host: first install (Trust On First Use)

1. Fetch the manifest, lift out `signature`, canonicalize the rest.
2. Verify against `signing.public_key`.
3. On success, **pin** that public key into the extension's local state
   (`…/ext/<name>/trust.json`), alongside the installed version.

From now on, every update must verify against the pinned key (§5).

## 5. Host: verifying an update

- Canonicalize the candidate manifest (minus signatures), verify `signature`
  against the **pinned** key.
- Reject if verification fails — this is the "updates only from the same key"
  rule.
- Enforce monotonicity: only apply if `identity.version` is strictly higher
  than installed, on the tracked channel.
- If `release.valid_until` is present and in the past (beyond a small grace
  window), warn: the publisher may have stopped signing, or you are being held
  back at an old version (freeze). See §7.4 of the spec.

## 6. Key rotation (no brick)

A lost or leaked key must not permanently lock out updates. Rotation is a small,
ca-free dance:

1. **Announce** — a normal release, signed by the current pinned key, sets
   `signing.next_key` to the *new* public key. Hosts record the announced
   successor but keep trusting the current key.
2. **Rotate** — the first release under the new key is **dual-signed**:
   - `signature` = signature by the **new** key,
   - `signature_prev` = signature by the **old pinned** key,
   - `signing.public_key` = the new key.
   The host verifies `signature_prev` against the pinned key (satisfies
   "same key"), confirms `signing.public_key` equals the previously announced
   `next_key`, verifies `signature` against the new key, then **re-pins** to the
   new key.
3. **After** — subsequent releases are signed by the new key alone.

If a key is lost with **no** `next_key` announced in advance, self-rotation is
impossible by design — recovery is a fresh TOFU the user must explicitly
confirm. That is the safe outcome, not a bug.

## 7. Unsigned extensions

Signing is optional but recommended. An unsigned manifest installs with a clear
warning, and once an extension has been installed *signed*, the host must not
silently accept a later *unsigned* manifest for it (downgrade-to-unsigned is a
trust break needing explicit user action).
