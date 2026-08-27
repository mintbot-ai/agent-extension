"""AXP signing, verification and Trust-On-First-Use pinning (SPEC §8).

Keys are ed25519. The public form is ``ed25519:<base64 of the 32 raw
bytes>`` (SPEC §8.2); the private form is a standard PKCS#8 PEM so any tool
can handle it. Signatures are base64 of the 64-byte ed25519 signature over
:func:`axp.jcs.signing_input`.

Two interchangeable backends, picked automatically:

  * ``cryptography`` when importable — in-process, fast.
  * the ``openssl`` CLI (>= 1.1.1) otherwise — zero Python dependencies,
    which is what lets a host without any crypto wheel still verify.

:class:`PinStore` is the reference TOFU state machine: first-use pinning per
extension id, "updates only from the same key", announce → dual-sign key
rotation, and the signed→unsigned ratchet. Hosts can use it as-is (it
persists to a JSON file) or copy the logic.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import jcs

KEY_PREFIX = "ed25519:"
_KEY_RE = re.compile(r"^ed25519:[A-Za-z0-9+/]{43}=$")
# The constant DER prefix that turns 32 raw ed25519 public-key bytes into a
# SubjectPublicKeyInfo the openssl CLI accepts.
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SigningError(ValueError):
    """A key, signature, or trust-state problem. The message is user-facing."""


def _raw_public_key(public_key: str) -> bytes:
    if not _KEY_RE.match(public_key or ""):
        raise SigningError(
            f"public key {public_key!r} is malformed "
            "(expected ed25519:<base64 of 32 raw bytes>)"
        )
    try:
        raw = base64.b64decode(public_key[len(KEY_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningError(f"public key base64 is invalid: {exc}") from exc
    if len(raw) != 32:
        raise SigningError(f"public key decodes to {len(raw)} bytes, expected 32")
    return raw


def _decode_signature(signature: str) -> bytes:
    try:
        sig = base64.b64decode(signature or "", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningError(f"signature base64 is invalid: {exc}") from exc
    if len(sig) != 64:
        raise SigningError(f"signature decodes to {len(sig)} bytes, expected 64")
    return sig


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def _have_cryptography() -> bool:
    from importlib.util import find_spec
    return find_spec("cryptography") is not None


HAVE_CRYPTOGRAPHY = _have_cryptography()


def _load_private_key(private_key_pem: bytes):
    """(cryptography backend) PEM → Ed25519PrivateKey, or SigningError."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private key is not ed25519")
    return key


def _openssl() -> str:
    exe = shutil.which("openssl")
    if exe is None:
        raise SigningError(
            "neither the 'cryptography' package nor the openssl CLI is "
            "available; cannot sign or verify"
        )
    return exe


def _run_openssl(args: list[str], *, expect_ok: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run([_openssl(), *args], capture_output=True, text=False, check=False)
    if expect_ok and proc.returncode != 0:
        raise SigningError(
            f"openssl {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[:300]}"
        )
    return proc


def generate_private_key_pem() -> bytes:
    """A fresh ed25519 private key as PKCS#8 PEM bytes."""
    if HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    with tempfile.TemporaryDirectory(prefix="axp-keygen-") as tmp:
        out = Path(tmp) / "key.pem"
        _run_openssl(["genpkey", "-algorithm", "ed25519", "-out", str(out)])
        return out.read_bytes()


def public_key_from_private(private_key_pem: bytes) -> str:
    """``ed25519:<base64raw>`` public form of a PKCS#8 PEM private key."""
    if HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import serialization
        raw = _load_private_key(private_key_pem).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        return KEY_PREFIX + base64.b64encode(raw).decode()
    with tempfile.TemporaryDirectory(prefix="axp-pub-") as tmp:
        keyfile = Path(tmp) / "key.pem"
        keyfile.write_bytes(private_key_pem)
        proc = _run_openssl(["pkey", "-in", str(keyfile), "-pubout", "-outform", "DER"])
        der = proc.stdout
        if len(der) < 32:
            raise SigningError("openssl produced an unexpectedly short public key")
        return KEY_PREFIX + base64.b64encode(der[-32:]).decode()


def sign_bytes(data: bytes, private_key_pem: bytes) -> str:
    """base64 ed25519 signature of ``data``."""
    if HAVE_CRYPTOGRAPHY:
        return base64.b64encode(_load_private_key(private_key_pem).sign(data)).decode()
    with tempfile.TemporaryDirectory(prefix="axp-sign-") as tmp:
        keyfile = Path(tmp) / "key.pem"
        datafile = Path(tmp) / "data.bin"
        keyfile.write_bytes(private_key_pem)
        datafile.write_bytes(data)
        proc = _run_openssl(["pkeyutl", "-sign", "-inkey", str(keyfile),
                             "-rawin", "-in", str(datafile)])
        return base64.b64encode(proc.stdout).decode()


def verify_bytes(data: bytes, signature: str, public_key: str) -> bool:
    """True iff ``signature`` is a valid ed25519 signature of ``data`` by
    ``public_key``. Malformed inputs raise :class:`SigningError`; a merely
    *wrong* signature returns False."""
    raw_key = _raw_public_key(public_key)
    raw_sig = _decode_signature(signature)
    if HAVE_CRYPTOGRAPHY:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_sig, data)
            return True
        except InvalidSignature:
            return False
    with tempfile.TemporaryDirectory(prefix="axp-verify-") as tmp:
        pubfile = Path(tmp) / "pub.der"
        datafile = Path(tmp) / "data.bin"
        sigfile = Path(tmp) / "sig.bin"
        pubfile.write_bytes(_SPKI_PREFIX + raw_key)
        datafile.write_bytes(data)
        sigfile.write_bytes(raw_sig)
        proc = _run_openssl(
            ["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(pubfile),
             "-rawin", "-in", str(datafile), "-sigfile", str(sigfile)],
            expect_ok=False,
        )
        return proc.returncode == 0


# ---------------------------------------------------------------------------
# Manifest-level operations
# ---------------------------------------------------------------------------

def sign_manifest(manifest: dict, private_key_pem: bytes, *,
                  prev_private_key_pem: bytes | None = None) -> dict:
    """Return a copy of ``manifest`` with ``signature`` set (SPEC §8.2).

    ``signing.public_key`` must already be present and must match the private
    key — signing with a mismatched key would publish an unverifiable
    manifest, so it is refused here rather than discovered by users.

    ``prev_private_key_pem`` turns the result into a key-rotation release
    (SPEC §8.3): ``signature_prev`` by the OLD pinned key over the very same
    signing input, so hosts still pinning the old key can verify the
    hand-over to the new one. Any ``signature_prev`` already on the input is
    dropped either way — a countersignature only ever matched one exact
    payload and must never be carried over to a re-signed document.
    """
    signing = manifest.get("signing") or {}
    declared = signing.get("public_key")
    if not declared:
        raise SigningError("manifest has no signing.public_key; add it before signing")
    actual = public_key_from_private(private_key_pem)
    if declared != actual:
        raise SigningError(
            f"signing.public_key {declared!r} does not match this private key "
            f"({actual!r}) — wrong key file?"
        )
    out = {k: v for k, v in manifest.items() if k not in ("signature", "signature_prev")}
    payload = jcs.signing_input(out)
    out["signature"] = sign_bytes(payload, private_key_pem)
    if prev_private_key_pem is not None:
        if public_key_from_private(prev_private_key_pem) == actual:
            raise SigningError(
                "the previous key is the same as the signing key; a rotation release "
                "needs the OLD key as --prev-key and the NEW key as --key"
            )
        out["signature_prev"] = sign_bytes(payload, prev_private_key_pem)
    return out


def verify_manifest(manifest: dict, public_key: str | None = None) -> bool:
    """Verify ``manifest['signature']`` against ``public_key`` (default: the
    manifest's own ``signing.public_key`` — self-consistency, which is what
    TOFU trusts on FIRST use; later uses must pass the pinned key)."""
    signature = manifest.get("signature")
    if not isinstance(signature, str) or not signature:
        raise SigningError("manifest has no signature")
    if public_key is None:
        public_key = (manifest.get("signing") or {}).get("public_key")
        if not public_key:
            raise SigningError("manifest has no signing.public_key")
    return verify_bytes(jcs.signing_input(manifest), signature, public_key)


# ---------------------------------------------------------------------------
# Publisher key directory (SPEC section 8.5)
# ---------------------------------------------------------------------------

KEY_DIRECTORY_PATH = "/.well-known/agent-extension-keys.json"


def key_directory_url(publisher: str) -> str:
    return f"https://{publisher}{KEY_DIRECTORY_PATH}"


def parse_key_directory(document: object, *, publisher: str, name: str | None) -> list[str]:
    """The publisher's currently valid keys for extension ``name``.

    Shape::

        {"publisher": "ext.example.com",
         "keys": [{"public_key": "ed25519:…", "key_id": "…",
                   "extensions": ["graph-memory"],   # optional: restrict to names
                   "revoked": false}]}

    Entries whose ``extensions`` list exists but does not contain ``name``
    and entries marked ``revoked`` are excluded. A document for another
    publisher, or one that is not an object with a ``keys`` array, is an
    error — a host must not treat a stray JSON file as a key directory.
    """
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise SigningError("key directory is not an object with a keys[] array")
    if document.get("publisher") and document["publisher"] != publisher:
        raise SigningError(
            f"key directory belongs to {document['publisher']!r}, not {publisher!r}"
        )
    keys: list[str] = []
    for entry in document["keys"]:
        if not isinstance(entry, dict) or entry.get("revoked"):
            continue
        scope = entry.get("extensions")
        if name is not None and isinstance(scope, list) and name not in scope:
            continue
        public_key = entry.get("public_key")
        if isinstance(public_key, str) and _KEY_RE.match(public_key):
            keys.append(public_key)
    return keys


# ---------------------------------------------------------------------------
# Trust-On-First-Use pin store (SPEC section 8.1, 8.3, 8.4, 8.5)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustDecision:
    """What :meth:`PinStore.decide` concluded about one candidate manifest.

    ``accepted`` is the gate; ``action`` says what happened / must happen:

      pin        first use — key verified against itself; pin on commit
      same-key   verified against the already-pinned key
      announce   same-key release that (also) announced a next_key
      rotate     dual-signed rotation verified; the pin moves on commit
      recover    lost-key recovery via the publisher key directory
                 (accepted only when the host passed allow_recovery=True)
      unsigned   accepted without a signature (never previously pinned)
      refuse     not accepted; ``reason`` says why

    ``entry`` is the pin-store record to persist on commit (None when the
    decision changes nothing). ``decide`` never writes; a host commits only
    after the install actually succeeded, so a failed download or hook can
    never leave a pin behind (SPEC section 8: the pin records what was
    INSTALLED, not what was merely seen).
    """

    accepted: bool
    action: str
    reason: str = ""
    entry: dict | None = None


class PinStore:
    """JSON-file-backed key pins, keyed by extension id.

    State per extension id: ``{"public_key": …, "next_key": …|null,
    "was_signed": bool}``. The file is created lazily and written atomically.

    Two-phase use (recommended)::

        decision = store.decide(ext_id, manifest)
        if decision.accepted:
            ... download, verify digest, run hooks ...
            store.commit(ext_id, decision)

    :meth:`evaluate` is decide + commit in one step for hosts that have no
    later failure point (validation tools, dry runs).
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._pins: dict[str, dict] = {}
        if self._path.exists():
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                # A stray list/scalar must not masquerade as an empty store:
                # treating it as "nothing pinned" would silently disable TOFU.
                raise ValueError("pin store is not a JSON object")
            self._pins = loaded

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self._path)

    def pinned_key(self, ext_id: str) -> str | None:
        entry = self._pins.get(ext_id)
        return entry.get("public_key") if entry else None

    def announced_key(self, ext_id: str) -> str | None:
        entry = self._pins.get(ext_id)
        return entry.get("next_key") if entry else None

    def decide(
        self,
        ext_id: str,
        manifest: dict,
        *,
        allow_unsigned: bool = True,
        directory_keys: list[str] | None = None,
        allow_recovery: bool = False,
    ) -> TrustDecision:
        """Run the section-8 trust decision for one candidate manifest. Pure:
        nothing is written until :meth:`commit`.

        ``allow_unsigned`` — host policy for never-pinned extensions (SPEC
        section 8.4 says install-with-warning; a stricter host passes False).
        The signed→unsigned ratchet is not a policy: once pinned, an unsigned
        manifest is always refused.

        ``directory_keys`` — the publisher's key directory (section 8.5) as
        the host fetched it, or None when it was not consulted. When given,
        a rotation is accepted only if the new key is listed there (a stolen
        signing key alone can then no longer move the pin), and a manifest
        signed by an unannounced key that IS listed while the pinned key is
        NOT is a lost-key ``recover`` — accepted only with
        ``allow_recovery=True``, otherwise refused with that action named so
        the host can ask the user.
        """
        entry = self._pins.get(ext_id)
        signing = manifest.get("signing") or {}
        candidate_key = signing.get("public_key")
        signature = manifest.get("signature")

        if not signature:
            if entry and entry.get("was_signed"):
                return TrustDecision(False, "refuse",
                                     "previously installed signed; an unsigned manifest "
                                     "is a trust break (ratchet)")
            if not allow_unsigned:
                return TrustDecision(False, "refuse", "unsigned manifests are not accepted by this host")
            return TrustDecision(True, "unsigned",
                                 entry={"public_key": None, "next_key": None, "was_signed": False})

        if not candidate_key:
            return TrustDecision(False, "refuse", "signature present without signing.public_key")

        pinned = entry.get("public_key") if entry else None

        if pinned is None:
            # First use (or previously unsigned): trust the manifest's own key.
            if directory_keys is not None and candidate_key not in directory_keys:
                return TrustDecision(False, "refuse",
                                     "signing key is not listed in the publisher's key directory")
            if not verify_manifest(manifest, candidate_key):
                return TrustDecision(False, "refuse", "signature does not verify against signing.public_key")
            return TrustDecision(True, "pin", entry={
                "public_key": candidate_key,
                "next_key": signing.get("next_key"),
                "was_signed": True,
            })

        if candidate_key == pinned:
            if not verify_manifest(manifest, pinned):
                return TrustDecision(False, "refuse", "signature does not verify against the pinned key")
            # Record (or clear) a rotation announcement carried by this release.
            new_entry = {**entry, "next_key": signing.get("next_key")}
            return TrustDecision(True, "announce" if signing.get("next_key") else "same-key",
                                 entry=new_entry)

        # Different key. Only a valid dual-signed rotation may move the pin —
        # and, when the publisher's key directory was consulted, only to a key
        # the publisher lists there (section 8.5).
        announced = entry.get("next_key") if entry else None
        payload = jcs.signing_input(manifest)
        if candidate_key == announced:
            signature_prev = manifest.get("signature_prev")
            if not signature_prev:
                return TrustDecision(False, "refuse",
                                     "rotation release must be dual-signed (signature_prev by the pinned key)")
            if directory_keys is not None and candidate_key not in directory_keys:
                return TrustDecision(False, "refuse",
                                     "announced key is not listed in the publisher's key directory; "
                                     "refusing the rotation")
            if not verify_bytes(payload, signature_prev, pinned):
                return TrustDecision(False, "refuse", "signature_prev does not verify against the pinned key")
            if not verify_bytes(payload, signature, candidate_key):
                return TrustDecision(False, "refuse", "signature does not verify against the announced new key")
            return TrustDecision(True, "rotate", entry={
                "public_key": candidate_key,
                "next_key": signing.get("next_key"),
                "was_signed": True,
            })

        if (directory_keys is not None and candidate_key in directory_keys
                and pinned not in directory_keys):
            # Lost-key recovery: the publisher's domain now vouches for the
            # new key and no longer for the pinned one. Never silent.
            if not verify_bytes(payload, signature, candidate_key):
                return TrustDecision(False, "refuse", "signature does not verify against the directory-listed key")
            new_entry = {"public_key": candidate_key, "next_key": signing.get("next_key"),
                         "was_signed": True}
            if not allow_recovery:
                return TrustDecision(False, "recover",
                                     "the publisher replaced their signing key without a rotation "
                                     "(key directory lists the new key, not the pinned one); "
                                     "explicit re-trust is required", entry=new_entry)
            return TrustDecision(True, "recover", entry=new_entry)

        return TrustDecision(False, "refuse",
                             "key changed without an announced rotation "
                             "(signing.next_key); refusing — possible key compromise")

    def commit(self, ext_id: str, decision: TrustDecision) -> None:
        """Persist an accepted decision's pin state. A refused decision is a
        programming error to commit."""
        if not decision.accepted:
            raise SigningError(f"cannot commit a refused trust decision ({decision.reason})")
        if decision.entry is not None:
            self._pins[ext_id] = dict(decision.entry)
            self._save()

    def evaluate(self, ext_id: str, manifest: dict, *, allow_unsigned: bool = True,
                 directory_keys: list[str] | None = None,
                 allow_recovery: bool = False) -> TrustDecision:
        """decide + commit in one step."""
        decision = self.decide(ext_id, manifest, allow_unsigned=allow_unsigned,
                               directory_keys=directory_keys, allow_recovery=allow_recovery)
        if decision.accepted:
            self.commit(ext_id, decision)
        return decision

    def forget(self, ext_id: str) -> None:
        """Explicit user re-trust (lost key, SPEC section 8.3): drop the pin so the
        next install is a fresh TOFU. Never called automatically."""
        self._pins.pop(ext_id, None)
        self._save()
