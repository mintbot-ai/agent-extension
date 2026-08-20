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

def sign_manifest(manifest: dict, private_key_pem: bytes) -> dict:
    """Return a copy of ``manifest`` with ``signature`` set (SPEC §8.2).

    ``signing.public_key`` must already be present and must match the private
    key — signing with a mismatched key would publish an unverifiable
    manifest, so it is refused here rather than discovered by users.
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
    out = {k: v for k, v in manifest.items() if k != "signature"}
    out["signature"] = sign_bytes(jcs.signing_input(out), private_key_pem)
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
# Trust-On-First-Use pin store (SPEC §8.1, §8.3, §8.4)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustDecision:
    """What :meth:`PinStore.evaluate` concluded about one candidate manifest.

    ``accepted`` is the gate; ``action`` says what happened / must happen:

      pin        first use — key verified against itself and pinned
      same-key   verified against the already-pinned key
      rotate     dual-signed rotation verified; the pin was moved
      announce   same-key release that (also) announced a next_key (recorded)
      unsigned   accepted without a signature (never previously pinned)
      refuse     not accepted; ``reason`` says why
    """

    accepted: bool
    action: str
    reason: str = ""


class PinStore:
    """JSON-file-backed key pins, keyed by extension id.

    State per extension id: ``{"public_key": …, "next_key": …|null,
    "was_signed": bool}``. The file is created lazily and written atomically.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._pins: dict[str, dict] = {}
        if self._path.exists():
            self._pins = json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self._path)

    def pinned_key(self, ext_id: str) -> str | None:
        entry = self._pins.get(ext_id)
        return entry.get("public_key") if entry else None

    def evaluate(self, ext_id: str, manifest: dict, *, allow_unsigned: bool = True) -> TrustDecision:
        """Run the full §8 trust decision for one candidate manifest and
        update the pin state on acceptance.

        ``allow_unsigned`` is the host's policy for never-pinned extensions
        (SPEC §8.4 says install-with-warning; a stricter host passes False).
        The signed→unsigned ratchet is not a policy: once pinned, an unsigned
        manifest is always refused.
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
            self._pins[ext_id] = {"public_key": None, "next_key": None, "was_signed": False}
            self._save()
            return TrustDecision(True, "unsigned")

        if not candidate_key:
            return TrustDecision(False, "refuse", "signature present without signing.public_key")

        pinned = entry.get("public_key") if entry else None

        if pinned is None:
            # First use (or previously unsigned): trust the manifest's own key.
            if not verify_manifest(manifest, candidate_key):
                return TrustDecision(False, "refuse", "signature does not verify against signing.public_key")
            self._pins[ext_id] = {
                "public_key": candidate_key,
                "next_key": signing.get("next_key"),
                "was_signed": True,
            }
            self._save()
            return TrustDecision(True, "pin")

        if candidate_key == pinned:
            if not verify_manifest(manifest, pinned):
                return TrustDecision(False, "refuse", "signature does not verify against the pinned key")
            # Record (or clear) a rotation announcement carried by this release.
            self._pins[ext_id]["next_key"] = signing.get("next_key")
            self._save()
            return TrustDecision(True, "announce" if signing.get("next_key") else "same-key")

        # Different key: only a valid dual-signed rotation may move the pin.
        announced = entry.get("next_key") if entry else None
        if candidate_key != announced:
            return TrustDecision(False, "refuse",
                                 "key changed without an announced rotation "
                                 "(signing.next_key); refusing — possible key compromise")
        signature_prev = manifest.get("signature_prev")
        if not signature_prev:
            return TrustDecision(False, "refuse",
                                 "rotation release must be dual-signed (signature_prev by the pinned key)")
        payload = jcs.signing_input(manifest)
        if not verify_bytes(payload, signature_prev, pinned):
            return TrustDecision(False, "refuse", "signature_prev does not verify against the pinned key")
        if not verify_bytes(payload, signature, candidate_key):
            return TrustDecision(False, "refuse", "signature does not verify against the announced new key")
        self._pins[ext_id] = {
            "public_key": candidate_key,
            "next_key": signing.get("next_key"),
            "was_signed": True,
        }
        self._save()
        return TrustDecision(True, "rotate")

    def forget(self, ext_id: str) -> None:
        """Explicit user re-trust (lost key, SPEC §8.3): drop the pin so the
        next install is a fresh TOFU. Never called automatically."""
        self._pins.pop(ext_id, None)
        self._save()
