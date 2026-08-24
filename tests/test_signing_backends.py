"""axp.signing — the openssl CLI backend, cross-backend interoperability,
malformed-input errors, and the PinStore paths the lifecycle test does not
walk (unsigned → signed, forget, announced_key).

The cryptography backend is what every other test exercises; a host without
the wheel (SPEC decision #5: "not every machine has the Hermes stack") runs
the openssl path, so it must produce and accept byte-identical keys and
signatures.
"""

import shutil

import pytest

from axp import jcs, signing
from axp.manifest import ext_id


requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


@pytest.fixture
def openssl_only(monkeypatch):
    monkeypatch.setattr(signing, "HAVE_CRYPTOGRAPHY", False)


def _signed(example, pem, pub, **extra):
    data = dict(example)
    data["signing"] = {"public_key": pub, "key_id": "t", "next_key": None, **extra}
    data.pop("signature", None)
    return signing.sign_manifest(data, pem)


@requires_openssl
def test_openssl_backend_roundtrip(openssl_only, example):
    pem = signing.generate_private_key_pem()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    pub = signing.public_key_from_private(pem)
    assert pub.startswith("ed25519:") and len(pub) == len("ed25519:") + 44
    signed = _signed(example, pem, pub)
    assert signing.verify_manifest(signed) is True
    signed["identity"] = {**signed["identity"], "version": "9.9.9"}
    assert signing.verify_manifest(signed) is False


@requires_openssl
def test_backends_are_interoperable(monkeypatch, example):
    """Keys and signatures made by one backend verify with the other — the
    manifest a publisher signs with cryptography must verify on an openssl-only
    host and vice versa."""
    assert signing.HAVE_CRYPTOGRAPHY, "this test needs both backends present"
    pem_c = signing.generate_private_key_pem()
    pub_c = signing.public_key_from_private(pem_c)
    signed_c = _signed(example, pem_c, pub_c)

    monkeypatch.setattr(signing, "HAVE_CRYPTOGRAPHY", False)
    assert signing.public_key_from_private(pem_c) == pub_c
    assert signing.verify_manifest(signed_c) is True
    pem_o = signing.generate_private_key_pem()
    pub_o = signing.public_key_from_private(pem_o)
    signed_o = _signed(example, pem_o, pub_o)

    monkeypatch.setattr(signing, "HAVE_CRYPTOGRAPHY", True)
    assert signing.public_key_from_private(pem_o) == pub_o
    assert signing.verify_manifest(signed_o) is True
    # And the two backends sign the same bytes identically (ed25519 is deterministic).
    payload = jcs.signing_input(signed_o)
    sig_c = signing.sign_bytes(payload, pem_o)
    monkeypatch.setattr(signing, "HAVE_CRYPTOGRAPHY", False)
    assert signing.sign_bytes(payload, pem_o) == sig_c


def test_openssl_missing_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(signing, "HAVE_CRYPTOGRAPHY", False)
    monkeypatch.setattr(signing.shutil, "which", lambda _n: None)
    with pytest.raises(signing.SigningError, match="neither the 'cryptography' package nor the openssl CLI"):
        signing.generate_private_key_pem()


def test_malformed_keys_and_signatures_raise_not_return_false(example):
    pem = signing.generate_private_key_pem()
    pub = signing.public_key_from_private(pem)
    signed = _signed(example, pem, pub)
    payload = jcs.signing_input(signed)
    for bad_key in ("rsa:AAAA", "ed25519:" + "A" * 10, "ed25519:" + "!" * 43 + "=", "", None):
        with pytest.raises(signing.SigningError, match="malformed"):
            signing.verify_bytes(payload, signed["signature"], bad_key)
    with pytest.raises(signing.SigningError, match="base64 is invalid"):
        signing.verify_bytes(payload, "not*base64", pub)
    with pytest.raises(signing.SigningError, match="expected 64"):
        signing.verify_bytes(payload, "AAAA", pub)
    # A syntactically valid but wrong signature is merely False.
    other = signing.sign_bytes(b"other payload", pem)
    assert signing.verify_bytes(payload, other, pub) is False


def test_verify_manifest_error_paths(example):
    with pytest.raises(signing.SigningError, match="no signature"):
        signing.verify_manifest({**example, "signature": ""})
    unsigned = {k: v for k, v in example.items() if k not in ("signature", "signing")}
    with pytest.raises(signing.SigningError, match="no signature"):
        signing.verify_manifest(unsigned)
    with pytest.raises(signing.SigningError, match="no signing.public_key"):
        signing.verify_manifest({**unsigned, "signature": "AAAA"})


def test_sign_manifest_requires_a_declared_key(example):
    pem = signing.generate_private_key_pem()
    bare = {k: v for k, v in example.items() if k not in ("signature", "signing")}
    with pytest.raises(signing.SigningError, match="no signing.public_key"):
        signing.sign_manifest(bare, pem)


def test_private_key_must_be_ed25519():
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    x_pem = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(signing.SigningError, match="not ed25519"):
        signing.public_key_from_private(x_pem)
    with pytest.raises(signing.SigningError, match="not ed25519"):
        signing.sign_bytes(b"x", x_pem)


def test_pin_store_unsigned_then_signed_then_forget(tmp_path, example):
    """An extension first installed unsigned may later go signed (that pins),
    and forget() is the explicit re-trust that resets the ratchet."""
    store = signing.PinStore(tmp_path / "pins.json")
    eid = ext_id(example)
    unsigned = {k: v for k, v in example.items() if k not in ("signature", "signing")}
    assert store.evaluate(eid, unsigned).action == "unsigned"
    assert store.evaluate(eid, unsigned).action == "unsigned"     # still allowed: never signed
    assert store.pinned_key(eid) is None and store.announced_key(eid) is None

    pem = signing.generate_private_key_pem()
    pub = signing.public_key_from_private(pem)
    pem2 = signing.generate_private_key_pem()
    pub2 = signing.public_key_from_private(pem2)
    assert store.evaluate(eid, _signed(example, pem, pub, next_key=pub2)).action == "pin"
    assert store.pinned_key(eid) == pub
    assert store.announced_key(eid) == pub2, "a first-use release may already announce a successor"
    # Ratchet engaged now.
    assert store.evaluate(eid, unsigned).action == "refuse"
    # forget() drops the pin AND the ratchet: the next unsigned install is fresh.
    store.forget(eid)
    assert store.pinned_key(eid) is None
    assert store.evaluate(eid, unsigned).action == "unsigned"
    store.forget("never/pinned")  # idempotent


def test_pin_store_commit_without_entry_writes_nothing(tmp_path):
    store = signing.PinStore(tmp_path / "pins.json")
    store.commit("a/b", signing.TrustDecision(True, "same-key"))
    assert not (tmp_path / "pins.json").exists()


def test_signature_present_without_key_is_refused(tmp_path, example):
    store = signing.PinStore(tmp_path / "pins.json")
    broken = {k: v for k, v in example.items() if k != "signing"}
    decision = store.decide(ext_id(example), broken)
    assert not decision.accepted and "without signing.public_key" in decision.reason


def test_pin_store_refuses_a_document_that_is_not_an_object(tmp_path):
    """A stray list/scalar must not be read as "nothing pinned" — that would
    silently disable TOFU for every extension."""
    path = tmp_path / "pins.json"
    for text in ("[]", "42", '"x"', "null"):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError, match="not a JSON object"):
            signing.PinStore(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        signing.PinStore(path)
    path.write_text("{}", encoding="utf-8")
    assert signing.PinStore(path).pinned_key("pub.test/x") is None
