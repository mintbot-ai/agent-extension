"""axp.signing — roundtrip, tamper, TOFU pinning, rotation, ratchet."""

import pytest

from axp import signing
from axp.manifest import ext_id


@pytest.fixture(scope="module")
def keypair():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture(scope="module")
def keypair2():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


def _signed(example, keypair, **signing_extra):
    pem, pub = keypair
    example = dict(example)
    example["signing"] = {"public_key": pub, "key_id": "test", "next_key": None, **signing_extra}
    example.pop("signature", None)
    return signing.sign_manifest(example, pem)


def test_sign_verify_roundtrip_and_tamper(example, keypair):
    signed = _signed(example, keypair)
    assert signing.verify_manifest(signed) is True
    tampered = dict(signed)
    tampered["identity"] = {**signed["identity"], "version": "9.9.9"}
    assert signing.verify_manifest(tampered) is False


def test_sign_refuses_mismatched_declared_key(example, keypair, keypair2):
    example = dict(example)
    example["signing"] = {"public_key": keypair2[1]}
    with pytest.raises(signing.SigningError, match="does not match this private key"):
        signing.sign_manifest(example, keypair[0])


def test_pin_store_full_lifecycle(tmp_path, example, keypair, keypair2):
    store = signing.PinStore(tmp_path / "pins.json")
    eid = ext_id(example)
    pem1, pub1 = keypair
    pem2, pub2 = keypair2

    # 1. First use pins the key.
    v1 = _signed(example, keypair)
    assert store.evaluate(eid, v1).action == "pin"
    assert store.pinned_key(eid) == pub1

    # 2. Same-key update verifies against the pin; a different unpinned key refuses.
    v2 = _signed(example, keypair)
    assert store.evaluate(eid, v2).action == "same-key"
    stranger = _signed(example, keypair2)
    decision = store.evaluate(eid, stranger)
    assert not decision.accepted and "without an announced rotation" in decision.reason

    # 3. Ratchet: unsigned after signed is refused.
    unsigned = {k: v for k, v in example.items() if k not in ("signing", "signature")}
    decision = store.evaluate(eid, unsigned)
    assert not decision.accepted and "ratchet" in decision.reason

    # 4. Announce, then dual-signed rotation moves the pin.
    announce = _signed(example, keypair, next_key=pub2)
    assert store.evaluate(eid, announce).action == "announce"
    rotation = _signed(example, keypair2)                     # signature by the NEW key
    from axp import jcs
    rotation["signature_prev"] = signing.sign_bytes(jcs.signing_input(rotation), pem1)
    assert store.evaluate(eid, rotation).action == "rotate"
    assert store.pinned_key(eid) == pub2

    # 5. Rotation without signature_prev (or to an unannounced key) refuses.
    surprise = _signed(example, keypair)
    decision = store.evaluate(eid, surprise)
    assert not decision.accepted

    # 6. State survives a reload.
    reloaded = signing.PinStore(tmp_path / "pins.json")
    assert reloaded.pinned_key(eid) == pub2


def test_pin_store_unsigned_policy(tmp_path, example):
    store = signing.PinStore(tmp_path / "pins.json")
    unsigned = {k: v for k, v in example.items() if k not in ("signing", "signature")}
    eid = ext_id(example)
    assert store.evaluate(eid, unsigned, allow_unsigned=False).accepted is False
    assert store.evaluate(eid, unsigned).action == "unsigned"


def test_decide_is_pure_and_commit_persists(tmp_path, example, keypair):
    store = signing.PinStore(tmp_path / "pins.json")
    eid = ext_id(example)
    decision = store.decide(eid, _signed(example, keypair))
    assert decision.accepted and decision.action == "pin" and decision.entry
    assert store.pinned_key(eid) is None and not (tmp_path / "pins.json").exists()
    store.commit(eid, decision)
    assert store.pinned_key(eid) == keypair[1]
    with pytest.raises(signing.SigningError):
        store.commit(eid, signing.TrustDecision(False, "refuse", "nope"))


def test_key_directory_gates_rotation_and_enables_recovery(tmp_path, example, keypair, keypair2):
    from axp import jcs
    store = signing.PinStore(tmp_path / "pins.json")
    eid = ext_id(example)
    pem1, pub1 = keypair
    pem2, pub2 = keypair2
    assert store.evaluate(eid, _signed(example, keypair)).action == "pin"

    # Announce + dual-sign, but the publisher directory does NOT list the new
    # key -> a stolen key alone cannot move the pin.
    assert store.evaluate(eid, _signed(example, keypair, next_key=pub2)).action == "announce"
    rotation = _signed(example, keypair2)
    rotation["signature_prev"] = signing.sign_bytes(jcs.signing_input(rotation), pem1)
    refused = store.decide(eid, rotation, directory_keys=[pub1])
    assert not refused.accepted and "key directory" in refused.reason
    # Listed -> accepted; not consulted (None) -> classic behaviour.
    assert store.decide(eid, rotation, directory_keys=[pub1, pub2]).action == "rotate"
    assert store.decide(eid, rotation).action == "rotate"

    # Lost key: no announcement, directory now lists only the new key.
    store = signing.PinStore(tmp_path / "pins2.json")
    assert store.evaluate(eid, _signed(example, keypair)).action == "pin"
    fresh = _signed(example, keypair2)
    plain = store.decide(eid, fresh)
    assert not plain.accepted and plain.action == "refuse"
    offered = store.decide(eid, fresh, directory_keys=[pub2])
    assert not offered.accepted and offered.action == "recover"   # host must ask the user
    granted = store.decide(eid, fresh, directory_keys=[pub2], allow_recovery=True)
    assert granted.accepted and granted.action == "recover"
    # Directory still vouching for the pinned key -> NOT a recovery, a compromise.
    both = store.decide(eid, fresh, directory_keys=[pub1, pub2], allow_recovery=True)
    assert not both.accepted and both.action == "refuse"


def test_first_use_honours_directory_when_consulted(tmp_path, example, keypair, keypair2):
    store = signing.PinStore(tmp_path / "pins.json")
    eid = ext_id(example)
    decision = store.decide(eid, _signed(example, keypair), directory_keys=[keypair2[1]])
    assert not decision.accepted and "not listed" in decision.reason


def test_parse_key_directory():
    doc = {"publisher": "pub.example", "keys": [
        {"public_key": "ed25519:" + "A" * 43 + "=", "key_id": "a"},
        {"public_key": "ed25519:" + "B" * 43 + "=", "extensions": ["other"]},
        {"public_key": "ed25519:" + "C" * 43 + "=", "revoked": True},
        {"public_key": "rsa:nope"},
        "garbage",
    ]}
    assert signing.parse_key_directory(doc, publisher="pub.example", name="mine") == ["ed25519:" + "A" * 43 + "="]
    with pytest.raises(signing.SigningError):
        signing.parse_key_directory(doc, publisher="evil.example", name="mine")
    with pytest.raises(signing.SigningError):
        signing.parse_key_directory(["not", "a", "directory"], publisher="pub.example", name="mine")
    assert signing.key_directory_url("pub.example") == "https://pub.example/.well-known/agent-extension-keys.json"
