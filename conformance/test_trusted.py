"""Trusted profile (SPEC §11): TOFU pinning, rotation, ratchet (§8).

Signed scenario manifests are generated at run time with real ed25519 keys —
static fixtures cannot carry valid signatures across key regenerations.
"""

import pytest

from axp import jcs, signing
from axp.manifest import ext_id


@pytest.fixture(scope="module")
def key_a():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture(scope="module")
def key_b():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


def _signed(example, key, *, next_key=None, version=None):
    pem, pub = key
    out = dict(example)
    if version:
        out["identity"] = {**out["identity"], "version": version}
    out["signing"] = {"public_key": pub, "key_id": "conformance", "next_key": next_key}
    out.pop("signature", None)
    out.pop("signature_prev", None)
    return signing.sign_manifest(out, pem)


def _unsigned(example):
    return {k: v for k, v in example.items() if k not in ("signing", "signature", "signature_prev")}


def test_first_use_pins_and_same_key_updates_pass(adapter, example, key_a):
    eid = ext_id(example)
    accepted, action = adapter.evaluate_trust(eid, _signed(example, key_a))
    assert accepted and action == "pin"
    accepted, action = adapter.evaluate_trust(eid, _signed(example, key_a, version="0.3.1"))
    assert accepted and action == "same-key"


def test_key_change_without_rotation_refuses(adapter, example, key_a, key_b):
    eid = ext_id(example)
    assert adapter.evaluate_trust(eid, _signed(example, key_a))[0]
    accepted, action = adapter.evaluate_trust(eid, _signed(example, key_b))
    assert not accepted and action == "refuse"


def test_signed_then_unsigned_ratchet(adapter, example, key_a):
    eid = ext_id(example)
    assert adapter.evaluate_trust(eid, _signed(example, key_a))[0]
    accepted, action = adapter.evaluate_trust(eid, _unsigned(example))
    assert not accepted and action == "refuse"


def test_tampered_manifest_refuses(adapter, example, key_a):
    eid = ext_id(example)
    tampered = _signed(example, key_a)
    tampered["identity"] = {**tampered["identity"], "version": "6.6.6"}
    accepted, _action = adapter.evaluate_trust(eid, tampered)
    assert not accepted


def test_announce_then_dual_signed_rotation(adapter, example, key_a, key_b):
    eid = ext_id(example)
    pem_a, _pub_a = key_a
    assert adapter.evaluate_trust(eid, _signed(example, key_a))[0]

    accepted, action = adapter.evaluate_trust(eid, _signed(example, key_a, next_key=key_b[1]))
    assert accepted and action == "announce"

    # Rotation without signature_prev must refuse …
    bare = _signed(example, key_b, version="0.4.0")
    accepted, _action = adapter.evaluate_trust(eid, bare)
    assert not accepted

    # … the dual-signed release moves the pin …
    rotation = _signed(example, key_b, version="0.4.0")
    rotation["signature_prev"] = signing.sign_bytes(jcs.signing_input(rotation), pem_a)
    accepted, action = adapter.evaluate_trust(eid, rotation)
    assert accepted and action == "rotate"

    # … and the old key no longer signs updates.
    accepted, _action = adapter.evaluate_trust(eid, _signed(example, key_a, version="0.4.1"))
    assert not accepted


def test_rotation_to_a_key_the_publisher_directory_does_not_list_is_refused(adapter, example, key_a, key_b):
    """SPEC section 8.5: when the directory is consulted, a rotation may only
    move the pin to a key the publisher lists. A stolen signing key alone
    can no longer take an extension over."""
    if not hasattr(adapter, "evaluate_trust_with_directory"):
        pytest.skip("host does not implement key-directory cross-checks (optional)")
    eid = ext_id(example)
    pem_a, pub_a = key_a
    assert adapter.evaluate_trust(eid, _signed(example, key_a))[0]
    assert adapter.evaluate_trust(eid, _signed(example, key_a, next_key=key_b[1]))[1] == "announce"
    rotation = _signed(example, key_b, version="0.4.0")
    rotation["signature_prev"] = signing.sign_bytes(jcs.signing_input(rotation), pem_a)
    accepted, action = adapter.evaluate_trust_with_directory(eid, rotation, [pub_a])
    assert not accepted and action == "refuse"
    accepted, action = adapter.evaluate_trust_with_directory(eid, rotation, [pub_a, key_b[1]])
    assert accepted and action == "rotate"
