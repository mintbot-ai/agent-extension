"""Commerce capability (SPEC section 14): a host that installs sold extensions
checks entitlements the same way everywhere.

Optional — hosts without the ``verify_entitlement`` adapter method skip this
module. Signed documents are generated at run time with real ed25519 keys.
"""

from datetime import datetime, timedelta, timezone

import pytest

from axp import entitlements, jcs, signing
from axp.manifest import ext_id

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
ISSUER = "ext.example.com"


@pytest.fixture(scope="module")
def issuing_key():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture(scope="module")
def manifest_key():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture(scope="module")
def host_key():
    pem = signing.generate_private_key_pem()
    return pem, entitlements.holder_from_private(pem)


@pytest.fixture
def commerce(adapter, example):
    if not hasattr(adapter, "verify_entitlement"):
        pytest.skip("host does not implement entitlement checks (optional)")
    example["commerce"] = {"entitlement": "required", "issuers": [ISSUER]}
    return adapter


@pytest.fixture
def directory(manifest_key, issuing_key):
    return {"publisher": ISSUER, "keys": [
        {"public_key": manifest_key[1], "extensions": ["sample-memory"]},
        {"public_key": issuing_key[1], "extensions": ["sample-memory"], "roles": ["entitlement"]},
    ]}


def _entitlement(issuing_key, host_key, example, **kw):
    defaults: dict = dict(extension=ext_id(example), holder=host_key[1], plan="pro", issuer=ISSUER,
                          private_key_pem=issuing_key[0], issued_at=NOW)
    defaults.update(kw)
    return entitlements.issue(**defaults)


def test_valid_entitlement_is_accepted(commerce, example, issuing_key, host_key, directory):
    doc = _entitlement(issuing_key, host_key, example, valid_until=NOW + timedelta(days=30))
    assert commerce.verify_entitlement(example, doc, host_key[1], directory, NOW) == (True, "valid")
    perpetual = _entitlement(issuing_key, host_key, example)
    assert commerce.verify_entitlement(example, perpetual, host_key[1], directory, NOW + timedelta(days=3650))[0]


def test_grace_then_expiry(commerce, example, issuing_key, host_key, directory):
    doc = _entitlement(issuing_key, host_key, example, valid_until=NOW + timedelta(days=30))
    accepted, status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW + timedelta(days=33))
    assert accepted and status == "grace"
    accepted, status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW + timedelta(days=60))
    assert not accepted and status == "expired"


def test_entitlement_is_bound_to_the_host_key(commerce, example, issuing_key, host_key, directory):
    other = entitlements.holder_from_private(signing.generate_private_key_pem())
    doc = _entitlement(issuing_key, host_key, example)
    accepted, status = commerce.verify_entitlement(example, doc, other, directory, NOW)
    assert not accepted and status == "wrong_holder"


def test_entitlement_for_another_extension_is_refused(commerce, example, issuing_key, host_key, directory):
    doc = _entitlement(issuing_key, host_key, example, extension="ext.example.com/other")
    accepted, status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW)
    assert not accepted and status == "wrong_extension"


def test_tampered_entitlement_is_refused(commerce, example, issuing_key, host_key, directory):
    doc = dict(_entitlement(issuing_key, host_key, example, valid_until=NOW + timedelta(days=1)))
    doc["valid_until"] = "2099-01-01T00:00:00Z"
    accepted, _status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW)
    assert not accepted


def test_manifest_key_cannot_vouch_for_entitlements(commerce, example, manifest_key, host_key, directory):
    """Role separation (14.3): the offline manifest key is listed without
    roles and therefore never issues entitlements, even though it is the
    publisher's own key and the signature is genuine."""
    doc = _entitlement(manifest_key, host_key, example)
    accepted, status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW)
    assert not accepted and status == "untrusted_key"


def test_issuing_key_cannot_move_the_manifest_pin(adapter, example, manifest_key, issuing_key, directory):
    """The converse (14.3, 8.5): a stolen online issuing key is listed in the
    directory, yet a host consulting that directory must refuse a rotation
    to it. Runs on any Trusted host with directory support."""
    if not hasattr(adapter, "evaluate_trust_with_directory"):
        pytest.skip("host does not implement key-directory cross-checks (optional)")
    eid = ext_id(example)
    base = {k: v for k, v in example.items() if k not in ("signature", "signature_prev")}
    base["signing"] = {"public_key": manifest_key[1], "key_id": "m", "next_key": None}
    assert adapter.evaluate_trust(eid, signing.sign_manifest(base, manifest_key[0]))[0]
    base["signing"]["next_key"] = issuing_key[1]
    assert adapter.evaluate_trust(eid, signing.sign_manifest(base, manifest_key[0]))[1] == "announce"
    rotation = dict(base, signing={"public_key": issuing_key[1], "key_id": "stolen", "next_key": None})
    rotation = signing.sign_manifest(rotation, issuing_key[0])
    rotation["signature_prev"] = signing.sign_bytes(jcs.signing_input(rotation), manifest_key[0])
    manifest_keys = signing.parse_key_directory(directory, publisher=ISSUER, name="sample-memory")
    accepted, action = adapter.evaluate_trust_with_directory(eid, rotation, manifest_keys)
    assert not accepted and action == "refuse"


def test_entitlement_from_an_unlisted_issuer_is_refused(commerce, example, issuing_key, host_key, directory):
    doc = _entitlement(issuing_key, host_key, example, issuer="market.example")
    accepted, status = commerce.verify_entitlement(example, doc, host_key[1], directory, NOW)
    assert not accepted and status == "untrusted_issuer"


def test_update_coverage_follows_updates_until(example, issuing_key, host_key):
    """14.7: a one-time purchase with an update window keeps running for ever
    but is not entitled to releases published after the window."""
    doc = _entitlement(issuing_key, host_key, example, updates_until=NOW + timedelta(days=365))
    assert entitlements.covers_release(doc, {"release": {"published_at": "2027-01-01T00:00:00Z"}})
    assert not entitlements.covers_release(doc, {"release": {"published_at": "2028-01-01T00:00:00Z"}})
    assert entitlements.time_status(doc, now=NOW + timedelta(days=5000)) == "valid"
