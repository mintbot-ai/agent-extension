"""axp.entitlements — issue / verify, time status, update coverage, holder
presentations (the AXP-Entitlement header), the store, and the key-role
separation that keeps an issuing key away from manifests (SPEC 14)."""

from datetime import datetime, timedelta, timezone

import pytest

from axp import entitlements as e
from axp import jcs, signing

EXT = "ext.example.com/sample-memory"
ISSUER = "ext.example.com"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
ARTIFACT = "https://ext.example.com/sample-memory-0.3.0.tar.gz"


@pytest.fixture(scope="module")
def issuing():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture(scope="module")
def host():
    pem = signing.generate_private_key_pem()
    return pem, e.holder_from_private(pem)


@pytest.fixture(scope="module")
def other_host():
    pem = signing.generate_private_key_pem()
    return pem, e.holder_from_private(pem)


def _issue(issuing, host, **kw):
    defaults: dict = dict(extension=EXT, holder=host[1], plan="pro", issuer=ISSUER,
                    private_key_pem=issuing[0], key_id="issuing-2026", issued_at=NOW)
    defaults.update(kw)
    return e.issue(**defaults)


def _verify(doc, issuing, host, **kw):
    defaults: dict = dict(extension=EXT, holder=host[1], issuer_keys=[issuing[1]], issuers=[ISSUER], now=NOW)
    defaults.update(kw)
    return e.verify_entitlement(doc, **defaults)


# --- issue / verify -----------------------------------------------------------

def test_issue_verify_roundtrip_and_shape(issuing, host):
    doc = _issue(issuing, host, valid_until=NOW + timedelta(days=30), updates_until=None, serial="S-1")
    assert doc["kind"] == e.ENTITLEMENT_KIND and doc["spec_version"] == "0.5"
    assert doc["valid_until"] == "2026-11-15T12:00:00Z" and doc["updates_until"] is None
    assert doc["signing"] == {"public_key": issuing[1], "key_id": "issuing-2026"}
    verdict = _verify(doc, issuing, host)
    assert verdict.valid and verdict.status == "valid" and verdict.entitlement == doc
    # Perpetual use: both bounds null.
    perpetual = _issue(issuing, host)
    assert perpetual["valid_until"] is None and perpetual["updates_until"] is None
    assert _verify(perpetual, issuing, host, now=NOW + timedelta(days=5000)).valid
    # A random serial is generated when none is given.
    assert perpetual["serial"] and perpetual["serial"] != _issue(issuing, host)["serial"]


def test_issue_accepts_iso_strings_and_rejects_garbage(issuing, host):
    doc = _issue(issuing, host, valid_until="2027-01-01T00:00:00Z", updates_until="2026-12-01T00:00:00+02:00")
    assert doc["valid_until"] == "2027-01-01T00:00:00Z"
    with pytest.raises(e.EntitlementError, match="ISO-8601"):
        _issue(issuing, host, valid_until="next week")
    with pytest.raises(e.EntitlementError, match="extension"):
        _issue(issuing, host, extension="no-slash")
    with pytest.raises(e.EntitlementError, match="holder"):
        _issue(issuing, host, holder="rsa:nope")


def test_sign_refuses_mismatched_declared_key(issuing, host, other_host):
    doc = dict(_issue(issuing, host))
    doc["signing"] = {"public_key": other_host[1]}
    with pytest.raises(e.EntitlementError, match="does not match this private key"):
        e.sign_entitlement(doc, issuing[0])
    del doc["signing"]
    with pytest.raises(e.EntitlementError, match="signing.public_key"):
        e.sign_entitlement(doc, issuing[0])


@pytest.mark.parametrize("mutate,status,fragment", [
    (lambda d: d.__setitem__("plan", "enterprise"), "bad_signature", "does not verify"),
    (lambda d: d.__setitem__("extension", "ext.example.com/other"), "wrong_extension", "not ext.example.com/sample-memory"),
    (lambda d: d.__setitem__("issuer", "market.example"), "untrusted_issuer", "not an issuer the manifest names"),
    (lambda d: d.pop("serial"), "malformed", "serial"),
    (lambda d: d.__setitem__("kind", "agent-extension"), "malformed", "kind"),
    (lambda d: d.pop("valid_until"), "malformed", "valid_until"),
    (lambda d: d.__setitem__("signature", "c2ln"), "bad_signature", "expected 64"),
])
def test_verify_refusals(issuing, host, mutate, status, fragment):
    doc = dict(_issue(issuing, host))
    mutate(doc)
    verdict = _verify(doc, issuing, host)
    assert not verdict.valid and verdict.status == status and fragment in verdict.reason


def test_verify_binds_holder_and_issuer_keys(issuing, host, other_host):
    doc = _issue(issuing, host)
    assert _verify(doc, issuing, host, holder=other_host[1]).status == "wrong_holder"
    assert _verify(doc, issuing, host, holder=None).valid        # an issuer inspecting its own records
    stranger = _verify(doc, issuing, host, issuer_keys=[other_host[1]])
    assert stranger.status == "untrusted_key" and not stranger.valid
    assert _verify(doc, issuing, host, issuer_keys=[]).status == "untrusted_key"
    # A document signed by a key that is NOT the declared signing key.
    forged = {k: v for k, v in doc.items() if k != "signature"}
    forged["signature"] = signing.sign_bytes(jcs.canonicalize(forged), other_host[0])
    assert _verify(forged, issuing, host).status == "bad_signature"
    # Issuers not consulted (None) -> only the keys decide.
    assert _verify(doc, issuing, host, issuers=None).valid
    assert e.verify_entitlement("not a dict", extension=EXT, holder=None, issuer_keys=[]).status == "malformed"


# --- time ---------------------------------------------------------------------

def test_time_status_valid_grace_expired_future(issuing, host):
    doc = _issue(issuing, host, valid_until=NOW + timedelta(days=30))
    assert e.time_status(doc, now=NOW) == "valid"
    assert e.time_status(doc, now=NOW + timedelta(days=30)) == "valid"           # inclusive
    assert e.time_status(doc, now=NOW + timedelta(days=33)) == "grace"
    assert e.time_status(doc, now=NOW + timedelta(days=37)) == "grace"           # 7-day default, inclusive
    assert e.time_status(doc, now=NOW + timedelta(days=38)) == "expired"
    assert e.time_status(doc, now=NOW + timedelta(days=33), grace_days=0) == "expired"
    assert e.time_status(doc, now=NOW - timedelta(days=1)) == "not_yet_valid"
    assert e.time_status(doc, now=NOW - timedelta(minutes=4)) == "valid"        # clock skew tolerated
    verdict = _verify(doc, issuing, host, now=NOW + timedelta(days=33))
    assert verdict.valid and verdict.status == "grace" and "grace" in verdict.reason
    verdict = _verify(doc, issuing, host, now=NOW + timedelta(days=60))
    assert not verdict.valid and verdict.status == "expired"
    assert _verify(doc, issuing, host, now=NOW - timedelta(days=1)).status == "not_yet_valid"


def test_covers_release_uses_updates_until(issuing, host):
    doc = _issue(issuing, host, updates_until=NOW + timedelta(days=365))
    inside = {"release": {"published_at": "2027-06-01T00:00:00Z"}}
    outside = {"release": {"published_at": "2027-12-01T00:00:00Z"}}
    assert e.covers_release(doc, inside) and not e.covers_release(doc, outside)
    assert e.covers_release(doc, inside["release"])                 # a bare release block works too
    assert e.covers_release(doc, {"release": {}})                   # undated release: cannot be placed
    assert e.covers_release(doc, {})
    assert e.covers_release(_issue(issuing, host), outside)         # updates_until null = everything


# --- presentations ------------------------------------------------------------

def test_presentation_roundtrip_through_the_header(issuing, host):
    doc = _issue(issuing, host)
    presentation = e.make_presentation(host_private_key_pem=host[0], audience=ARTIFACT, entitlement=doc, now=NOW)
    assert presentation["kind"] == e.PRESENTATION_KIND and presentation["holder"] == host[1]
    assert presentation["extension"] == EXT and presentation["expires_at"] == "2026-10-16T12:05:00Z"
    header = e.authorization_header(presentation)
    assert header.startswith("AXP-Entitlement ") and "=" not in header.split(" ", 1)[1]
    decoded = e.parse_authorization_header(header)
    assert decoded == presentation
    assert e.parse_authorization_header("axp-entitlement " + header.split(" ", 1)[1]) == presentation
    assert e.verify_presentation(header, audience=ARTIFACT, now=NOW + timedelta(minutes=2)) == presentation
    verdict = e.verify_presented_entitlement(header, audience=ARTIFACT, extension=EXT,
                                             issuer_keys=[issuing[1]], issuers=[ISSUER], now=NOW)
    assert verdict.valid and verdict.entitlement == doc


def test_presentation_refusals(issuing, host, other_host):
    doc = _issue(issuing, host)
    presentation = e.make_presentation(host_private_key_pem=host[0], audience=ARTIFACT, entitlement=doc, now=NOW)
    header = e.authorization_header(presentation)
    with pytest.raises(e.EntitlementError, match="addressed to"):
        e.verify_presentation(header, audience=ARTIFACT + "?x=1", now=NOW)
    with pytest.raises(e.EntitlementError, match="expired"):
        e.verify_presentation(header, audience=ARTIFACT, now=NOW + timedelta(minutes=11))
    with pytest.raises(e.EntitlementError, match="future"):
        e.verify_presentation(header, audience=ARTIFACT, now=NOW - timedelta(minutes=10))
    tampered = dict(presentation)
    tampered["audience"] = ARTIFACT + "?x=1"
    with pytest.raises(e.EntitlementError, match="holder key"):
        e.verify_presentation(tampered, audience=ARTIFACT + "?x=1", now=NOW)
    # A lifetime longer than the cap is refused even when still current.
    long = {k: v for k, v in presentation.items() if k != "signature"}
    long["expires_at"] = "2026-10-16T13:00:00Z"
    long["signature"] = signing.sign_bytes(jcs.canonicalize(long), host[0])
    with pytest.raises(e.EntitlementError, match="lifetime"):
        e.verify_presentation(long, audience=ARTIFACT, now=NOW)
    # Someone else's entitlement cannot be presented, even by a valid holder key.
    with pytest.raises(e.EntitlementError, match="another host key"):
        e.make_presentation(host_private_key_pem=other_host[0], audience=ARTIFACT, entitlement=doc, now=NOW)
    with pytest.raises(e.EntitlementError, match="https://"):
        e.make_presentation(host_private_key_pem=host[0], audience="http://x/a.tgz", entitlement=doc, now=NOW)
    with pytest.raises(e.EntitlementError, match="extension"):
        e.make_presentation(host_private_key_pem=host[0], audience=ARTIFACT, now=NOW)
    with pytest.raises(e.EntitlementError, match="ttl_seconds"):
        e.make_presentation(host_private_key_pem=host[0], audience=ARTIFACT, entitlement=doc, now=NOW, ttl_seconds=3600)
    for bad in ("Bearer abc", "AXP-Entitlement", "AXP-Entitlement !!!", "AXP-Entitlement " + e._b64url(b"[1]")):
        with pytest.raises(e.EntitlementError):
            e.parse_authorization_header(bad)


def test_presentation_without_entitlement_is_a_request(issuing, host):
    refresh = "https://api.ext.example.com/axp/entitlements"
    request = e.make_presentation(host_private_key_pem=host[0], audience=refresh, extension=EXT, now=NOW)
    assert "entitlement" not in request
    verdict = e.verify_presented_entitlement(e.authorization_header(request), audience=refresh,
                                             extension=EXT, issuer_keys=[issuing[1]], now=NOW)
    assert not verdict.valid and verdict.status == "no_entitlement"
    # Wrong audience / extension are refused before any entitlement logic runs.
    bad = e.verify_presented_entitlement(request, audience=ARTIFACT, extension=EXT, issuer_keys=[issuing[1]], now=NOW)
    assert bad.status == "malformed" and "presentation" in bad.reason
    other = e.verify_presented_entitlement(request, audience=refresh, extension="ext.example.com/other",
                                           issuer_keys=[issuing[1]], now=NOW)
    assert other.status == "wrong_extension"


def test_presented_entitlement_must_match_presentation(issuing, host, other_host):
    doc = _issue(issuing, host)
    presentation = {k: v for k, v in e.make_presentation(
        host_private_key_pem=host[0], audience=ARTIFACT, entitlement=doc, now=NOW).items() if k != "signature"}
    swapped = dict(presentation, entitlement=_issue(issuing, other_host))
    swapped["signature"] = signing.sign_bytes(jcs.canonicalize(swapped), host[0])
    with pytest.raises(e.EntitlementError, match="another holder"):
        e.verify_presentation(swapped, audience=ARTIFACT, now=NOW)
    # Even a correctly bound entitlement fails when the issuer's key is unknown to this server.
    verdict = e.verify_presented_entitlement(
        e.make_presentation(host_private_key_pem=host[0], audience=ARTIFACT, entitlement=doc, now=NOW),
        audience=ARTIFACT, extension=EXT, issuer_keys=[other_host[1]], now=NOW)
    assert verdict.status == "untrusted_key"


# --- key roles ----------------------------------------------------------------

def test_key_directory_roles_separate_manifest_and_issuing_keys():
    manifest_key = "ed25519:" + "A" * 43 + "="
    issuing_key = "ed25519:" + "B" * 43 + "="
    both = "ed25519:" + "C" * 43 + "="
    doc = {"publisher": "pub.example", "keys": [
        {"public_key": manifest_key, "extensions": ["mine"]},
        {"public_key": issuing_key, "extensions": ["mine"], "roles": ["entitlement"]},
        {"public_key": both, "roles": ["manifest", "entitlement"]},
    ]}
    assert signing.parse_key_directory(doc, publisher="pub.example", name="mine") == [manifest_key, both]
    assert signing.parse_key_directory(doc, publisher="pub.example", name="mine", role="entitlement") == [issuing_key, both]
    with pytest.raises(signing.SigningError, match="unknown key role"):
        signing.parse_key_directory(doc, publisher="pub.example", name="mine", role="billing")


def test_key_directory_scopes_by_bare_name_or_full_id():
    key = "ed25519:" + "D" * 43 + "="
    # A marketplace issuing for another publisher's extension lists the full id.
    market = {"publisher": "market.example", "keys": [
        {"public_key": key, "roles": ["entitlement"], "extensions": ["ext.example.com/paid-tool", "own-thing"]},
    ]}
    assert signing.parse_key_directory(market, publisher="market.example", name="ext.example.com/paid-tool",
                                       role="entitlement") == [key]
    assert signing.parse_key_directory(market, publisher="market.example", name="paid-tool", role="entitlement") == []
    assert signing.parse_key_directory(market, publisher="market.example", name="own-thing", role="entitlement") == [key]
    assert signing.parse_key_directory(market, publisher="market.example", name="market.example/own-thing",
                                       role="entitlement") == [key]
    assert signing.parse_key_directory(market, publisher="market.example", name=None, role="entitlement") == [key]
    assert signing.parse_key_directory(market, publisher="market.example", name="own-thing") == []   # not a manifest key


# --- store --------------------------------------------------------------------

def test_store_roundtrip_and_guards(tmp_path, issuing, host):
    store = e.EntitlementStore(tmp_path / "ent" / "entitlements.json")
    assert store.get(EXT) is None and store.extensions() == []
    doc = _issue(issuing, host)
    store.put(EXT, doc)
    assert store.get(EXT) == doc and store.extensions() == [EXT]
    assert oct((tmp_path / "ent" / "entitlements.json").stat().st_mode & 0o777) == "0o600"
    with pytest.raises(e.EntitlementError, match="not ext.example.com/other"):
        store.put("ext.example.com/other", doc)
    with pytest.raises(e.EntitlementError):
        store.put(EXT, {"kind": "nope"})
    reloaded = e.EntitlementStore(tmp_path / "ent" / "entitlements.json")
    assert reloaded.get(EXT) == doc
    reloaded.remove(EXT)
    reloaded.remove(EXT)   # idempotent
    assert e.EntitlementStore(tmp_path / "ent" / "entitlements.json").get(EXT) is None
    (tmp_path / "bad.json").write_text("[]")
    with pytest.raises(ValueError):
        e.EntitlementStore(tmp_path / "bad.json")
