"""The worked example is the spec's living fixture: it must validate against
both schemas AND the reference implementation, verify out of the box, and
its key directory must vouch for the key it is signed with — the same checks
CI runs through the CLI."""

import json
from pathlib import Path

import pytest

from axp import manifest, signing

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "sample-memory"
PAID = REPO / "examples" / "paid-tool"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("schema_name,document", [
    ("agent-extension.schema.json", EXAMPLE / "agent-extension.json"),
    ("agent-extension-keys.schema.json", EXAMPLE / "agent-extension-keys.json"),
    ("agent-extension.schema.json", PAID / "agent-extension.json"),
    ("agent-extension-keys.schema.json", PAID / "agent-extension-keys.json"),
    ("agent-extension-entitlement.schema.json", PAID / "entitlement.json"),
])
def test_schemas_are_valid_and_accept_their_example(schema_name, document):
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load(REPO / "schema" / schema_name)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_load(document), schema)
    assert schema["$id"].endswith("-0.5.json")


def test_entitlement_schema_rejects_malformed_documents():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(_load(REPO / "schema" / "agent-extension-entitlement.schema.json"))
    good = _load(PAID / "entitlement.json")
    assert list(validator.iter_errors(good)) == []
    assert list(validator.iter_errors({**good, "kind": "agent-extension"}))
    assert list(validator.iter_errors({**good, "holder": "rsa:x"}))
    assert list(validator.iter_errors({k: v for k, v in good.items() if k != "valid_until"}))   # null, not absent
    assert list(validator.iter_errors({**good, "x-vendor": 1})) == []


def test_keys_schema_rejects_malformed_entries():
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load(REPO / "schema" / "agent-extension-keys.schema.json")
    validator = jsonschema.Draft202012Validator(schema)
    assert list(validator.iter_errors({"keys": []})) == []
    assert list(validator.iter_errors({"keys": [{"public_key": "rsa:x"}]}))
    assert list(validator.iter_errors({"publisher": "Bad.Example", "keys": []}))
    assert list(validator.iter_errors({"keys": [{"key_id": "no key"}]}))
    # Unknown fields are ignored (forward compatibility), like the manifest.
    assert list(validator.iter_errors({"keys": [], "x-vendor": 1})) == []


def test_example_verifies_and_key_directory_vouches_for_it():
    doc = _load(EXAMPLE / "agent-extension.json")
    summary = manifest.validate(doc)
    assert signing.verify_manifest(doc) is True
    listed = signing.parse_key_directory(
        _load(EXAMPLE / "agent-extension-keys.json"),
        publisher=summary["publisher"], name=summary["name"],
    )
    assert doc["signing"]["public_key"] in listed


def test_commerce_example_verifies_end_to_end():
    """The paid-tool fixture (SPEC 14): the manifest validates and verifies,
    its gated target is reported, the key directory separates the manifest
    key from the issuing key, the shipped entitlement verifies for the
    example host key and covers the shipped release, and the example host
    key can present it for the artifact."""
    from axp import entitlements
    doc = _load(PAID / "agent-extension.json")
    summary = manifest.validate(doc)
    assert signing.verify_manifest(doc) is True
    assert summary["commerce"] == {"entitlement": "required", "plans": ["pro-monthly", "lifetime", "trial"],
                                   "issuers": ["ext.example.com"], "payment": ["x402"],
                                   "gated_delivery": True}
    directory = _load(PAID / "agent-extension-keys.json")
    manifest_keys = signing.parse_key_directory(directory, publisher="ext.example.com", name="paid-tool")
    issuing_keys = signing.parse_key_directory(directory, publisher="ext.example.com", name="paid-tool",
                                               role=signing.ROLE_ENTITLEMENT)
    assert doc["signing"]["public_key"] in manifest_keys and doc["signing"]["public_key"] not in issuing_keys
    entitlement = _load(PAID / "entitlement.json")
    assert entitlement["signing"]["public_key"] in issuing_keys and entitlement["signing"]["public_key"] not in manifest_keys
    host_key = (PAID / "example-host.key").read_bytes()
    holder = entitlements.holder_from_private(host_key)
    verdict = entitlements.verify_entitlement(entitlement, extension=summary["ext_id"], holder=holder,
                                              issuer_keys=issuing_keys, issuers=summary["commerce"]["issuers"])
    assert verdict.valid and verdict.status == "valid"
    assert entitlements.covers_release(entitlement, doc)
    # The manifest key alone can never vouch for an entitlement.
    assert entitlements.verify_entitlement(entitlement, extension=summary["ext_id"], holder=holder,
                                           issuer_keys=manifest_keys).status == "untrusted_key"
    audience = doc["targets"][0]["delivery"]["url"]
    header = entitlements.authorization_header(entitlements.make_presentation(
        host_private_key_pem=host_key, audience=audience, entitlement=entitlement))
    assert entitlements.verify_presented_entitlement(header, audience=audience, extension=summary["ext_id"],
                                                     issuer_keys=issuing_keys).valid
    # The issuing key committed next to it really is the one the directory lists.
    assert signing.public_key_from_private((PAID / "example-issuing.key").read_bytes()) in issuing_keys
