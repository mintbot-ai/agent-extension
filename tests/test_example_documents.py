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


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("schema_name,document_name", [
    ("agent-extension.schema.json", "agent-extension.json"),
    ("agent-extension-keys.schema.json", "agent-extension-keys.json"),
])
def test_schemas_are_valid_and_accept_their_example(schema_name, document_name):
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load(REPO / "schema" / schema_name)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_load(EXAMPLE / document_name), schema)
    assert schema["$id"].endswith("-0.4.json")


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
