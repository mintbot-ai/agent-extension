"""Directory security constraints must match their schema before selection."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from axp.signing import parse_key_directory

KEY = "ed25519:" + "A" * 43 + "="
SCHEMA = json.loads((Path(__file__).parents[1] / "schema/agent-extension-keys.schema.json").read_text())


@pytest.mark.parametrize("scope", [None, "mine", {}, False, 1, [None], ["mine", 1],
                                  ["mine", "Bad"], ["mine", "pub.example/"], ["mine", "a/b/c"]])
@pytest.mark.parametrize("name", ["mine", None])
def test_malformed_extension_scope_fails_closed(scope, name):
    doc = {"keys": [{"public_key": KEY, "extensions": scope}]}
    assert not Draft202012Validator(SCHEMA).is_valid(doc)
    assert parse_key_directory(doc, publisher="pub.example", name=name) == []


@pytest.mark.parametrize("scope,name,accepted", [
    ([], "mine", False), (["mine"], "mine", True),
    (["pub.example/mine"], "mine", True), (["mine"], "pub.example/mine", True),
    (["other.example/mine"], "mine", False), (["mine"], None, True),
])
def test_valid_extension_scope_schema_parity(scope, name, accepted):
    doc = {"keys": [{"public_key": KEY, "extensions": scope}]}
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert parse_key_directory(doc, publisher="pub.example", name=name) == ([KEY] if accepted else [])


@pytest.mark.parametrize("roles", [None, "manifest", {}, False, [None], ["manifest", None],
                                  ["manifest", {}], ["entitlement", 1]])
@pytest.mark.parametrize("name", ["mine", None])
@pytest.mark.parametrize("role", ["manifest", "entitlement"])
def test_malformed_roles_fail_closed(roles, name, role):
    doc = {"keys": [{"public_key": KEY, "roles": roles}]}
    assert not Draft202012Validator(SCHEMA).is_valid(doc)
    assert parse_key_directory(doc, publisher="pub.example", name=name, role=role) == []


@pytest.mark.parametrize("roles,accepted", [([], False), (["future"], False),
                                         (["manifest", "future"], True)])
def test_well_formed_roles_require_explicit_membership(roles, accepted):
    doc = {"keys": [{"public_key": KEY, "roles": roles}]}
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert parse_key_directory(doc, publisher="pub.example", name="mine") == ([KEY] if accepted else [])


def test_absent_constraints_keep_legacy_manifest_only_meaning():
    doc = {"keys": [{"public_key": KEY}]}
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert parse_key_directory(doc, publisher="pub.example", name="mine") == [KEY]
    assert parse_key_directory(doc, publisher="pub.example", name=None) == [KEY]
    assert parse_key_directory(doc, publisher="pub.example", name="mine", role="entitlement") == []
