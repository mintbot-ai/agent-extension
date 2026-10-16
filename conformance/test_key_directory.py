"""Raw key-directory constraints (optional adapter capability, 8.5/14.3)."""
import pytest

KEY = "ed25519:" + "A" * 43 + "="


@pytest.fixture
def directory_adapter(adapter):
    if not hasattr(adapter, "parse_key_directory"):
        pytest.skip("host does not expose raw key-directory filtering (optional)")
    return adapter


@pytest.mark.parametrize("name", ["mine", None])
@pytest.mark.parametrize("field,value", [
    ("extensions", None), ("extensions", "mine"), ("extensions", {}),
    ("extensions", ["mine", None]), ("extensions", ["mine", "Bad"]),
    ("roles", None), ("roles", "manifest"), ("roles", {}),
    ("roles", ["manifest", None]),
])
def test_malformed_constraints_never_authorize(directory_adapter, name, field, value):
    doc = {"keys": [{"public_key": KEY, field: value}]}
    try:
        keys = directory_adapter.parse_key_directory(doc, "pub.example", name, "manifest")
    except Exception:
        return  # Rejecting the whole malformed directory is also fail-closed.
    assert KEY not in keys


def test_absence_is_not_explicit_null(directory_adapter):
    doc = {"keys": [{"public_key": KEY}]}
    assert directory_adapter.parse_key_directory(doc, "pub.example", "mine", "manifest") == [KEY]
    assert directory_adapter.parse_key_directory(doc, "pub.example", "mine", "entitlement") == []


def test_online_key_is_not_a_manifest_key(directory_adapter):
    doc = {"keys": [{"public_key": KEY, "roles": ["entitlement"], "extensions": ["mine"]}]}
    assert directory_adapter.parse_key_directory(doc, "pub.example", "mine", "manifest") == []
    assert directory_adapter.parse_key_directory(doc, "pub.example", "mine", "entitlement") == [KEY]
