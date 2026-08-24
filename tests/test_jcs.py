"""axp.jcs — canonicalization vectors (RFC 8785 subset)."""

import pytest

from axp import jcs


def test_objects_sort_by_utf16_code_units():
    # RFC 8785 §3.2.3 example ordering: literals, digits, uppercase,
    # lowercase, and the supplementary-plane character (surrogates) BEFORE
    # U+E000-range privates — the case where UTF-16 and code-point order differ.
    value = {"\u20ac": "Euro Sign", "\r": "CR", "1": "One",
             "\U0001f602": "Smiley", "\u00f6": "Latin Small Letter O With Diaeresis",
             "\ufb33": "Hebrew Letter Dalet With Dagesh", "</script>": "Browser Challenge"}
    out = jcs.canonicalize(value).decode()
    order = ["CR", "One", "Browser Challenge", "Latin Small", "Euro Sign", "Smiley", "Hebrew"]
    positions = [out.index(label) for label in order]
    assert positions == sorted(positions)


def test_string_escaping_matches_rfc():
    assert jcs.canonicalize("a\u0008b\tc\nd\u000ce\rf\"g\\h\u0001i") == (
        b'"a\\bb\\tc\\nd\\fe\\rf\\\"g\\\\h\\u0001i"'
    )
    # Non-ASCII stays literal (UTF-8), not \u-escaped.
    assert jcs.canonicalize("õäöü") == '"õäöü"'.encode()


def test_scalars_and_nesting():
    assert jcs.canonicalize({"b": [True, False, None, 42], "a": {}}) == b'{"a":{},"b":[true,false,null,42]}'
    assert jcs.canonicalize(0) == b"0" and jcs.canonicalize(-7) == b"-7"


def test_floats_and_unsafe_ints_are_refused():
    with pytest.raises(jcs.JCSError, match="non-integer numbers"):
        jcs.canonicalize({"x": 1.5})
    with pytest.raises(jcs.JCSError, match="IEEE-754"):
        jcs.canonicalize(2**53 + 1)
    assert jcs.canonicalize(2**53) == str(2**53).encode()


def test_signing_input_strips_signatures_only():
    manifest = {"kind": "agent-extension", "signature": "sig", "signature_prev": "old", "z": 1}
    assert jcs.signing_input(manifest) == b'{"kind":"agent-extension","z":1}'


def test_nested_and_empty_containers():
    assert jcs.canonicalize({"a": [{"b": [[]]}], "": ""}) == b'{"":"","a":[{"b":[[]]}]}'
    assert jcs.canonicalize([]) == b"[]" and jcs.canonicalize({}) == b"{}"
    assert jcs.canonicalize([True, 1]) == b"[true,1]"   # bools never collapse into ints


def test_keys_are_escaped_and_unicode_keys_kept_literal():
    assert jcs.canonicalize({'a"b': 1}) == b'{"a\\"b":1}'
    assert jcs.canonicalize({"õ": 1, "a": 2}) == '{"a":2,"õ":1}'.encode()
    assert jcs.canonicalize("\x7f") == b'"\x7f"'  # DEL is not a C0 control: literal


def test_unsupported_types_are_refused_by_name():
    with pytest.raises(jcs.JCSError, match="not a string"):
        jcs.canonicalize({1: "x"})
    with pytest.raises(jcs.JCSError, match="type set"):
        jcs.canonicalize({"a": {1, 2}})
    with pytest.raises(jcs.JCSError, match="type bytes"):
        jcs.canonicalize(b"raw")
    with pytest.raises(jcs.JCSError):
        jcs.canonicalize({"nested": [{"deep": 0.5}]})


def test_signing_input_is_stable_under_key_order():
    a = {"signature": "s", "z": 1, "a": {"y": [1], "x": None}}
    b = {"a": {"x": None, "y": [1]}, "z": 1, "signature": "other"}
    assert jcs.signing_input(a) == jcs.signing_input(b)
