"""JCS (RFC 8785) canonical JSON serialization — the signing input for AXP.

AXP signatures cover the JCS canonicalization of the manifest with the
``signature`` / ``signature_prev`` fields removed (SPEC §8.2). This module
implements the subset of RFC 8785 an AXP manifest can contain:

  * objects with string keys, sorted by UTF-16 code units
  * arrays, strings (RFC 8785 §3.2.2.2 escaping), booleans, null
  * integers within the IEEE-754 exact range (|n| <= 2**53)

Non-integer numbers are **rejected**, not serialized: ECMAScript float
formatting is the one genuinely hard part of RFC 8785, and no AXP field is a
float (the JSON Schema only carries integers). Refusing keeps this module
dependency-free and removes a whole class of cross-implementation signature
mismatches. A manifest that smuggles a float in an ``x-`` extension fails to
sign/verify with a clear message — publishers must use strings or integers.

For payloads inside the manifest's shape, the output is byte-identical to any
full RFC 8785 implementation.
"""

from __future__ import annotations

from typing import Any

# 2**53 — integers beyond this are not exactly representable as IEEE-754
# doubles, so ECMAScript serialization (and thus JCS) is lossy there.
_MAX_SAFE_INT = 9007199254740992

# RFC 8785 §3.2.2.2: two-char escapes for these controls, \u00XX for the rest.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class JCSError(ValueError):
    """The value cannot be canonicalized under this module's JCS subset."""


def _serialize_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        short = _SHORT_ESCAPES.get(code)
        if short is not None:
            out.append(short)
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(value: str) -> tuple[int, ...]:
    """RFC 8785 §3.2.3 sorts object keys by UTF-16 code units, not code
    points — they differ for supplementary-plane characters (emoji sort
    *before* U+E000..U+FFFF privates in UTF-16, after them by code point)."""
    units: list[int] = []
    for ch in value:
        code = ord(ch)
        if code < 0x10000:
            units.append(code)
        else:
            code -= 0x10000
            units.append(0xD800 + (code >> 10))
            units.append(0xDC00 + (code & 0x3FF))
    return tuple(units)


def _serialize(value: Any, out: list[str]) -> None:
    # bool before int: Python bools are ints.
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise JCSError(
                f"integer {value} exceeds the IEEE-754 exact range (2**53); "
                "JCS cannot represent it interoperably"
            )
        out.append(str(value))
    elif isinstance(value, float):
        raise JCSError(
            "non-integer numbers are not allowed in AXP manifests "
            "(use a string or an integer) — see axp.jcs module docs"
        )
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JCSError(f"object key {key!r} is not a string")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                out.append(",")
            out.append(_serialize_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    else:
        raise JCSError(f"type {type(value).__name__} cannot be canonicalized")


def canonicalize(value: Any) -> bytes:
    """Canonical JCS bytes (UTF-8) of ``value``. Raises :class:`JCSError`."""
    out: list[str] = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")


def signing_input(manifest: dict) -> bytes:
    """The exact bytes an AXP signature covers (SPEC §8.2): the manifest
    without ``signature`` / ``signature_prev``, canonicalized."""
    stripped = {k: v for k, v in manifest.items() if k not in ("signature", "signature_prev")}
    return canonicalize(stripped)
