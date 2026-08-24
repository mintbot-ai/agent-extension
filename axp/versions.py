"""Version ordering and constraint matching (SPEC section 4.3).

One ordering for semver (``1.4.0``) and calver (``2026.6``): segments compare
numerically, missing trailing segments count as zero (``2026.6 == 2026.6.0``),
a pre-release (``1.2.0-rc.1``) sorts below its release, and build metadata
(``+…``) never affects ordering (SemVer section 10).

A *constraint* is a space-separated list of comparators, all of which must
hold::

    >=X   >X   <=X   <X   =X   ^X   ~X   X (same as =X)

``^X`` keeps the first non-zero segment fixed (``^1.2`` = ``>=1.2 <2``,
``^0.2.3`` = ``>=0.2.3 <0.3``, npm semantics); ``~X`` keeps everything but
the second segment fixed (``~1.2.3`` = ``>=1.2.3 <1.3``, ``~1`` = ``>=1 <2``).

Pure functions, stdlib only. Hosts vendor this module so that
``requires.extensions``, ``targets[].runtime_version`` and the
strictly-higher update rule mean exactly the same thing everywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import zip_longest

_VERSION_RE = re.compile(
    r"^([0-9]+(?:[.][0-9]+)*)(?:-([0-9A-Za-z.-]+))?(?:[+]([0-9A-Za-z.-]+))?$"
)
# Longest operators first so ">=" is not read as ">" + "=1.0".
_OPERATORS = (">=", "<=", ">", "<", "=", "^", "~")


class VersionError(ValueError):
    """A version or constraint string this grammar cannot read. User-facing."""


@dataclass(frozen=True)
class Version:
    """A parsed version. Compare with :func:`compare`, never by tuple order —
    segment padding and pre-release rules live there."""

    segments: tuple[int, ...]
    prerelease: tuple[tuple[int, object], ...]
    raw: str

    def __str__(self) -> str:
        return self.raw


def parse(text: str) -> Version:
    raw = str(text).strip()
    match = _VERSION_RE.match(raw)
    if match is None:
        raise VersionError(f"{raw!r} is not a version (expected digits separated by dots, optional -prerelease)")
    segments = tuple(int(part) for part in match.group(1).split("."))
    prerelease: tuple[tuple[int, object], ...] = ()
    if match.group(2):
        # Numeric identifiers compare numerically and below alphanumeric ones
        # (SemVer section 11); the leading 0/1 encodes that rule in the tuple.
        prerelease = tuple(
            (0, int(part)) if part.isdigit() else (1, part)
            for part in match.group(2).split(".")
        )
    return Version(segments, prerelease, raw)


def is_version(text: str) -> bool:
    return _VERSION_RE.match(str(text).strip()) is not None


def compare(a: str | Version, b: str | Version) -> int:
    """-1 / 0 / +1 like ``cmp``."""
    va = a if isinstance(a, Version) else parse(a)
    vb = b if isinstance(b, Version) else parse(b)
    for x, y in zip_longest(va.segments, vb.segments, fillvalue=0):
        if x != y:
            return -1 if x < y else 1
    # Same core: a release outranks every pre-release of that core.
    if bool(va.prerelease) != bool(vb.prerelease):
        return 1 if not va.prerelease else -1
    if va.prerelease != vb.prerelease:
        return -1 if va.prerelease < vb.prerelease else 1
    return 0


def is_newer(candidate: str, installed: str) -> bool:
    """The strictly-higher rule (SPEC section 7.4) — the only comparison
    auto-update may use."""
    return compare(candidate, installed) > 0


def sort_key(text: str):
    """A key for ``sorted()`` consistent with :func:`compare`."""
    version = parse(text)
    # Pad to a fixed width so tuple order equals segment-wise numeric order
    # for any realistic depth; pre-releases sort below the bare release.
    segments = version.segments + (0,) * (8 - len(version.segments))
    return (segments[:8], 0 if version.prerelease else 1, version.prerelease)


def _caret_upper(version: Version) -> tuple[int, ...]:
    segments = version.segments
    index = next((i for i, seg in enumerate(segments) if seg != 0), len(segments) - 1)
    return segments[:index] + (segments[index] + 1,)


def _tilde_upper(version: Version) -> tuple[int, ...]:
    segments = version.segments
    index = min(1, len(segments) - 1)
    return segments[:index] + (segments[index] + 1,)


def _below(version: Version, upper: tuple[int, ...]) -> bool:
    return compare(version, Version(upper, (), ".".join(map(str, upper)))) < 0


def parse_constraint(text: str) -> list[tuple[str, Version]]:
    """``">=1.2 <2"`` → ``[(">=", 1.2), ("<", 2)]``. Raises :class:`VersionError`."""
    out: list[tuple[str, Version]] = []
    tokens = str(text).split()
    if not tokens:
        raise VersionError("empty version constraint")
    for token in tokens:
        operator = next((op for op in _OPERATORS if token.startswith(op)), "=")
        operand = token[len(operator):] if token.startswith(operator) else token
        if not operand:
            raise VersionError(f"constraint {token!r} has an operator but no version")
        out.append((operator, parse(operand)))
    return out


def is_constraint(text: str) -> bool:
    try:
        parse_constraint(text)
    except VersionError:
        return False
    return True


def satisfies(version: str | Version, constraint: str) -> bool:
    """True iff ``version`` meets every comparator in ``constraint``."""
    v = version if isinstance(version, Version) else parse(version)
    for operator, bound in parse_constraint(constraint):
        c = compare(v, bound)
        if operator == ">=" and c < 0:
            return False
        if operator == ">" and c <= 0:
            return False
        if operator == "<=" and c > 0:
            return False
        if operator == "<" and c >= 0:
            return False
        if operator == "=" and c != 0:
            return False
        if operator == "^" and (c < 0 or not _below(v, _caret_upper(bound))):
            return False
        if operator == "~" and (c < 0 or not _below(v, _tilde_upper(bound))):
            return False
    return True
