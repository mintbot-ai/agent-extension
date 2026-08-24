"""axp.versions — ordering and the constraint grammar (SPEC section 4.3)."""

import pytest

from axp import versions as v


def test_ordering_semver_calver_and_padding():
    assert v.compare("1.0.0", "1.0.0") == 0
    assert v.compare("2026.6", "2026.6.0") == 0
    assert v.compare("1.10.0", "1.9.9") > 0
    assert v.compare("2026.8.3", "2026.6") > 0
    assert v.is_newer("2.0.0", "1.99.99")
    assert not v.is_newer("1.0.0", "1.0.0")


def test_prerelease_and_build_metadata():
    assert v.compare("1.2.0-rc.1", "1.2.0") < 0
    assert v.compare("1.2.0-rc.1", "1.1.9") > 0
    assert v.compare("1.2.0-rc.2", "1.2.0-rc.10") < 0     # numeric identifiers
    assert v.compare("1.2.0-alpha", "1.2.0-1") > 0        # alphanumeric > numeric
    assert v.compare("1.2.0-rc", "1.2.0-rc.1") < 0        # shorter prefix first
    assert v.compare("1.0.0+build.7", "1.0.0") == 0


def test_parse_rejects_garbage():
    for bad in ("latest", "v1.0", "1.", "", "1..2", "1.0.0-"):
        with pytest.raises(v.VersionError):
            v.parse(bad)
    assert v.is_version("1.0.0") and not v.is_version("v1")


@pytest.mark.parametrize("version,constraint,expected", [
    ("1.5.0", ">=1.0 <2", True),
    ("2.0.0", ">=1.0 <2", False),
    ("2026.8.3", ">=2026.6", True),
    ("2026.5", ">=2026.6", False),
    ("0.18.2", ">=0.18.2", True),
    ("1.0.0", "1.0.0", True),          # bare = exact
    ("1.0.1", "=1.0.0", False),
    ("1.9.9", "^1.2", True),
    ("2.0.0", "^1.2", False),
    ("0.2.9", "^0.2.3", True),
    ("0.3.0", "^0.2.3", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("1.9.0", "~1", True),
    ("2.0.0", "~1", False),
    ("1.5.0", ">1.5.0", False),
    ("1.5.0", "<=1.5.0", True),
])
def test_satisfies(version, constraint, expected):
    assert v.satisfies(version, constraint) is expected


def test_constraint_grammar_errors():
    for bad in ("", ">=", ">= 1.0", "~latest"):
        with pytest.raises(v.VersionError):
            v.parse_constraint(bad)
    assert v.is_constraint(">=1 <2") and not v.is_constraint("whatever")


def test_sort_key_matches_compare():
    items = ["1.2.0", "1.2.0-rc.1", "1.10.0", "2026.6", "1.2.0-rc.10", "0.9"]
    assert sorted(items, key=v.sort_key) == ["0.9", "1.2.0-rc.1", "1.2.0-rc.10", "1.2.0", "1.10.0", "2026.6"]


def test_caret_and_tilde_on_short_and_zero_versions():
    assert v.satisfies("0.0.3", "^0.0.3") and not v.satisfies("0.0.4", "^0.0.3")
    assert v.satisfies("0.2.9", "^0.2") and not v.satisfies("0.3.0", "^0.2")
    assert v.satisfies("1.9.9", "^1") and not v.satisfies("2.0.0", "^1")
    assert v.satisfies("2.5", "~2") and not v.satisfies("3.0", "~2")
    assert v.satisfies("2026.6.9", "~2026.6") and not v.satisfies("2026.7", "~2026.6")
    assert v.satisfies("1.2.0-rc.1", ">=1.2.0-rc.1 <1.2.0")


def test_compare_accepts_parsed_versions_and_str_roundtrip():
    parsed = v.parse("1.0")
    assert str(parsed) == "1.0"
    assert v.compare(parsed, "1.0.0") == 0 and v.compare("1.0.0", parsed) == 0
    assert v.compare(v.parse("1.0.0-alpha.1"), v.parse("1.0.0-alpha.beta")) < 0
    assert v.satisfies(parsed, ">=1")


def test_unknown_operators_are_errors_not_silent_matches():
    # "!=" is not in the grammar: it must fail loudly, never be read as "=".
    with pytest.raises(v.VersionError):
        v.satisfies("1.5.0", ">=1.0 <2 !=1.6")
    assert v.satisfies("1.5.0", ">=1.0 <2 <=1.5.0") and not v.satisfies("1.5.1", ">=1.0 <2 <=1.5.0")
