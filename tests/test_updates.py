"""axp.updates — channel rule, policy grammar, freshness, consent ratchet."""

from datetime import datetime, timedelta, timezone

import pytest

from axp import updates as u

_NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def test_channel_acceptance():
    assert u.channel_accepts("stable", "stable")
    assert not u.channel_accepts("stable", "beta")
    assert u.channel_accepts("beta", "stable") and u.channel_accepts("beta", "beta")
    assert not u.channel_accepts("beta", "alpha")
    assert u.channel_accepts("dev", "alpha")
    assert u.channel_accepts("canary", "canary")
    assert not u.channel_accepts("canary", "stable") and not u.channel_accepts("stable", "canary")
    assert u.channel_accepts("", "")  # both default to stable


def test_parse_policy():
    assert u.parse_policy(" Auto ") == "auto"
    assert u.parse_policy("pin", "1.2.3") == "pin=1.2.3"
    assert u.parse_policy("PIN=2.0.0") == "pin=2.0.0"
    with pytest.raises(u.PolicyError):
        u.parse_policy("pin")
    with pytest.raises(u.PolicyError):
        u.parse_policy("pin=latest")
    with pytest.raises(u.PolicyError):
        u.parse_policy("yolo")


def test_is_expired_grace_window_and_optionality():
    fresh = {"release": {"valid_until": (_NOW - timedelta(days=3)).isoformat()}}
    stale = {"release": {"valid_until": (_NOW - timedelta(days=8)).isoformat()}}
    assert u.is_expired(fresh, now=_NOW) is False
    assert u.is_expired(stale, now=_NOW) is True
    assert u.is_expired(stale, now=_NOW, grace_days=30) is False
    assert u.is_expired({"release": {}}, now=_NOW) is False
    assert u.is_expired({"release": {"valid_until": "garbage"}}, now=_NOW) is False
    assert u.is_expired({"release": {"valid_until": "2026-08-01T00:00:00Z"}}, now=_NOW) is True


def test_permissions_widened_semantics():
    old = {"network_egress": ["api.test", "cdn.test:443", "*.hf.test"],
           "network_ingress": ["6379/tcp"],
           "filesystem": ["state:rw", "config:r", "hermes:skills:rw"],
           "secrets": ["TOKEN"], "root": False}
    same = dict(old)
    assert u.permissions_widened(old, same) == []
    # Narrowing in every dimension is never a widening.
    narrower = {"network_egress": ["api.test:443", "cdn.test:443", "x.hf.test:443"],
                "network_ingress": ["127.0.0.1:6379/tcp"],
                "filesystem": ["state:r", "hermes:skills:r"],
                "secrets": [], "root": False}
    assert u.permissions_widened(old, narrower) == []
    # Each kind of widening is named.
    assert u.permissions_widened(old, {**old, "network_egress": old["network_egress"] + ["evil.test"]}) == ["network_egress"]
    assert u.permissions_widened(old, {**old, "network_egress": ["cdn.test"]}) == ["network_egress"]  # any port > :443
    assert u.permissions_widened(old, {**old, "network_egress": ["hf.test"]}) == ["network_egress"]   # apex not under *.hf.test
    assert u.permissions_widened(old, {**old, "network_ingress": ["8080/tcp"]}) == ["network_ingress"]
    assert u.permissions_widened(old, {**old, "filesystem": ["config:rw"]}) == ["filesystem"]
    assert u.permissions_widened(old, {**old, "filesystem": ["hermes:plugins:rw"]}) == ["filesystem"]
    assert u.permissions_widened(old, {**old, "secrets": ["TOKEN", "OTHER"]}) == ["secrets"]
    assert u.permissions_widened(old, {**old, "root": True}) == ["root"]
    assert u.permissions_widened({"root": True}, {"root": False}) == []
    assert u.permissions_widened(None, {"network_egress": ["a.test"]}) == ["network_egress"]


def test_parse_scope():
    assert u.parse_scope("state:rw") == (None, "state", "rw")
    assert u.parse_scope("hermes:skills:r") == ("hermes", "skills", "r")
    assert u.parse_scope("state") == (None, "state", "r")
