"""Runtime-neutral update rules (SPEC section 7) and the consent ratchet.

Pure functions over manifest / install-record dicts; no IO. A Managed host
vendors this module so channels, freshness, policy strings and "did the
new version widen what the user approved" are decided identically
everywhere — those are exactly the decisions a user must be able to trust
across hosts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Mapping

from . import versions

# Least stable first (SPEC section 7.2). Tracking channel C accepts C and every
# channel to its right; custom channels are opaque and exact-match only.
CORE_CHANNELS = ("dev", "alpha", "beta", "stable")
DEFAULT_CHANNEL = "stable"

POLICIES = ("auto", "notify", "pin", "off")

# SPEC section 7.4: how far past release.valid_until an installed manifest may be
# before a host should start warning that the extension may be held back.
DEFAULT_FRESHNESS_GRACE_DAYS = 7


class PolicyError(ValueError):
    """An update-policy string this grammar cannot read. User-facing."""


# --- channels -----------------------------------------------------------------

def channel_accepts(tracked: str, candidate: str) -> bool:
    tracked = (tracked or DEFAULT_CHANNEL).strip().lower()
    candidate = (candidate or DEFAULT_CHANNEL).strip().lower()
    if tracked in CORE_CHANNELS and candidate in CORE_CHANNELS:
        return CORE_CHANNELS.index(candidate) >= CORE_CHANNELS.index(tracked)
    return tracked == candidate


# --- policy -------------------------------------------------------------------

def parse_policy(value: str, installed_version: str = "") -> str:
    """Normalise a stored policy: ``auto`` | ``notify`` | ``off`` |
    ``pin=X.Y.Z``. Bare ``pin`` pins the installed version (SPEC section 7.5)."""
    value = str(value or "").strip().lower()
    if value in ("auto", "notify", "off"):
        return value
    if value == "pin":
        if not installed_version:
            raise PolicyError("cannot pin: no installed version to pin to")
        return f"pin={installed_version}"
    if value.startswith("pin="):
        target = value[len("pin="):]
        if not versions.is_version(target):
            raise PolicyError(f"pin target {target!r} is not a version")
        return f"pin={target}"
    raise PolicyError(f"policy must be one of {list(POLICIES)} (got {value!r})")


# --- freshness ----------------------------------------------------------------

def parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_expired(document: Mapping, *, now: datetime | None = None,
               grace_days: int = DEFAULT_FRESHNESS_GRACE_DAYS) -> bool:
    """True when ``release.valid_until`` (if any) lies more than ``grace_days``
    in the past. Works on a manifest and on an install record alike — both
    carry the ``release`` block. No ``valid_until`` means never expired: the
    field is the publisher's opt-in freeze defence, not a requirement."""
    valid_until = parse_timestamp((document.get("release") or {}).get("valid_until"))
    if valid_until is None:
        return False
    now = now or datetime.now(timezone.utc)
    return now - valid_until > timedelta(days=grace_days)


# --- permission surface comparison (the consent ratchet) ----------------------

def parse_scope(entry: str) -> tuple[str | None, str, str]:
    """``"state:rw"`` → ``(None, "state", "rw")``; ``"hermes:skills:r"`` →
    ``("hermes", "skills", "r")``."""
    parts = str(entry).split(":")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    scope, _, mode = str(entry).partition(":")
    return None, scope, mode or "r"


def _egress_covers(granted: str, wanted: str) -> bool:
    """``host[:port]`` coverage: a bare host covers every port of that host;
    ``*.example.com`` covers any host under ``example.com``."""
    g_host, _, g_port = granted.rpartition(":") if ":" in granted else (granted, "", "")
    w_host, _, w_port = wanted.rpartition(":") if ":" in wanted else (wanted, "", "")
    g_host, w_host = g_host.lower(), w_host.lower()
    if g_port and g_port != w_port:
        return False
    if g_host.startswith("*."):
        return w_host.endswith(g_host[1:]) and w_host != g_host[2:] or w_host == g_host
    return g_host == w_host


def _ingress_covers(granted: str, wanted: str) -> bool:
    """``[addr:]port/proto`` coverage: no address means any address."""
    g_addr, _, g_rest = granted.rpartition(":") if granted.count(":") else ("", "", granted)
    w_addr, _, w_rest = wanted.rpartition(":") if wanted.count(":") else ("", "", wanted)
    if g_rest != w_rest:
        return False
    return not g_addr or g_addr == w_addr


def _scope_covers(granted: str, wanted: str) -> bool:
    g_rt, g_scope, g_mode = parse_scope(granted)
    w_rt, w_scope, w_mode = parse_scope(wanted)
    if (g_rt, g_scope) != (w_rt, w_scope):
        return False
    return g_mode == "rw" or w_mode == "r"


def permissions_widened(consented: Mapping | None, candidate: Mapping | None) -> list[str]:
    """Names of the permission dimensions a candidate widens beyond what the
    user approved. Empty == every requested access is already covered, so a
    host may apply the update without a new consent. Narrowing is never
    flagged (``state:rw`` → ``state:r``, ``api:443`` → ``api:443`` ⊂ ``api``)."""
    old = consented or {}
    new = candidate or {}
    widened: list[str] = []

    def entries(block: Mapping, key: str) -> list[str]:
        return [str(x) for x in (block.get(key) or [])]

    def covered(key: str, covers) -> bool:
        granted = entries(old, key)
        return all(any(covers(g, w) for g in granted) for w in entries(new, key))

    if not covered("network_egress", _egress_covers):
        widened.append("network_egress")
    if not covered("network_ingress", _ingress_covers):
        widened.append("network_ingress")
    if not covered("filesystem", _scope_covers):
        widened.append("filesystem")
    if not set(entries(new, "secrets")) <= set(entries(old, "secrets")):
        widened.append("secrets")
    if bool(new.get("root")) and not bool(old.get("root")):
        widened.append("root")
    return widened
