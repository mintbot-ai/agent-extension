"""Commerce: signed entitlements and holder presentations (SPEC section 14).

An *entitlement* is an issuer's signed statement that one host — the
*holder*, identified by its own ed25519 key — may use an extension: until
when (``valid_until``, null = for ever) and with the right to releases
published until when (``updates_until``, null = all). It is the only
commerce object AXP defines. How the money moved is not AXP's business:
whoever issued the entitlement collected it, by whatever means, and AXP only
says what the proof of that looks like and how a host checks it.

The document reuses the manifest's machinery end to end — JCS
canonicalization, ed25519, the publisher key directory with the key role
``entitlement`` — so a host that verifies manifests verifies entitlements
with the same code and the same trust root.

A *presentation* is how the holder proves possession of its key to an
issuer or an artifact server: a short-lived, audience-bound document signed
by the host key, optionally carrying the entitlement. Encoded, it is the
``Authorization: AXP-Entitlement <token>`` header of SPEC sections 14.4 and
14.5 — one primitive for a gated artifact download, for asking an issuer for
a new or renewed entitlement, and for the server-side check of either.

Pure functions plus a small JSON-file store; no network.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn

from . import jcs, signing
from .manifest import ED25519_KEY_RE, EXT_ID_RE, NAME_RE, PUBLISHER_RE, SPEC_VERSION_RE
from .updates import parse_timestamp

ENTITLEMENT_KIND = "agent-extension-entitlement"
PRESENTATION_KIND = "agent-extension-presentation"
SPEC_VERSION = "0.5"

# The Authorization scheme a holder presents (SPEC section 14.4 / 14.5).
AUTH_SCHEME = "AXP-Entitlement"
# A presentation is a proof for one request, not a credential: short-lived.
DEFAULT_PRESENTATION_TTL_SECONDS = 300
# Tolerated clock difference between the parties for issued_at / expires_at.
CLOCK_SKEW_SECONDS = 300
# SPEC section 14.6: how long after valid_until a host keeps the extension
# running while a renewal is attempted (the publisher may shorten or extend
# it with commerce.grace_days).
DEFAULT_GRACE_DAYS = 7

# Time-only verdicts, in the order a host shows them.
STATUS_VALID = "valid"
STATUS_GRACE = "grace"
STATUS_EXPIRED = "expired"
STATUS_NOT_YET_VALID = "not_yet_valid"


class EntitlementError(ValueError):
    """A malformed or unverifiable entitlement / presentation. User-facing."""


@dataclass(frozen=True)
class Verdict:
    """What :func:`verify_entitlement` concluded.

    ``valid`` is the gate. ``status`` says why / how: ``valid``, ``grace``
    (past ``valid_until`` but inside the grace window — still accepted, the
    host should be renewing), or a refusal: ``expired``, ``not_yet_valid``,
    ``wrong_extension``, ``wrong_holder``, ``untrusted_issuer``,
    ``untrusted_key``, ``bad_signature``, ``malformed``, ``no_entitlement``.
    ``entitlement`` is the checked document when it was at least well-formed.
    """

    valid: bool
    status: str
    reason: str = ""
    entitlement: dict | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """``2026-10-16T12:00:00Z`` — the one spelling the tooling writes."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp_field(value: object) -> str | None:
    """Accept a datetime or an ISO string for an optional timestamp field."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return format_timestamp(value)
    text = str(value)
    if parse_timestamp(text) is None:
        raise EntitlementError(f"{text!r} is not an ISO-8601 timestamp")
    return text


def _fail(field: str, message: str) -> NoReturn:
    raise EntitlementError(f"{field}: {message}")


def _string(parent: Mapping, key: str, path: str, *, required: bool = False,
            pattern=None, expect: str = "") -> str | None:
    value = parent.get(key)
    if value is None:
        if required:
            _fail(path + key, "is required")
        return None
    if not isinstance(value, str) or not value.strip():
        _fail(path + key, "must be a non-empty string")
    if pattern is not None and not pattern.match(value):
        _fail(path + key, f"{value!r} is malformed" + (f" (expected {expect})" if expect else ""))
    return value


def _timestamp(parent: Mapping, key: str, path: str, *, required: bool = False,
               nullable: bool = False) -> datetime | None:
    if key not in parent or parent.get(key) is None:
        if required and not (nullable and key in parent):
            _fail(path + key, "is required" + (" (null = unbounded)" if nullable else ""))
        return None
    value = parent[key]
    parsed = parse_timestamp(value) if isinstance(value, str) else None
    if parsed is None:
        _fail(path + key, f"{value!r} is not an ISO-8601 timestamp")
    return parsed


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise EntitlementError(f"token is not base64url: {exc}") from exc


def _sign_document(document: Mapping, private_key_pem: bytes) -> dict:
    out = {k: v for k, v in document.items() if k != "signature"}
    try:
        out["signature"] = signing.sign_bytes(jcs.canonicalize(out), private_key_pem)
    except jcs.JCSError as exc:
        raise EntitlementError(str(exc)) from exc
    return out


def _verify_document(document: Mapping, public_key: str) -> bool:
    signature = document.get("signature")
    if not isinstance(signature, str) or not signature:
        raise EntitlementError("document has no signature")
    payload = {k: v for k, v in document.items() if k != "signature"}
    try:
        return signing.verify_bytes(jcs.canonicalize(payload), signature, public_key)
    except (jcs.JCSError, signing.SigningError) as exc:
        raise EntitlementError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Entitlements (SPEC section 14.2)
# ---------------------------------------------------------------------------

def validate_entitlement(document: Any) -> dict:
    """Structural check of an entitlement document; returns it. Signature,
    holder, extension and time are :func:`verify_entitlement`'s job."""
    if not isinstance(document, dict):
        raise EntitlementError("entitlement must be a JSON object")
    if document.get("kind") != ENTITLEMENT_KIND:
        _fail("kind", f"must be {ENTITLEMENT_KIND!r}")
    _string(document, "spec_version", "", pattern=SPEC_VERSION_RE, expect="0.MINOR")
    _string(document, "extension", "", required=True, pattern=EXT_ID_RE, expect="<publisher>/<name>")
    _string(document, "holder", "", required=True, pattern=ED25519_KEY_RE,
            expect="ed25519:<base64 of the host's 32 raw public-key bytes>")
    _string(document, "plan", "", required=True, pattern=NAME_RE, expect="a plan id [a-z0-9][a-z0-9_-]*")
    _string(document, "serial", "", required=True)
    _string(document, "issuer", "", required=True, pattern=PUBLISHER_RE,
            expect="a lowercase DNS name such as ext.example.com")
    _timestamp(document, "issued_at", "", required=True)
    _timestamp(document, "valid_until", "", required=True, nullable=True)
    _timestamp(document, "updates_until", "", required=True, nullable=True)
    block = document.get("signing")
    if not isinstance(block, dict):
        _fail("signing", "is required (the issuing key)")
    _string(block, "public_key", "signing.", required=True, pattern=ED25519_KEY_RE,
            expect="ed25519:<base64 of 32 raw bytes>")
    _string(block, "key_id", "signing.")
    _string(document, "signature", "", required=True)
    return document


def sign_entitlement(document: Mapping, private_key_pem: bytes) -> dict:
    """Return a copy of ``document`` with ``signature`` set. ``signing.public_key``
    must already name this key — a mismatch would publish an unverifiable
    entitlement, so it is refused here."""
    declared = (document.get("signing") or {}).get("public_key")
    if not declared:
        raise EntitlementError("entitlement has no signing.public_key; add the issuing key before signing")
    actual = signing.public_key_from_private(private_key_pem)
    if declared != actual:
        raise EntitlementError(
            f"signing.public_key {declared!r} does not match this private key ({actual!r}) — wrong key file?"
        )
    return validate_entitlement(_sign_document(document, private_key_pem))


def issue(
    *,
    extension: str,
    holder: str,
    plan: str,
    issuer: str,
    private_key_pem: bytes,
    key_id: str | None = None,
    issued_at: datetime | str | None = None,
    valid_until: datetime | str | None = None,
    updates_until: datetime | str | None = None,
    serial: str | None = None,
) -> dict:
    """Build and sign an entitlement (SPEC section 14.2).

    ``valid_until`` None = perpetual use; ``updates_until`` None = every
    future release. A subscription sets both to the period end; a one-time
    purchase sets ``valid_until`` None and ``updates_until`` to the end of
    the update window it bought (or None); a trial sets ``valid_until`` to
    the trial end. ``serial`` defaults to a random token — it is what an
    issuer later revokes or renews by.
    """
    document = {
        "kind": ENTITLEMENT_KIND,
        "spec_version": SPEC_VERSION,
        "extension": extension,
        "holder": holder,
        "plan": plan,
        "serial": serial or secrets.token_urlsafe(16),
        "issuer": issuer,
        "issued_at": _timestamp_field(issued_at) or format_timestamp(_now(None)),
        "valid_until": _timestamp_field(valid_until),
        "updates_until": _timestamp_field(updates_until),
        "signing": {"public_key": signing.public_key_from_private(private_key_pem)},
    }
    if key_id:
        document["signing"]["key_id"] = key_id
    return sign_entitlement(document, private_key_pem)


def time_status(document: Mapping, *, now: datetime | None = None,
                grace_days: int = DEFAULT_GRACE_DAYS) -> str:
    """``valid`` | ``grace`` | ``expired`` | ``not_yet_valid`` from the
    timestamps alone (SPEC section 14.6). ``grace`` is still a usable
    entitlement; the host should be renewing it."""
    moment = _now(now)
    issued_at = parse_timestamp(document.get("issued_at"))
    if issued_at is not None and issued_at - moment > timedelta(seconds=CLOCK_SKEW_SECONDS):
        return STATUS_NOT_YET_VALID
    valid_until = parse_timestamp(document.get("valid_until"))
    if valid_until is None or moment <= valid_until:
        return STATUS_VALID
    if moment - valid_until <= timedelta(days=grace_days):
        return STATUS_GRACE
    return STATUS_EXPIRED


def covers_release(document: Mapping, release: Mapping) -> bool:
    """May the holder take a release? True unless the entitlement's
    ``updates_until`` lies before the release's ``published_at`` (SPEC
    section 14.7). ``release`` is a manifest or its ``release`` block. A
    release without ``published_at`` cannot be placed and is treated as
    covered — the gate a publisher controls is the artifact server, and a
    publisher selling update windows stamps the date (``axp release`` does)."""
    updates_until = parse_timestamp(document.get("updates_until"))
    if updates_until is None:
        return True
    block = release.get("release") if isinstance(release.get("release"), Mapping) else release
    published_at = parse_timestamp((block or {}).get("published_at"))
    return published_at is None or published_at <= updates_until


def verify_entitlement(
    document: Any,
    *,
    extension: str,
    holder: str | None,
    issuer_keys: list[str],
    issuers: list[str] | None = None,
    now: datetime | None = None,
    grace_days: int = DEFAULT_GRACE_DAYS,
) -> Verdict:
    """The whole SPEC section 14.3 check, as a host or an issuer runs it.

    ``extension`` is the id being installed; ``holder`` the host's own key
    (None skips the binding check — only an issuer inspecting its own
    records should do that); ``issuer_keys`` the issuer's ``entitlement``
    role keys as :func:`axp.signing.parse_key_directory` returned them for
    this extension; ``issuers`` the manifest's ``commerce.issuers`` (default:
    the publisher) — an entitlement from anyone else is refused before its
    key is even looked at. Pure; never writes.
    """
    try:
        checked = validate_entitlement(document)
    except EntitlementError as exc:
        return Verdict(False, "malformed", str(exc))
    if checked["extension"] != extension:
        return Verdict(False, "wrong_extension",
                       f"entitlement is for {checked['extension']}, not {extension}", checked)
    if holder is not None and checked["holder"] != holder:
        return Verdict(False, "wrong_holder", "entitlement is bound to another host key", checked)
    if issuers is not None and checked["issuer"] not in issuers:
        return Verdict(False, "untrusted_issuer",
                       f"{checked['issuer']} is not an issuer the manifest names", checked)
    key = checked["signing"]["public_key"]
    if key not in issuer_keys:
        return Verdict(False, "untrusted_key",
                       f"signing key is not an entitlement key of {checked['issuer']}", checked)
    try:
        if not _verify_document(checked, key):
            return Verdict(False, "bad_signature", "signature does not verify against the issuing key", checked)
    except EntitlementError as exc:
        return Verdict(False, "bad_signature", str(exc), checked)
    status = time_status(checked, now=now, grace_days=grace_days)
    if status == STATUS_VALID:
        return Verdict(True, status, "", checked)
    if status == STATUS_GRACE:
        return Verdict(True, status, f"valid_until passed; inside the {grace_days}-day grace window", checked)
    if status == STATUS_NOT_YET_VALID:
        return Verdict(False, status, "issued_at lies in the future", checked)
    return Verdict(False, status, f"valid_until {checked['valid_until']} has passed", checked)


# ---------------------------------------------------------------------------
# Holder presentations (SPEC section 14.4 / 14.5)
# ---------------------------------------------------------------------------

def holder_from_private(host_private_key_pem: bytes) -> str:
    """The ``holder`` value of a host key: its public form. A host key is an
    ordinary ed25519 key (``axp keygen``), generated once per installation."""
    return signing.public_key_from_private(host_private_key_pem)


def make_presentation(
    *,
    host_private_key_pem: bytes,
    audience: str,
    entitlement: Mapping | None = None,
    extension: str | None = None,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_PRESENTATION_TTL_SECONDS,
    nonce: str | None = None,
) -> dict:
    """A signed, audience-bound proof of possession of the host key, for
    one request to ``audience`` (the exact URL being fetched or posted to).

    With ``entitlement`` it authorizes a gated download or a renewal; without
    one it asks the issuer for an entitlement for ``extension`` (SPEC
    section 14.5). It is valid for ``ttl_seconds`` only.
    """
    holder = holder_from_private(host_private_key_pem)
    if not str(audience).lower().startswith("https://"):
        raise EntitlementError("audience must be the https:// URL the presentation is sent to")
    if entitlement is not None:
        entitlement = validate_entitlement(dict(entitlement))
        if entitlement["holder"] != holder:
            raise EntitlementError("entitlement is bound to another host key; cannot present it")
        if extension is not None and extension != entitlement["extension"]:
            raise EntitlementError("extension does not match the entitlement's")
        extension = entitlement["extension"]
    if not extension or not EXT_ID_RE.match(extension):
        raise EntitlementError("extension (<publisher>/<name>) is required")
    if ttl_seconds <= 0 or ttl_seconds > DEFAULT_PRESENTATION_TTL_SECONDS:
        raise EntitlementError(f"ttl_seconds must be 1..{DEFAULT_PRESENTATION_TTL_SECONDS}")
    issued = _now(now)
    document: dict = {
        "kind": PRESENTATION_KIND,
        "spec_version": SPEC_VERSION,
        "holder": holder,
        "extension": extension,
        "audience": audience,
        "issued_at": format_timestamp(issued),
        "expires_at": format_timestamp(issued + timedelta(seconds=ttl_seconds)),
        "nonce": nonce or secrets.token_urlsafe(16),
    }
    if entitlement is not None:
        document["entitlement"] = entitlement
    return _sign_document(document, host_private_key_pem)


def authorization_header(presentation: Mapping) -> str:
    """``AXP-Entitlement <base64url of the JCS presentation>`` — the value of
    the ``Authorization`` request header."""
    try:
        return f"{AUTH_SCHEME} {_b64url(jcs.canonicalize(dict(presentation)))}"
    except jcs.JCSError as exc:
        raise EntitlementError(str(exc)) from exc


def parse_authorization_header(value: str) -> dict:
    """The presentation inside an ``Authorization`` header value, decoded but
    NOT verified — pass it to :func:`verify_presentation`."""
    scheme, _, token = str(value or "").strip().partition(" ")
    if scheme.lower() != AUTH_SCHEME.lower() or not token.strip():
        raise EntitlementError(f"Authorization scheme must be {AUTH_SCHEME}")
    try:
        document = json.loads(_unb64url(token.strip()).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EntitlementError(f"presentation token is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise EntitlementError("presentation must be a JSON object")
    return document


def verify_presentation(
    document: Any,
    *,
    audience: str,
    now: datetime | None = None,
    max_ttl_seconds: int = DEFAULT_PRESENTATION_TTL_SECONDS,
) -> dict:
    """Server side: check a presentation (a decoded document or the raw
    ``Authorization`` header value) was made by its ``holder`` for exactly
    ``audience`` and is current. Returns the presentation; raises
    :class:`EntitlementError` with the reason otherwise. The embedded
    entitlement, if any, is NOT checked here — see
    :func:`verify_presented_entitlement`."""
    if isinstance(document, str):
        document = parse_authorization_header(document)
    if not isinstance(document, dict):
        raise EntitlementError("presentation must be a JSON object")
    if document.get("kind") != PRESENTATION_KIND:
        _fail("kind", f"must be {PRESENTATION_KIND!r}")
    holder = _string(document, "holder", "", required=True, pattern=ED25519_KEY_RE,
                     expect="ed25519:<base64 of 32 raw bytes>")
    assert holder is not None
    _string(document, "extension", "", required=True, pattern=EXT_ID_RE, expect="<publisher>/<name>")
    presented_audience = _string(document, "audience", "", required=True)
    _string(document, "nonce", "", required=True)
    issued_at = _timestamp(document, "issued_at", "", required=True)
    expires_at = _timestamp(document, "expires_at", "", required=True)
    assert issued_at is not None and expires_at is not None
    if presented_audience != audience:
        raise EntitlementError(f"presentation is addressed to {presented_audience}, not {audience}")
    moment = _now(now)
    skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
    if issued_at - moment > skew:
        raise EntitlementError("presentation issued_at lies in the future")
    if expires_at + skew < moment:
        raise EntitlementError("presentation has expired")
    if expires_at - issued_at > timedelta(seconds=max_ttl_seconds):
        raise EntitlementError(f"presentation lifetime exceeds {max_ttl_seconds} seconds")
    if "entitlement" in document:
        validate_entitlement(document["entitlement"])
        if document["entitlement"]["holder"] != holder:
            raise EntitlementError("presented entitlement is bound to another holder")
        if document["entitlement"]["extension"] != document["extension"]:
            raise EntitlementError("presented entitlement is for another extension")
    if not _verify_document(document, holder):
        raise EntitlementError("presentation signature does not verify against the holder key")
    return document


def verify_presented_entitlement(
    document: Any,
    *,
    audience: str,
    extension: str,
    issuer_keys: list[str],
    issuers: list[str] | None = None,
    now: datetime | None = None,
    grace_days: int = DEFAULT_GRACE_DAYS,
) -> Verdict:
    """What an artifact server or issuer runs on an incoming request: the
    presentation check, then the embedded entitlement against the issuer
    keys THIS server trusts. A presentation without an entitlement yields
    ``no_entitlement`` (an issuer answers it with a checkout, SPEC 14.5).
    A bad presentation is ``malformed`` — answer 401, never 402."""
    try:
        presentation = verify_presentation(document, audience=audience, now=now)
    except EntitlementError as exc:
        return Verdict(False, "malformed", f"presentation: {exc}")
    if presentation["extension"] != extension:
        return Verdict(False, "wrong_extension",
                       f"presentation is for {presentation['extension']}, not {extension}")
    entitlement = presentation.get("entitlement")
    if entitlement is None:
        return Verdict(False, "no_entitlement", "presentation carries no entitlement")
    return verify_entitlement(entitlement, extension=extension, holder=presentation["holder"],
                              issuer_keys=issuer_keys, issuers=issuers, now=now, grace_days=grace_days)


# ---------------------------------------------------------------------------
# Host-side store
# ---------------------------------------------------------------------------

class EntitlementStore:
    """JSON-file-backed entitlements held by this host, keyed by extension
    id — the file a host hands hooks as ``AXP_ENTITLEMENT_FILE`` is derived
    from these records. Written atomically, like :class:`axp.signing.PinStore`."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._entries: dict[str, dict] = {}
        if self._path.exists():
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("entitlement store is not a JSON object")
            self._entries = loaded

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)

    def get(self, ext_id: str) -> dict | None:
        entry = self._entries.get(ext_id)
        return dict(entry) if entry else None

    def put(self, ext_id: str, entitlement: Mapping) -> None:
        checked = validate_entitlement(dict(entitlement))
        if checked["extension"] != ext_id:
            raise EntitlementError(f"entitlement is for {checked['extension']}, not {ext_id}")
        self._entries[ext_id] = checked
        self._save()

    def remove(self, ext_id: str) -> None:
        if self._entries.pop(ext_id, None) is not None:
            self._save()

    def extensions(self) -> list[str]:
        return sorted(self._entries)
