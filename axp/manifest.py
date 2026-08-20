"""AXP manifest validation and target selection (SPEC v0.3).

Runtime-neutral reference implementation of the structural rules the spec
states in prose and the JSON Schema states declaratively. Unlike a schema
validator it also implements the *semantics*: the §2.4 forward-compatibility
rule (ignore unknown fields and component types, refuse unknown
security-relevant enum values), the §13 v0.2 compatibility readings, and §5
target selection for a concrete host.

Two entry points:

* :func:`validate` — check a whole decoded manifest (every target, not just
  an installable one) and return a normalized summary. This is what
  ``axp validate`` and publisher tooling use.
* :func:`select_target` — pick the target a host with the given runtimes and
  platform would install (SPEC §5, including the ``posix`` fallback).

Errors are :class:`ManifestError` with a user-facing message that names the
offending field.
"""

from __future__ import annotations

import platform as _platform
import re
from datetime import datetime
from typing import Any, NoReturn

AXP_KIND = "agent-extension"
SUPPORTED_SPEC_MAJORS = (0,)

RUNTIME_POSIX = "posix"
DELIVERY_ARCHIVE = "archive"
DELIVERY_HERMES = "hermes-integration"
ARCHIVE_FORMATS = ("tar.gz", "zip")

ENFORCEMENT_TIERS = ("declared", "advisory", "enforced")
UPDATE_POLICIES = ("auto", "notify", "pin", "off")
UPDATE_CHECKS = ("hourly", "daily", "weekly", "manual")
UPDATE_SOURCE_KINDS = {"github": "repo", "forge": "url", "feed": "url", "direct": "url"}
LIFECYCLE_HOOKS = ("install", "upgrade", "uninstall", "health")
REQUIRED_LIFECYCLE_HOOKS = ("install", "uninstall")
# Core component types (SPEC §4.2) -> required fields per entry.
PROVIDES_TYPES: dict[str, tuple[str, ...]] = {
    "mcp_servers": ("name", "transport"),
    "tools": ("name",),
    "services": ("name", "kind"),
    "memory": ("name", "kind"),
    "skills": ("name",),
    "prompts": ("name",),
    "channels": ("name",),
    "model_providers": ("name",),
    "hooks": ("name", "event"),
    "cron": ("name", "schedule"),
}
PROVIDES_ALIASES = {"persona": "prompts"}  # v0.2 name -> v0.3 name (SPEC §13)
MCP_TRANSPORTS = ("stdio", "http", "sse")
# Closed set (SPEC §2.4): an unknown permission key is a refusal, because
# ignoring it could under-warn the user.
PERMISSION_KEYS = ("network_egress", "network_ingress", "filesystem", "secrets", "root", "reason")

# Grammar — byte-identical to schema/agent-extension.schema.json patterns.
SPEC_VERSION_RE = re.compile(r"^0\.[0-9]+$")
PUBLISHER_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
NAME_MAX_LEN = 64
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].+)?$")
CHANNEL_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
ED25519_KEY_RE = re.compile(r"^ed25519:[A-Za-z0-9+/]{43}=$")
GITHUB_REPO_RE = re.compile(r"^[^/\s]+/[^/\s]+$")
RUNTIME_ID_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$")
PLATFORM_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+$")
EXT_ID_RE = re.compile(r"^[a-z0-9.-]+/[a-z0-9][a-z0-9_-]*$")
EGRESS_RE = re.compile(r"^(\*\.)?[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?$")
INGRESS_RE = re.compile(r"^([A-Za-z0-9.:\[\]-]+:)?[0-9]{1,5}/(tcp|udp)$")
FS_SCOPE_RE = re.compile(r"^([a-z][a-z0-9_-]*:)?[a-z][a-z0-9_-]*:(r|rw)$")
VERSION_RANGE_RE = re.compile(r"^(\s*(>=|<=|>|<|=|\^|~)?[0-9]+(\.[0-9A-Za-z-]+)*\s*)+$")


class ManifestError(ValueError):
    """A structural problem in an AXP manifest. The message is user-facing."""


def is_axp_manifest(data: Any) -> bool:
    """True iff ``data`` is a decoded JSON object that declares itself AXP."""
    return isinstance(data, dict) and data.get("kind") == AXP_KIND


def host_platform() -> str:
    """GOOS/GOARCH-style platform of this machine, for ``targets[].platforms``."""
    machine = _platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    return f"{_platform.system().lower()}/{arch}"


def ext_id(manifest: dict) -> str:
    """``<publisher>/<name>`` — the identity everything keys on (SPEC §4.1)."""
    identity = manifest.get("identity") or {}
    return f"{identity.get('publisher', '')}/{identity.get('name', '')}"


# ---------------------------------------------------------------------------
# Field helpers — every check names the offending field
# ---------------------------------------------------------------------------

def _fail(field: str, message: str) -> NoReturn:
    raise ManifestError(f"{field}: {message}")


def _req_dict(parent: dict, key: str, path: str) -> dict:
    value = parent.get(key)
    if value is None:
        _fail(path + key, "is required")
    if not isinstance(value, dict):
        _fail(path + key, "must be an object")
    return value


def _opt_dict(parent: dict, key: str, path: str) -> dict | None:
    value = parent.get(key)
    if value is not None and not isinstance(value, dict):
        _fail(path + key, "must be an object")
    return value


def _string(parent: dict, key: str, path: str, *, required: bool = False,
            pattern: re.Pattern | None = None, expect: str = "") -> str | None:
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


def _enum(parent: dict, key: str, path: str, choices: tuple[str, ...],
          *, default: str | None = None) -> str | None:
    value = parent.get(key)
    if value is None:
        return default
    if value not in choices:
        _fail(path + key, f"must be one of {list(choices)} (got {value!r})")
    return value


def _string_list(parent: dict, key: str, path: str, *,
                 pattern: re.Pattern | None = None, expect: str = "") -> list[str]:
    value = parent.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        _fail(path + key, "must be a list of non-empty strings")
    if pattern is not None:
        for item in value:
            if not pattern.match(item):
                _fail(path + key, f"entry {item!r} is malformed" + (f" (expected {expect})" if expect else ""))
    return list(value)


def _https_url(parent: dict, key: str, path: str, *, required: bool = False) -> str | None:
    value = _string(parent, key, path, required=required)
    if value is not None and not value.lower().startswith("https://"):
        _fail(path + key, "must be an https:// URL")
    return value


def _sha256(parent: dict, key: str, path: str) -> str:
    value = _string(parent, key, path, required=True)
    assert value is not None
    if not SHA256_RE.match(value):
        _fail(path + key, "must be a 64-char hex digest")
    return value.lower()


def _datetime(parent: dict, key: str, path: str) -> None:
    value = _string(parent, key, path)
    if value is None:
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(path + key, f"{value!r} is not an ISO-8601 timestamp")


def _relative_path(parent: dict, key: str, path: str, *, required: bool = False) -> str | None:
    """Artifact-relative: no absolute paths, no ``..`` escapes, no NUL."""
    value = _string(parent, key, path, required=required)
    if value is None:
        return None
    if value.startswith("/") or "\x00" in value or any(part == ".." for part in value.split("/")):
        _fail(path + key, f"{value!r} must be a relative path inside the artifact")
    return value


# ---------------------------------------------------------------------------
# Block checks, in SPEC order
# ---------------------------------------------------------------------------

def _check_identity(data: dict, origin: str | None) -> dict:
    block = _req_dict(data, "identity", "")
    name = _string(block, "name", "identity.", required=True, pattern=NAME_RE,
                   expect="[a-z0-9][a-z0-9_-]*")
    assert name is not None
    if len(name) > NAME_MAX_LEN:
        _fail("identity.name", f"is longer than {NAME_MAX_LEN} characters")
    publisher = _string(block, "publisher", "identity.", pattern=PUBLISHER_RE,
                        expect="a lowercase DNS name such as ext.example.com")
    derived = False
    if publisher is None:
        # v0.2 document (SPEC §13): derive the namespace from the manifest
        # origin when the caller knows it; flag it so tooling can nudge the
        # publisher to add the field.
        if origin and PUBLISHER_RE.match(origin):
            publisher, derived = origin, True
        else:
            _fail("identity.publisher", "is required (and no origin to derive it from)")
    _string(block, "version", "identity.", required=True, pattern=SEMVER_RE,
            expect="semver MAJOR.MINOR.PATCH")
    _string(block, "display_name", "identity.", required=True)
    _string(block, "description", "identity.", required=True)
    _https_url(block, "homepage", "identity.")
    _string_list(block, "keywords", "identity.")
    return {"publisher": publisher, "publisher_derived": derived, "name": name,
            "ext_id": f"{publisher}/{name}", "version": block["version"]}


def _check_provides(data: dict) -> list[str]:
    """Validate core component types; unknown types are ignored (§2.4).
    Returns the normalized (aliased) list of component types present."""
    block = _req_dict(data, "provides", "")
    present: list[str] = []
    for raw_key, items in block.items():
        key = PROVIDES_ALIASES.get(raw_key, raw_key)
        if key == "config":
            config = _opt_dict(block, raw_key, "provides.") or {}
            _relative_path(config, "schema_ref", "provides.config.")
            _string_list(config, "secrets", "provides.config.")
            present.append("config")
            continue
        required = PROVIDES_TYPES.get(key)
        if required is None:
            continue  # unknown / x- vendor type: not interpreted, never refused
        if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
            _fail(f"provides.{raw_key}", "must be a list of objects")
        for index, item in enumerate(items):
            for field in required:
                if field == "name" and raw_key == "persona" and "name" not in item:
                    continue  # v0.2 persona fragments had no name
                _string(item, field, f"provides.{raw_key}[{index}].", required=True)
            if key == "mcp_servers":
                _enum(item, "transport", f"provides.{raw_key}[{index}].", MCP_TRANSPORTS)
        present.append(key)
    return present


def _check_requires(data: dict) -> None:
    block = _opt_dict(data, "requires", "")
    if block is None:
        return
    raw_exts = block.get("extensions")
    if raw_exts is not None:
        if not isinstance(raw_exts, list):
            _fail("requires.extensions", "must be a list")
        for index, entry in enumerate(raw_exts):
            if isinstance(entry, str) and entry.strip():
                continue  # v0.2 shorthand "some-ext >= 1.0" (SPEC §13)
            if not isinstance(entry, dict):
                _fail(f"requires.extensions[{index}]", "must be an object {id, version}")
            _string(entry, "id", f"requires.extensions[{index}].", required=True,
                    pattern=EXT_ID_RE, expect="<publisher>/<name>")
            _string(entry, "version", f"requires.extensions[{index}].",
                    pattern=VERSION_RANGE_RE, expect="e.g. '>=1.0 <2'")
    resources = _opt_dict(block, "resources", "requires.")
    if resources is not None:
        for key in ("disk_mb", "ram_mb"):
            value = resources.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                _fail(f"requires.resources.{key}", "must be a non-negative integer")
    _string_list(block, "commands", "requires.")


def _check_permissions(data: dict) -> None:
    block = _opt_dict(data, "permissions", "") or {}
    unknown = sorted(set(block) - set(PERMISSION_KEYS))
    if unknown:
        _fail("permissions", f"has unknown keys {unknown} (known: {list(PERMISSION_KEYS)})")
    _string_list(block, "network_egress", "permissions.", pattern=EGRESS_RE, expect="host[:port]")
    _string_list(block, "network_ingress", "permissions.", pattern=INGRESS_RE, expect="[addr:]port/tcp|udp")
    _string_list(block, "filesystem", "permissions.", pattern=FS_SCOPE_RE,
                 expect="<scope>:r|rw or <runtime>:<scope>:r|rw")
    _string_list(block, "secrets", "permissions.")
    root = block.get("root")
    if root is not None and not isinstance(root, bool):
        _fail("permissions.root", "must be true or false")
    reason = block.get("reason")
    if isinstance(reason, dict):
        for key, text in reason.items():
            if not isinstance(text, str):
                _fail(f"permissions.reason.{key}", "must be a string")
    elif reason is not None and not isinstance(reason, str):
        _fail("permissions.reason", "must be a string or an object of strings")


def _check_release(data: dict) -> str | None:
    block = _opt_dict(data, "release", "")
    if block is None:
        return None
    channel = _string(block, "channel", "release.", required=True, pattern=CHANNEL_RE,
                      expect="dev|alpha|beta|stable or a custom lowercase name")
    _datetime(block, "published_at", "release.")
    _datetime(block, "valid_until", "release.")
    artifact = _req_dict(block, "artifact", "release.")
    _https_url(artifact, "url", "release.artifact.", required=True)
    _sha256(artifact, "sha256", "release.artifact.")
    return channel


def _check_updates(data: dict) -> None:
    block = _opt_dict(data, "updates", "")
    if block is None:
        return
    source = _req_dict(block, "source", "updates.")
    kind = _enum(source, "kind", "updates.source.", tuple(UPDATE_SOURCE_KINDS))
    if kind is None:
        _fail("updates.source.kind", "is required")
    if kind == "github":
        _string(source, "repo", "updates.source.", required=True,
                pattern=GITHUB_REPO_RE, expect="owner/repo")
    else:
        _https_url(source, "url", "updates.source.", required=True)
        if kind == "forge":
            _string(source, "repo", "updates.source.", required=True)
    _enum(block, "check", "updates.", UPDATE_CHECKS)
    _enum(block, "policy", "updates.", UPDATE_POLICIES)


def _check_signing(data: dict) -> bool:
    signing = _opt_dict(data, "signing", "")
    signature = _string(data, "signature", "")
    signature_prev = _string(data, "signature_prev", "")
    if signing is None:
        if signature is not None or signature_prev is not None:
            _fail("signature", "present without a signing block")
        return False
    if signature is None:
        _fail("signature", "missing although a signing block is present")
    _string(signing, "public_key", "signing.", required=True,
            pattern=ED25519_KEY_RE, expect="ed25519:<base64 of 32 raw bytes>")
    _string(signing, "next_key", "signing.", pattern=ED25519_KEY_RE,
            expect="ed25519:<base64 of 32 raw bytes>")
    return True


def _check_target(entry: Any, index: int) -> str:
    if not isinstance(entry, dict):
        _fail(f"targets[{index}]", "must be an object")
    path = f"targets[{index}]."
    runtime = _string(entry, "runtime", path, required=True, pattern=RUNTIME_ID_RE,
                      expect="posix, a registered runtime id, or a reverse-DNS id")
    assert runtime is not None
    _string(entry, "runtime_version", path, pattern=VERSION_RANGE_RE, expect="e.g. '>=2026.6'")
    _string_list(entry, "platforms", path, pattern=PLATFORM_RE, expect="os/arch such as linux/amd64")
    _enum(entry, "enforcement", path, ENFORCEMENT_TIERS)

    delivery = _req_dict(entry, "delivery", path)
    method = _string(delivery, "method", path + "delivery.", required=True)
    if method == DELIVERY_ARCHIVE:
        _https_url(delivery, "url", path + "delivery.", required=True)
        _sha256(delivery, "sha256", path + "delivery.")
        _enum(delivery, "format", path + "delivery.", ARCHIVE_FORMATS)
    elif method == DELIVERY_HERMES:
        if runtime != "hermes":
            _fail(path + "delivery.method", f"{DELIVERY_HERMES!r} is only valid on the hermes target")
        _https_url(delivery, "install_url", path + "delivery.", required=True)
        _sha256(delivery, "install_sha256", path + "delivery.")
        _string(delivery, "uninstall_command", path + "delivery.", required=True)
    # Other methods (clawhub, x-…) are runtime-profile territory: the core
    # only requires that `method` names them (§5.2).

    lifecycle = _req_dict(entry, "lifecycle", path)
    unknown = sorted(set(lifecycle) - set(LIFECYCLE_HOOKS))
    if unknown:
        _fail(path + "lifecycle", f"has unknown hooks {unknown} (known: {list(LIFECYCLE_HOOKS)})")
    for hook in LIFECYCLE_HOOKS:
        _relative_path(lifecycle, hook, path + "lifecycle.",
                       required=hook in REQUIRED_LIFECYCLE_HOOKS)

    component_map = _opt_dict(entry, "component_map", path)
    if component_map:
        for key, value in component_map.items():
            if not isinstance(value, (str, dict)):
                _fail(path + f"component_map.{key}", "must be a string or an object")
    return runtime


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def validate(data: Any, *, origin: str | None = None) -> dict:
    """Validate a whole decoded AXP manifest (every target).

    ``origin`` is the registrable domain the manifest was fetched from, used
    only to derive a missing v0.2 ``identity.publisher`` (SPEC §13).
    Returns a summary: ``{ext_id, publisher, publisher_derived, name,
    version, channel, signed, runtimes, provides}``.
    """
    if not is_axp_manifest(data):
        raise ManifestError(f"kind: must be {AXP_KIND!r}")
    raw = _string(data, "spec_version", "", required=True, pattern=SPEC_VERSION_RE,
                  expect="0.MINOR")
    assert raw is not None
    if int(raw.split(".", 1)[0]) not in SUPPORTED_SPEC_MAJORS:
        _fail("spec_version", f"{raw!r} is not supported (this library understands 0.x)")

    identity = _check_identity(data, origin)
    provides = _check_provides(data)
    _check_requires(data)
    _check_permissions(data)
    channel = _check_release(data)
    _check_updates(data)
    signed = _check_signing(data)

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        _fail("targets", "must be a non-empty list")
    runtimes = [_check_target(entry, index) for index, entry in enumerate(targets)]

    return {
        **identity,
        "channel": channel or "stable",
        "signed": signed,
        "runtimes": runtimes,
        "provides": provides,
    }


def select_target(data: dict, *, runtimes: tuple[str, ...],
                  platform: str | None = None) -> tuple[dict, str]:
    """The target a host speaking ``runtimes`` (preference order; include
    ``posix`` last to opt in to the §5.1 fallback) on ``platform`` installs.
    Returns ``(target, runtime)``; raises with a message naming what the
    manifest offers when nothing matches."""
    if platform is None:
        platform = host_platform()
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ManifestError("targets: must be a non-empty list")
    offered = sorted({str(t["runtime"]) for t in targets if isinstance(t, dict) and t.get("runtime")})
    for runtime in runtimes:
        for entry in targets:
            if not isinstance(entry, dict) or entry.get("runtime") != runtime:
                continue
            platforms = entry.get("platforms") or []
            if not platforms or platform in platforms:
                return entry, runtime
    raise ManifestError(
        f"no targets[] entry this host can install — it speaks {list(runtimes)} "
        f"on {platform}; the manifest offers {offered}"
    )
