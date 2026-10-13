"""AXP 0.5 panel declarations: a standalone, stdlib-only host building block.

This module may be byte-vendored without the rest of axp. Validation performs
no I/O, URL normalization, routing, authentication or capability filtering.
Hosts must separately enforce proxy isolation and lifecycle revocation.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import NoReturn


class PanelViewError(ValueError):
    """An invalid panel declaration; the message identifies its manifest field."""


def _fail(field: str, message: str) -> NoReturn:
    raise PanelViewError(f"{field}: {message}")


def _string(item: dict, field: str, prefix: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        _fail(prefix + field, "must be a non-empty string")
    return value


def validate_panel_views(provides: dict) -> list[dict]:
    """Check a provides block and return detached copies of its view entries.

    Absent/empty panel_views returns []; invalid input raises PanelViewError.
    All capability strings and unknown fields are retained, not interpreted.
    Only referenced services are checked; ordinary service protocols are not
    constrained. Bearer syntax follows AXP's existing state:token-file contract.
    """
    if not isinstance(provides, dict):
        _fail("provides", "must be an object")
    views = provides.get("panel_views", [])
    if not isinstance(views, list) or not all(isinstance(v, dict) for v in views):
        _fail("provides.panel_views", "must be a list of objects")
    seen: set[str] = set()
    for index, view in enumerate(views):
        prefix = f"provides.panel_views[{index}]."
        for field in ("name", "service"):
            value = _string(view, field, prefix)
            if len(value) > 64 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value):
                _fail(prefix + field, "must be a safe slug of at most 64 characters")
        if view["name"] in seen:
            _fail(prefix + "name", "duplicate view name")
        seen.add(view["name"])
        _string(view, "title", prefix)
        mount_path = _string(view, "path", prefix)
        # Never normalize untrusted paths across different URI decoders.
        if (not re.fullmatch(r"/[A-Za-z0-9/._~!$&'()*+,;=:@-]*", mount_path)
                or "//" in mount_path
                or any(part in (".", "..") for part in mount_path.split("/"))):
            _fail(prefix + "path", "must be an unencoded root-relative URI path without traversal or empty segments")
        if "icon" in view:
            _string(view, "icon", prefix)
        capabilities = view.get("capabilities")
        if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
            _fail(prefix + "capabilities", "must be a list of strings")
        services = provides.get("services", [])
        if not isinstance(services, list) or not all(isinstance(s, dict) for s in services):
            _fail(prefix + "service", "requires a services list of objects")
        matches = [s for s in services if s.get("name") == view["service"]]
        if len(matches) != 1:
            _fail(prefix + "service", "must reference exactly one provides.services entry")
        service = matches[0]
        endpoint = _string(service, "endpoint", prefix + "service.")
        origin = re.fullmatch(r"http://(?:127\.0\.0\.1|\[::1\]):([0-9]{1,5})/?", endpoint)
        if origin is None or not 1 <= int(origin[1]) <= 65535:
            _fail(prefix + "service.endpoint", "must be an http loopback literal origin with explicit port 1-65535")
        auth = service.get("auth")
        if auth is not None:
            auth_prefix = prefix + "service.auth."
            if not isinstance(auth, dict):
                _fail(prefix + "service.auth", "must be an object")
            scheme = _string(auth, "scheme", auth_prefix)
            if scheme == "bearer":
                token_file = _string(auth, "token_file", auth_prefix)
                scope, sep, relative = token_file.partition(":")
                if not sep or scope != "state":
                    _fail(auth_prefix + "token_file", "must be 'state:<relative path>'")
                if (not relative or relative.startswith("/") or "\x00" in relative
                        or any(part == ".." for part in relative.split("/"))):
                    _fail(auth_prefix + "token_file", "must name a file inside the state scope")
            # Unknown schemes are structurally valid (AXP 2.4). Hosts must not
            # proxy them until supported; they must never guess a credential.
    return deepcopy(views)
