"""AXP 0.5 settings sections: a standalone, stdlib-only host building block.

An extension may ask for one section of its own in a host's settings. The
host renders it and owns its controls; the declaration carries only plain
text and references to declared panel views. This module may be
byte-vendored without the rest of axp. Validation performs no I/O.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import NoReturn

TITLE_MAX = 60
SUMMARY_MAX = 400
_LANGUAGE_TAG = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*")


class SettingsSectionError(ValueError):
    """An invalid settings section; the message identifies its manifest field."""


def _fail(field: str, message: str) -> NoReturn:
    raise SettingsSectionError(f"{field}: {message}")


def _text(item: dict, field: str, prefix: str, limit: int) -> None:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        _fail(prefix + field, "must be a non-empty string")
    if len(value) > limit:
        _fail(prefix + field, f"must be at most {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(prefix + field, "must be plain text without control characters")


def validate_settings_section(provides: dict) -> dict | None:
    """Check a provides block and return a detached copy of its section.

    Absent returns None; invalid input raises SettingsSectionError. Unknown
    fields are retained, not interpreted. ``views`` must name declared panel
    views; the views themselves are checked by ``validate_panel_views``.
    """
    if not isinstance(provides, dict):
        _fail("provides", "must be an object")
    if "settings_section" not in provides:
        return None
    section = provides["settings_section"]
    prefix = "provides.settings_section."
    if not isinstance(section, dict):
        _fail("provides.settings_section", "must be an object")
    _text(section, "title", prefix, TITLE_MAX)
    _text(section, "summary", prefix, SUMMARY_MAX)
    if "icon" in section and (not isinstance(section["icon"], str) or not section["icon"].strip()):
        _fail(prefix + "icon", "must be a non-empty string")
    views = section.get("views", [])
    if not isinstance(views, list) or not all(isinstance(view, str) for view in views):
        _fail(prefix + "views", "must be a list of panel view names")
    if len(set(views)) != len(views):
        _fail(prefix + "views", "must not name a view twice")
    declared = provides.get("panel_views", [])
    names = ({view.get("name") for view in declared if isinstance(view, dict)}
             if isinstance(declared, list) else set())
    for index, view in enumerate(views):
        if view not in names:
            _fail(f"{prefix}views[{index}]", "must name a provides.panel_views entry")
    localized = section.get("localized", {})
    if not isinstance(localized, dict):
        _fail(prefix + "localized", "must be an object keyed by language tag")
    for tag, texts in localized.items():
        if not isinstance(tag, str) or not _LANGUAGE_TAG.fullmatch(tag):
            _fail(prefix + "localized", f"{tag!r} is not a BCP 47 language tag")
        where = f"{prefix}localized.{tag}"
        if not isinstance(texts, dict) or not {"title", "summary"} & set(texts):
            _fail(where, "must be an object with a title and/or a summary")
        for field, limit in (("title", TITLE_MAX), ("summary", SUMMARY_MAX)):
            if field in texts:
                _text(texts, field, where + ".", limit)
    return deepcopy(section)
