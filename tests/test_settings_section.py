"""A settings section is host-rendered text bound to the extension's lifecycle."""
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

from axp import manifest

REPO = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
NEWLINE, TAB = chr(10), chr(9)


@pytest.fixture
def section(example):
    example["provides"] = {
        "services": [{"name": "desktop", "kind": "daemon", "endpoint": "http://127.0.0.1:6080"}],
        "panel_views": [{"name": "desktop", "title": "Desktop", "service": "desktop",
                         "path": "/desktop/", "capabilities": ["pin"]}],
        "settings_section": {
            "title": "Agent desktop",
            "summary": "A shared desktop for you and your agent, right in your browser.",
            "icon": "monitor",
            "views": ["desktop"],
            "localized": {"et": {"title": "Agendi töölaud"},
                          "pt-BR": {"summary": "Uma área de trabalho compartilhada."}},
        },
    }
    return example


def test_helper_is_standalone_and_returns_a_detached_section(section):
    spec = importlib.util.spec_from_file_location("vendored_settings", REPO / "axp/settings_section.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    declared = section["provides"]["settings_section"]
    found = module.validate_settings_section(section["provides"])
    assert found == declared
    found["views"].append("changed")
    assert declared["views"] == ["desktop"]
    assert module.validate_settings_section({}) is None


def test_section_is_a_known_component_valid_against_the_schema(section):
    assert "settings_section" in manifest.validate(section)["provides"]
    jsonschema.validate(section, SCHEMA)


def test_a_section_without_views_needs_no_panel(section):
    section["provides"] = {"settings_section": {"title": "Notes", "summary": "Keeps your notes in sync."}}
    assert "settings_section" in manifest.validate(section)["provides"]
    jsonschema.validate(section, SCHEMA)


@pytest.mark.parametrize("change", [
    {"title": None}, {"title": ""}, {"title": "   "}, {"title": "x" * 61}, {"title": "two" + NEWLINE + "lines"},
    {"summary": None}, {"summary": "x" * 401}, {"summary": "tab" + TAB + "here"},
    {"icon": None}, {"icon": ""},
    {"views": "desktop"}, {"views": [7]}, {"views": ["absent"]}, {"views": ["desktop", "desktop"]},
    {"localized": []}, {"localized": {"not a tag": {"title": "x"}}}, {"localized": {"et": "x"}},
    {"localized": {"et": {}}}, {"localized": {"et": {"title": ""}}},
    {"localized": {"et": {"summary": "x" * 401}}},
])
def test_invalid_sections_are_refused(section, change):
    section["provides"]["settings_section"].update(change)
    with pytest.raises(manifest.ManifestError, match="settings_section"):
        manifest.validate(section)


@pytest.mark.parametrize("missing", ["title", "summary"])
def test_title_and_summary_are_required(section, missing):
    del section["provides"]["settings_section"][missing]
    with pytest.raises(manifest.ManifestError, match="settings_section." + missing):
        manifest.validate(section)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(section, SCHEMA)


@pytest.mark.parametrize("provides", [None, [], {"settings_section": None}, {"settings_section": []}])
def test_standalone_helper_rejects_invalid_shapes(provides):
    from axp.settings_section import SettingsSectionError, validate_settings_section
    with pytest.raises(SettingsSectionError):
        validate_settings_section(provides)


@pytest.mark.parametrize("change", [{"title": ""}, {"summary": "x" * 401}, {"views": ["desktop", "desktop"]},
                                    {"localized": {"not a tag": {"title": "x"}}}, {"localized": {"et": {}}}])
def test_schema_checks_section_metadata(section, change):
    section["provides"]["settings_section"].update(change)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(section, SCHEMA)


def test_unknown_fields_are_kept_not_interpreted(section):
    from axp.settings_section import validate_settings_section
    section["provides"]["settings_section"]["x-accent"] = "teal"
    assert manifest.validate(section)
    assert validate_settings_section(section["provides"])["x-accent"] == "teal"


def test_unsigned_panel_example_declares_its_settings_section():
    doc = json.loads((REPO / "examples/panel-view/agent-extension.json").read_text())
    jsonschema.validate(doc, SCHEMA)
    assert "settings_section" in manifest.validate(doc)["provides"]
