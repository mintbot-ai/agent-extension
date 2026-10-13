"""AXP 0.5 declaration conformance; live proxy enforcement is host-tested."""
import copy
import json
from pathlib import Path

import pytest


@pytest.fixture
def panel_manifest():
    return json.loads((Path(__file__).resolve().parents[1] /
                       "examples/panel-view/agent-extension.json").read_text())


def test_panel_example_and_optional_hooks(adapter, panel_manifest):
    adapter.validate(panel_manifest)


def test_unknown_capabilities_are_not_rejected(adapter, panel_manifest):
    panel_manifest["provides"]["panel_views"][0]["capabilities"].append("future-layout")
    adapter.validate(panel_manifest)


@pytest.mark.parametrize("field,value", [
    ("name", "../view"), ("path", "//example.com"), ("path", "/../secret"),
    ("path", "/%252e%252e/"), ("path", "/%2Fadmin"), ("path", "/a\\b"),
    ("path", "/a?token=x"), ("path", "/a#x"), ("service", "missing"),
    ("capabilities", [True]),
])
def test_rejects_unsafe_panel_declarations(adapter, panel_manifest, field, value):
    panel_manifest["provides"]["panel_views"][0][field] = value
    with pytest.raises(Exception):
        adapter.validate(panel_manifest)


@pytest.mark.parametrize("endpoint", [
    "http://localhost:6080", "http://127.0.0.1", "http://127.0.0.1:0",
    "http://user@127.0.0.1:6080", "http://127.0.0.1:6080/desktop/",
    "http://127.0.0.1:6080?token=x", "http://127.0.0.1:6080#x",
    "http://[::ffff:127.0.0.1]:6080", "https://127.0.0.1:6080",
])
def test_panel_services_are_literal_loopback_origins(adapter, panel_manifest, endpoint):
    panel_manifest["provides"]["services"][0]["endpoint"] = endpoint
    with pytest.raises(Exception):
        adapter.validate(panel_manifest)


def test_rejects_duplicate_panel_names(adapter, panel_manifest):
    view = copy.deepcopy(panel_manifest["provides"]["panel_views"][0])
    view["title"] = "Other title, same route identity"
    panel_manifest["provides"]["panel_views"].append(view)
    with pytest.raises(Exception):
        adapter.validate(panel_manifest)
