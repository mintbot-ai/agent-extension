"""Panel views are validated before any host proxy can expose them."""
import json
from pathlib import Path
import pytest
import jsonschema

from axp import manifest

REPO = Path(__file__).resolve().parents[1]


def test_helper_is_standalone_and_returns_detached_views(panel):
    import importlib.util
    spec = importlib.util.spec_from_file_location("vendored_panels", REPO / "axp/panel_views.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    views = module.validate_panel_views(panel["provides"])
    assert views == panel["provides"]["panel_views"]
    views[0]["capabilities"].append("changed")
    assert "changed" not in panel["provides"]["panel_views"][0]["capabilities"]
    with pytest.raises(module.PanelViewError):
        module.validate_panel_views({"panel_views": None})


@pytest.mark.parametrize("provides", [None, [], {"panel_views": None}, {"panel_views": {}},
                                      {"panel_views": [None]}])
def test_standalone_helper_rejects_invalid_shapes(provides):
    from axp.panel_views import PanelViewError, validate_panel_views
    with pytest.raises(PanelViewError):
        validate_panel_views(provides)


@pytest.mark.parametrize("provides", [{}, {"panel_views": []},
                                      {"services": [{"name": "db", "endpoint": "tcp://remote:6379"}]}])
def test_absent_views_do_not_constrain_other_services(provides):
    from axp.panel_views import validate_panel_views
    assert validate_panel_views(provides) == []


@pytest.mark.parametrize("auth", ["bearer", {}, {"scheme": "bearer"},
                                 {"scheme": "bearer", "token_file": "config:token"},
                                 {"scheme": "bearer", "token_file": "state:"},
                                 {"scheme": "bearer", "token_file": "state:/absolute"}])
def test_standalone_bearer_contract_rejections(panel, auth):
    from axp.panel_views import PanelViewError, validate_panel_views
    panel["provides"]["services"][0]["auth"] = auth
    with pytest.raises(PanelViewError, match="auth"):
        validate_panel_views(panel["provides"])


def test_unknown_auth_scheme_is_structurally_forward_compatible(panel):
    from axp.panel_views import validate_panel_views
    panel["provides"]["services"][0]["auth"] = {"scheme": "future-auth", "token_file": 7}
    assert validate_panel_views(panel["provides"])


def test_current_draft_and_publisher_skeleton():
    import axp
    from axp.publish import skeleton
    assert axp.__version__ == "0.5.0"
    doc = skeleton(publisher="ext.example.com", name="test", display_name="Test", description="Test")
    assert doc["spec_version"] == "0.5"


@pytest.mark.parametrize("path", ["//evil", "/../x", "/%2e%2e/", "/a\\b", "/x?q", "/x#f", "/a\n"])
def test_schema_rejects_unsafe_paths(panel, path):
    panel["provides"]["panel_views"][0]["path"] = path
    schema = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(panel, schema)


def test_unsigned_panel_example():
    doc = json.loads((REPO / "examples/panel-view/agent-extension.json").read_text())
    schema = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
    jsonschema.validate(doc, schema)
    assert manifest.validate(doc)["signed"] is False
    assert doc["spec_version"] == "0.5"
    assert "panel_views" in doc["provides"]


def test_schema_accepts_optional_lifecycle(panel):
    panel["targets"][0]["lifecycle"].update(enable="enable.sh", disable="disable.sh")
    schema = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
    jsonschema.validate(panel, schema)


@pytest.mark.parametrize("field,value", [("capabilities", [7]), ("name", "../x"), ("service", "../x"), ("title", ""), ("icon", None)])
def test_schema_checks_panel_metadata(panel, field, value):
    panel["provides"]["panel_views"][0][field] = value
    schema = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(panel, schema)


@pytest.fixture
def panel(example):
    example["provides"] = {
        "services": [{"name": "desktop", "kind": "daemon", "endpoint": "http://127.0.0.1:6080"}],
        "panel_views": [{"name": "desktop", "title": "Desktop", "icon": "monitor",
                         "service": "desktop", "path": "/desktop/", "capabilities": ["pin", "fullscreen"]}],
    }
    return example


@pytest.mark.parametrize("hook", ["enable", "disable"])
def test_optional_managed_lifecycle_hooks(panel, hook):
    panel["targets"][0]["lifecycle"][hook] = f"scripts/{hook}.sh"
    manifest.validate(panel)
    panel["targets"][0]["lifecycle"][hook] = "../escape.sh"
    with pytest.raises(manifest.ManifestError, match="relative path"):
        manifest.validate(panel)


def test_panel_views_are_known_components(panel):
    assert "panel_views" in manifest.validate(panel)["provides"]


@pytest.mark.parametrize("field,value", [
    ("name", "../x"), ("name", "UPPER"), ("name", "x\n"), ("name", "x" * 65),
    ("service", "absent"), ("service", "../desktop"), ("icon", 7), ("icon", None),
    ("capabilities", None), ("capabilities", "pin"), ("capabilities", [7]),
])
def test_invalid_panel_metadata(panel, field, value):
    panel["provides"]["panel_views"][0][field] = value
    with pytest.raises(manifest.ManifestError, match="panel_views"):
        manifest.validate(panel)


def test_duplicate_view_names(panel):
    panel["provides"]["panel_views"] *= 2
    with pytest.raises(manifest.ManifestError, match="duplicate"):
        manifest.validate(panel)


def test_ambiguous_service_reference(panel):
    panel["provides"]["services"] *= 2
    with pytest.raises(manifest.ManifestError, match="service"):
        manifest.validate(panel)


def test_capabilities_required(panel):
    del panel["provides"]["panel_views"][0]["capabilities"]
    with pytest.raises(manifest.ManifestError, match="capabilities"):
        manifest.validate(panel)


def test_exported_helper_accepts_provides_without_mutation(panel):
    import copy
    import axp
    provides = panel["provides"]
    provides["panel_views"][0]["capabilities"] = ["pin", "future-capability", ""]
    before = copy.deepcopy(provides)
    assert axp.validate_panel_views(provides) == provides["panel_views"]
    assert provides == before


BAD_PATHS = ["relative", "//evil", "/a//b", "/../x", "/a/./b", "/a/..", "/a\\b",
             "/%2e%2e/", "/%2f/x", "/%5c/x", "/%252e%252e/", "/%", "/a?x", "/a#x",
             "/a\n", "/a\x00", "/a\x7f", "/a b", "/café"]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_rejects_unsafe_mount_paths(panel, path):
    panel["provides"]["panel_views"][0]["path"] = path
    with pytest.raises(manifest.ManifestError, match="path"):
        manifest.validate_panel_views(panel["provides"])


@pytest.mark.parametrize("path", ["/", "/desktop", "/desktop/", "/desktop/index.html", "/v1.2/a-b_~!"])
def test_accepts_unambiguous_paths(panel, path):
    panel["provides"]["panel_views"][0]["path"] = path
    manifest.validate_panel_views(panel["provides"])


@pytest.mark.parametrize("path,subtree", [
    ("/", "/"), ("/desktop", "/"), ("/desktop/", "/desktop/"),
    ("/desktop/index.html", "/desktop/"),
])
def test_documented_entry_paths_and_proxy_subtrees(panel, path, subtree):
    # Routing is host-owned. Lock down its normative examples without adding
    # a routing implementation to this declaration-only validator.
    panel["provides"]["panel_views"][0]["path"] = path
    manifest.validate(panel)
    schema = json.loads((REPO / "schema/agent-extension.schema.json").read_text())
    jsonschema.validate(panel, schema)
    spec = (REPO / "SPEC.md").read_text()
    assert f"| `{path}` | `{subtree}` |" in spec


BAD_ENDPOINTS = [
    "https://127.0.0.1:6080", "http://localhost:6080", "http://127.1:6080",
    "http://0.0.0.0:6080", "http://example.com:6080", "http://[::ffff:127.0.0.1]:6080",
    "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536",
    "http://127.0.0.1:abc", "http://user@127.0.0.1:6080", "http://127.0.0.1:6080/x",
    "http://127.0.0.1:6080?", "http://127.0.0.1:6080#", "http://127.0.0.1:6080\n",
    " http://127.0.0.1:6080", "http://[::1%25lo]:6080", None, 7,
]


@pytest.mark.parametrize("endpoint", BAD_ENDPOINTS)
def test_rejects_nonliteral_or_ambiguous_panel_endpoint(panel, endpoint):
    panel["provides"]["services"][0]["endpoint"] = endpoint
    with pytest.raises(manifest.ManifestError, match="endpoint"):
        manifest.validate_panel_views(panel["provides"])


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:1", "http://127.0.0.1:65535/", "http://[::1]:6080/"])
def test_accepts_loopback_origins_and_existing_bearer_contract(panel, endpoint):
    service = panel["provides"]["services"][0]
    service["endpoint"] = endpoint
    service["auth"] = {"scheme": "bearer", "token_file": "state:desktop/token"}
    manifest.validate_panel_views(panel["provides"])
    service["auth"]["token_file"] = "state:../host-token"
    with pytest.raises(manifest.ManifestError, match="token_file"):
        manifest.validate_panel_views(panel["provides"])
