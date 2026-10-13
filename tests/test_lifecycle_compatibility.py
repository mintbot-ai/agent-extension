"""Closed lifecycle compatibility, including the documented pre-0.5 boundary.

The 0.4 vocabulary below is pinned to a3556519fadf91d6af142b886bac4941def5b672.
Its reference validator uses the same closed-set guard as today's validator;
restricting that vocabulary reproduces the old lifecycle acceptance contract.
The old schema has the same lifecycle shape, minus enable/disable properties.
No Git history or network access is needed when running this regression.
"""
import copy
import json
from pathlib import Path

import jsonschema
import pytest

from axp import manifest

REPO = Path(__file__).resolve().parents[1]
PRE_05_HOOKS = ("install", "upgrade", "uninstall", "health")


def schema():
    return json.loads((REPO / "schema/agent-extension.schema.json").read_text())


@pytest.mark.parametrize("hook", ["enable", "disable"])
def test_activation_hooks_require_documented_05_host_upgrade(example, monkeypatch, hook):
    example["spec_version"] = "0.5"
    # Unknown provides components are additive; executable hook keys are not.
    example["provides"]["future_component"] = {"opaque": True}
    old_schema = copy.deepcopy(schema())
    lifecycle = old_schema["properties"]["targets"]["items"]["properties"]["lifecycle"]
    lifecycle["properties"] = {key: lifecycle["properties"][key] for key in PRE_05_HOOKS}
    with monkeypatch.context() as old_host:
        old_host.setattr(manifest, "LIFECYCLE_HOOKS", PRE_05_HOOKS)
        manifest.validate(example)
        jsonschema.validate(example, old_schema)
        example["targets"][0]["lifecycle"][hook] = f"{hook}.sh"
        with pytest.raises(manifest.ManifestError, match="unknown hooks"):
            manifest.validate(example)
        with pytest.raises(jsonschema.ValidationError, match="Additional properties"):
            jsonschema.validate(example, old_schema)
    manifest.validate(example)
    jsonschema.validate(example, schema())

    spec = " ".join((REPO / "SPEC.md").read_text().split())
    assert "Activation hooks require a host upgrade to 0.5" in spec
    assert "`targets[].lifecycle` is a closed vocabulary" in spec


@pytest.mark.parametrize("hook", ["future", "x-acme-start", "hermes:start"])
def test_current_validator_and_schema_keep_lifecycle_closed(example, hook):
    example["targets"][0]["lifecycle"][hook] = "future.sh"
    with pytest.raises(manifest.ManifestError, match="unknown hooks"):
        manifest.validate(example)
    with pytest.raises(jsonschema.ValidationError, match="Additional properties"):
        jsonschema.validate(example, schema())
    spec = " ".join((REPO / "SPEC.md").read_text().split())
    assert "including `x-` and `<runtime>:` hook names" in spec
