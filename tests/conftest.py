"""Shared fixtures: the worked example manifest with digest placeholders filled."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def example() -> dict:
    data = json.loads((REPO / "examples/graph-memory/agent-extension.json").read_text())
    data = copy.deepcopy(data)
    for index, target in enumerate(data["targets"]):
        target["delivery"]["sha256"] = hashlib.sha256(f"artifact-{index}".encode()).hexdigest()
    data["release"]["artifact"]["sha256"] = hashlib.sha256(b"release").hexdigest()
    return data
