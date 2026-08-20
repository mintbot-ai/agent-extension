"""Core profile (SPEC §11): read manifests per §2.4, select targets per §5."""

import pytest


def test_accepts_the_worked_example(adapter, example):
    adapter.validate(example)


def test_ignores_unknown_fields_and_component_types(adapter, example):
    """§2.4: unknown fields, x- vendor entries and unknown provides types
    MUST NOT cause refusal."""
    example["x-vendor-block"] = {"anything": [1, 2, 3]}
    example["future_field"] = "whatever"
    example["provides"]["x-vendor-widgets"] = [{"name": "w"}]
    example["provides"]["holograms"] = "not even a list"
    example["targets"][0]["x-vendor-hint"] = True
    adapter.validate(example)


@pytest.mark.parametrize("mutate", [
    lambda m: m["permissions"].__setitem__("camera", True),          # unknown permission key
    lambda m: m["targets"][0].__setitem__("enforcement", "total"),   # unknown enforcement tier
    lambda m: m["updates"].__setitem__("policy", "yolo"),            # unknown update policy
], ids=["permission-key", "enforcement-tier", "update-policy"])
def test_refuses_unknown_security_relevant_enums(adapter, example, mutate):
    """§2.4: security-relevant unknowns MUST refuse (guessing would
    over-promise or under-warn)."""
    mutate(example)
    with pytest.raises(Exception):
        adapter.validate(example)


@pytest.mark.parametrize("mutate", [
    lambda m: m["identity"].pop("publisher"),                        # no namespace, no origin
    lambda m: m["targets"][0]["delivery"].__setitem__("sha256", "nope"),
    lambda m: m["targets"][0]["delivery"].__setitem__("url", "http://x.example/a.tgz"),
    lambda m: m["targets"][0]["lifecycle"].__setitem__("install", "../../etc/cron.d/x"),
    lambda m: m["targets"][0]["lifecycle"].pop("uninstall"),
], ids=["publisher", "digest", "plain-http", "path-escape", "no-uninstall"])
def test_refuses_structural_violations(adapter, example, mutate):
    mutate(example)
    with pytest.raises(Exception):
        adapter.validate(example)


def test_v02_publisher_derives_from_origin(adapter, example):
    del example["identity"]["publisher"]
    adapter.validate(example, origin="pub.example.org")


def test_target_selection_and_posix_fallback(adapter, example):
    assert adapter.select_runtime(example, ("hermes", "posix"), "linux/amd64") == "hermes"
    # §5: platforms constrain; §5.1: posix is the fallback.
    hermes = next(t for t in example["targets"] if t["runtime"] == "hermes")
    hermes["platforms"] = ["linux/arm64"]
    assert adapter.select_runtime(example, ("hermes", "posix"), "linux/amd64") == "posix"
    with pytest.raises(Exception):
        adapter.select_runtime(example, ("openclaw",), "linux/amd64")
