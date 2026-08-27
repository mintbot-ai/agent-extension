"""axp.manifest — validation and target selection."""

import pytest

from axp import manifest


def test_example_validates(example):
    summary = manifest.validate(example)
    assert summary["ext_id"] == "ext.example.com/sample-memory"
    assert summary["publisher_derived"] is False
    assert summary["channel"] == "stable" and summary["signed"] is True
    assert summary["runtimes"] == ["posix", "hermes", "claude-code"]
    assert "mcp_servers" in summary["provides"]


def test_v02_publisher_derived_from_origin(example):
    del example["identity"]["publisher"]
    summary = manifest.validate(example, origin="pub.example.org")
    assert summary["publisher"] == "pub.example.org" and summary["publisher_derived"] is True
    with pytest.raises(manifest.ManifestError, match="identity.publisher"):
        manifest.validate(example)


@pytest.mark.parametrize("mutate,fragment", [
    (lambda m: m.__setitem__("kind", "plugin"), "kind"),
    (lambda m: m.__setitem__("spec_version", "1.0"), "spec_version"),
    (lambda m: m["identity"].__setitem__("version", "1.0"), "identity.version"),
    (lambda m: m["permissions"].__setitem__("camera", True), "unknown keys"),
    (lambda m: m["permissions"].__setitem__("network_egress", ["https://x"]), "network_egress"),
    (lambda m: m["release"].__setitem__("channel", "Stable"), "release.channel"),
    (lambda m: m["updates"]["source"].__setitem__("kind", "torrent"), "updates.source.kind"),
    (lambda m: m["targets"][0]["lifecycle"].pop("uninstall"), "lifecycle.uninstall"),
    (lambda m: m["targets"][0]["lifecycle"].__setitem__("install", "../evil"), "relative path"),
    (lambda m: m["targets"][0].__setitem__("enforcement", "sandboxed"), "enforcement"),
    (lambda m: m["signing"].__setitem__("public_key", "rsa:AAAA"), "signing.public_key"),
    (lambda m: m.pop("signing"), "signature"),
])
def test_rejections(example, mutate, fragment):
    mutate(example)
    with pytest.raises(manifest.ManifestError, match=fragment):
        manifest.validate(example)


def test_forward_compat_ignores_unknown_fields_and_types(example):
    example["x-acme-billing"] = {"plan": "pro"}
    example["future_block"] = 7
    example["provides"]["x-acme-widgets"] = "anything"
    example["targets"][0]["x-note"] = True
    assert manifest.validate(example)["name"] == "sample-memory"


def test_v02_aliases(example):
    example["provides"]["persona"] = example["provides"].pop("prompts")
    example["requires"]["extensions"] = ["other-ext >= 1.0"]
    summary = manifest.validate(example)
    assert "prompts" in summary["provides"]


def test_select_target_prefers_host_order_and_platforms(example):
    target, runtime = manifest.select_target(example, runtimes=("hermes", "posix"), platform="linux/amd64")
    assert runtime == "hermes"
    # Hermes target excluded by platform -> posix fallback.
    next(t for t in example["targets"] if t["runtime"] == "hermes")["platforms"] = ["linux/arm64"]
    target, runtime = manifest.select_target(example, runtimes=("hermes", "posix"), platform="linux/amd64")
    assert runtime == "posix"
    # Host without the posix fallback refuses, naming what is offered.
    with pytest.raises(manifest.ManifestError, match="posix"):
        manifest.select_target(example, runtimes=("openclaw",), platform="linux/amd64")


def test_select_target_honours_runtime_version(example):
    hermes = next(t for t in example["targets"] if t["runtime"] == "hermes")
    hermes["runtime_version"] = ">=2026.6"
    _target, runtime = manifest.select_target(
        example, runtimes=("hermes", "posix"), platform="linux/amd64",
        runtime_versions={"hermes": "2026.8.3"})
    assert runtime == "hermes"
    _target, runtime = manifest.select_target(
        example, runtimes=("hermes", "posix"), platform="linux/amd64",
        runtime_versions={"hermes": "2026.5"})
    assert runtime == "posix"  # too old for the hermes target -> baseline
    with pytest.raises(manifest.ManifestError, match="needs runtime_version"):
        manifest.select_target(example, runtimes=("hermes",), platform="linux/amd64",
                               runtime_versions={"hermes": "2026.5"})
    # Unknown host version: the constraint cannot be checked, target accepted.
    _target, runtime = manifest.select_target(example, runtimes=("hermes",), platform="linux/amd64")
    assert runtime == "hermes"
    hermes["runtime_version"] = ">= 2026.6"
    with pytest.raises(manifest.ManifestError, match="runtime_version"):
        manifest.validate(example)


def test_hermes_integration_delivery_only_on_hermes(example):
    example["targets"][0]["delivery"] = {
        "method": "hermes-integration", "install_url": "https://x.example/a.tgz",
        "install_sha256": "0" * 64, "uninstall_command": "/opt/x/u.sh",
    }
    assert example["targets"][0]["runtime"] == "posix"
    with pytest.raises(manifest.ManifestError, match="only valid on the hermes target"):
        manifest.validate(example)
