"""axp.manifest — one accepted variant and the refusal for every block the
spec defines (provides / requires / permissions / release / updates / signing /
targets), plus the small public helpers. test_manifest.py walks the happy
path; this file pins the grammar edge by edge so a schema drift shows up as a
named field, not as a surprise on a client VPS."""

import platform

import pytest

from axp import manifest


def _validate(example):
    return manifest.validate(example)


# --- helpers ------------------------------------------------------------------

def test_public_helpers(example):
    assert manifest.is_axp_manifest(example) is True
    assert manifest.is_axp_manifest({"kind": "agent-extension"}) is True
    assert manifest.is_axp_manifest("agent-extension") is False
    assert manifest.ext_id(example) == "ext.example.com/graph-memory"
    assert manifest.ext_id({}) == "/"
    os_name, arch = manifest.host_platform().split("/")
    assert os_name == platform.system().lower() and arch


def test_validate_refuses_non_objects():
    for bad in (None, [], "x", 7):
        with pytest.raises(manifest.ManifestError, match="kind"):
            manifest.validate(bad)


def test_select_target_refuses_empty_or_missing_targets(example):
    example["targets"] = []
    with pytest.raises(manifest.ManifestError, match="non-empty list"):
        manifest.select_target(example, runtimes=("posix",), platform="linux/amd64")
    del example["targets"]
    with pytest.raises(manifest.ManifestError, match="non-empty list"):
        manifest.select_target(example, runtimes=("posix",), platform="linux/amd64")


# --- identity -----------------------------------------------------------------

@pytest.mark.parametrize("field,value,fragment", [
    ("publisher", "Ext.Example.com", "identity.publisher"),
    ("publisher", "localhost", "identity.publisher"),
    ("name", "x" * 65, "longer than 64"),
    ("name", "Bad Name", "identity.name"),
    ("display_name", "", "identity.display_name"),
    ("homepage", "http://plain.example", "identity.homepage"),
    ("keywords", "memory", "identity.keywords"),
])
def test_identity_rejections(example, field, value, fragment):
    example["identity"][field] = value
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


# --- provides -----------------------------------------------------------------

@pytest.mark.parametrize("mutate,fragment", [
    (lambda p: p.__setitem__("tools", "memory_query"), "provides.tools"),
    (lambda p: p.__setitem__("tools", ["memory_query"]), "provides.tools"),
    (lambda p: p.__setitem__("mcp_servers", [{"name": "m"}]), "transport"),
    (lambda p: p.__setitem__("mcp_servers", [{"name": "m", "transport": "grpc"}]), "transport"),
    (lambda p: p.__setitem__("services", [{"name": "s"}]), "services\\[0\\].kind"),
    (lambda p: p.__setitem__("memory", [{"kind": "graph"}]), "memory\\[0\\].name"),
    (lambda p: p.__setitem__("hooks", [{"name": "h"}]), "hooks\\[0\\].event"),
    (lambda p: p.__setitem__("cron", [{"name": "c"}]), "cron\\[0\\].schedule"),
    (lambda p: p.__setitem__("config", {"schema_ref": "/etc/passwd"}), "provides.config.schema_ref"),
    (lambda p: p.__setitem__("config", {"secrets": "TOKEN"}), "provides.config.secrets"),
    (lambda p: p.__setitem__("config", []), "provides.config"),
])
def test_provides_rejections(example, mutate, fragment):
    mutate(example["provides"])
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


def test_provides_accepts_every_core_type_and_reports_them(example):
    example["provides"] = {
        "mcp_servers": [{"name": "m", "transport": "http", "url": "https://x/mcp"}],
        "tools": [{"name": "t"}],
        "services": [{"name": "s", "kind": "daemon"}],
        "memory": [{"name": "g", "kind": "vector"}],
        "skills": [{"name": "k"}],
        "prompts": [{"name": "p"}],
        "channels": [{"name": "c"}],
        "model_providers": [{"name": "mp"}],
        "hooks": [{"name": "h", "event": "pre_reply"}],
        "cron": [{"name": "cr", "schedule": "0 4 * * *"}],
        "config": {"schema_ref": "schemas/config.json", "secrets": ["A"]},
        "x-vendor": "ignored",
    }
    summary = _validate(example)
    assert summary["provides"] == [
        "mcp_servers", "tools", "services", "memory", "skills", "prompts",
        "channels", "model_providers", "hooks", "cron", "config",
    ]
    # v0.2 persona entries without a name are still readable.
    example["provides"] = {"persona": [{"fragment_ref": "prompts/x.md"}]}
    assert _validate(example)["provides"] == ["prompts"]


# --- requires -----------------------------------------------------------------

@pytest.mark.parametrize("requires,fragment", [
    ({"extensions": "pub/x"}, "requires.extensions: must be a list"),
    ({"extensions": [7]}, "must be an object"),
    ({"extensions": [{"version": ">=1"}]}, "extensions\\[0\\].id"),
    ({"extensions": [{"id": "noslash"}]}, "extensions\\[0\\].id"),
    ({"extensions": [{"id": "pub.example/x", "version": "latest"}]}, "extensions\\[0\\].version"),
    ({"resources": {"disk_mb": -1}}, "disk_mb"),
    ({"resources": {"ram_mb": True}}, "ram_mb"),
    ({"resources": {"ram_mb": "lots"}}, "ram_mb"),
    ({"commands": "docker"}, "requires.commands"),
    (["x"], "requires: must be an object"),
])
def test_requires_rejections(example, requires, fragment):
    example["requires"] = requires
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


def test_requires_accepts_objects_shorthand_and_resources(example):
    example["requires"] = {
        "extensions": [{"id": "pub.example/dep", "version": ">=1.0 <2"}, "legacy-dep >= 1.0", {"id": "pub.example/nover"}],
        "resources": {"disk_mb": 0, "ram_mb": 512},
        "commands": ["docker", "systemctl"],
    }
    _validate(example)
    del example["requires"]
    _validate(example)


# --- permissions --------------------------------------------------------------

@pytest.mark.parametrize("permissions,fragment", [
    ({"network_ingress": ["6379"]}, "network_ingress"),
    ({"network_ingress": ["6379/sctp"]}, "network_ingress"),
    ({"filesystem": ["state"]}, "filesystem"),
    ({"filesystem": ["a:b:c:rw"]}, "filesystem"),
    ({"secrets": "TOKEN"}, "permissions.secrets"),
    ({"root": "yes"}, "permissions.root"),
    ({"reason": 7}, "permissions.reason"),
    ({"reason": {"root": 7}}, "permissions.reason.root"),
])
def test_permissions_rejections(example, permissions, fragment):
    example["permissions"] = permissions
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


def test_permissions_accepts_full_v03_surface(example):
    example["permissions"] = {
        "network_egress": ["api.test:443", "*.cdn.test", "10.0.0.5"],
        "network_ingress": ["6379/tcp", "127.0.0.1:8080/tcp", "[::1]:5353/udp"],
        "filesystem": ["state:rw", "config:r", "hermes:skills:rw"],
        "secrets": ["TOKEN"],
        "root": True,
        "reason": {"root": "installs a unit", "network_egress": "pulls an image"},
    }
    _validate(example)
    del example["permissions"]
    _validate(example)  # absent == empty declaration


# --- release / updates --------------------------------------------------------

@pytest.mark.parametrize("mutate,fragment", [
    (lambda r: r.pop("channel"), "release.channel"),
    (lambda r: r.__setitem__("published_at", "yesterday"), "release.published_at"),
    (lambda r: r.__setitem__("valid_until", "2026-13-01T00:00:00Z"), "release.valid_until"),
    (lambda r: r.pop("artifact"), "release.artifact"),
    (lambda r: r["artifact"].__setitem__("sha256", "abc"), "release.artifact.sha256"),
    (lambda r: r["artifact"].__setitem__("url", "ftp://x/a.tgz"), "release.artifact.url"),
])
def test_release_rejections(example, mutate, fragment):
    mutate(example["release"])
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


def test_release_is_optional_and_dates_accept_offsets(example):
    example["release"]["published_at"] = "2026-08-24T10:00:00+02:00"
    example["release"]["valid_until"] = "2027-01-01T00:00:00Z"
    assert _validate(example)["channel"] == "stable"
    del example["release"]
    assert _validate(example)["channel"] == "stable"


@pytest.mark.parametrize("updates,fragment", [
    ({}, "updates.source"),
    ({"source": {}}, "updates.source.kind"),
    ({"source": {"kind": "github"}}, "updates.source.repo"),
    ({"source": {"kind": "github", "repo": "nope"}}, "updates.source.repo"),
    ({"source": {"kind": "forge", "url": "https://git.example"}}, "updates.source.repo"),
    ({"source": {"kind": "feed"}}, "updates.source.url"),
    ({"source": {"kind": "direct", "url": "http://x/m.json"}}, "updates.source.url"),
    ({"source": {"kind": "direct", "url": "https://x/m.json"}, "check": "often"}, "updates.check"),
    ({"source": {"kind": "direct", "url": "https://x/m.json"}, "policy": "ask"}, "updates.policy"),
])
def test_updates_rejections(example, updates, fragment):
    example["updates"] = updates
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


@pytest.mark.parametrize("source", [
    {"kind": "github", "repo": "acme/x"},
    {"kind": "forge", "url": "https://git.example/api", "repo": "acme/x"},
    {"kind": "feed", "url": "https://x/feed.json"},
    {"kind": "direct", "url": "https://x/agent-extension.json"},
])
def test_updates_accepts_every_source_kind(example, source):
    example["updates"] = {"source": source, "check": "weekly", "policy": "pin"}
    _validate(example)


# --- signing ------------------------------------------------------------------

def test_signing_rejections(example):
    example["signing"]["next_key"] = "ed25519:short"
    with pytest.raises(manifest.ManifestError, match="signing.next_key"):
        _validate(example)
    example["signing"]["next_key"] = None
    example["signature"] = ""
    with pytest.raises(manifest.ManifestError, match="signature"):
        _validate(example)
    example["signature"] = "c2ln"
    example["signature_prev"] = 7
    with pytest.raises(manifest.ManifestError, match="signature_prev"):
        _validate(example)
    del example["signing"]
    del example["signature"]
    example["signature_prev"] = "b2xk"
    with pytest.raises(manifest.ManifestError, match="without a signing block"):
        _validate(example)


# --- targets ------------------------------------------------------------------

@pytest.mark.parametrize("mutate,fragment", [
    (lambda t: t.__setitem__("runtime", "Hermes!"), "runtime"),
    (lambda t: t.__setitem__("platforms", ["linux"]), "platforms"),
    (lambda t: t.__setitem__("delivery", {"method": "archive", "sha256": "0" * 64}), "delivery.url"),
    (lambda t: t.__setitem__("delivery", {"method": "archive", "url": "https://x/a.tgz", "sha256": "zz"}), "delivery.sha256"),
    (lambda t: t.__setitem__("delivery", {"method": "archive", "url": "https://x/a.tgz", "sha256": "0" * 64, "format": "rar"}), "delivery.format"),
    (lambda t: t.__setitem__("delivery", {"url": "https://x/a.tgz"}), "delivery.method"),
    (lambda t: t.__setitem__("lifecycle", {"install": "i.sh", "uninstall": "u.sh", "reboot": "r.sh"}), "unknown hooks"),
    (lambda t: t["lifecycle"].__setitem__("install", "/abs/install.sh"), "relative path"),
    (lambda t: t.__setitem__("component_map", {"tools": ["x"]}), "component_map.tools"),
])
def test_target_rejections(example, mutate, fragment):
    mutate(example["targets"][0])
    with pytest.raises(manifest.ManifestError, match=fragment):
        _validate(example)


def test_targets_list_shape(example):
    example["targets"] = "posix"
    with pytest.raises(manifest.ManifestError, match="targets"):
        _validate(example)
    example["targets"] = ["posix"]
    with pytest.raises(manifest.ManifestError, match="targets\\[0\\]: must be an object"):
        _validate(example)


def test_targets_accept_zip_archives_reverse_dns_runtimes_and_foreign_methods(example):
    example["targets"] = [
        {"runtime": "com.example.myagent", "platforms": ["darwin/arm64"], "enforcement": "enforced",
         "delivery": {"method": "archive", "url": "https://x/a.zip", "sha256": "0" * 64, "format": "zip"},
         "lifecycle": {"install": "install.sh", "uninstall": "scripts/uninstall.sh", "upgrade": "upgrade.sh", "health": "health.sh"},
         "component_map": {"skills": "skills/", "services": {"unit": "systemd:x.service"}}},
        {"runtime": "openclaw", "delivery": {"method": "clawhub", "package": "x"},
         "lifecycle": {"install": "i.sh", "uninstall": "u.sh"}},
    ]
    assert _validate(example)["runtimes"] == ["com.example.myagent", "openclaw"]
    with pytest.raises(manifest.ManifestError, match="no targets"):
        manifest.select_target(example, runtimes=("hermes", "posix"), platform="linux/amd64")
