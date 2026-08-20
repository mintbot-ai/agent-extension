"""axp.publish + the init/release CLI — the publisher flow end to end."""

import hashlib
import json
from pathlib import Path

import pytest

from axp import cli, publish, signing


def test_bump_version():
    assert publish.bump_version("1.2.3", "patch") == "1.2.4"
    assert publish.bump_version("1.2.3", "minor") == "1.3.0"
    assert publish.bump_version("1.2.3", "major") == "2.0.0"
    assert publish.bump_version("1.2.3-rc.1", "patch") == "1.2.4"  # tags dropped
    with pytest.raises(publish.PublishError, match="bump must be one of"):
        publish.bump_version("1.2.3", "mega")
    with pytest.raises(publish.PublishError, match="non-semver"):
        publish.bump_version("latest", "patch")


def test_init_writes_a_valid_skeleton(tmp_path, capsys):
    assert cli.main(["init", "--publisher", "pub.example", "--name", "tiny",
                     "--description", "a tiny test extension", "--dir", str(tmp_path)]) == 0
    capsys.readouterr()
    manifest_path = tmp_path / "agent-extension.json"
    data = json.loads(manifest_path.read_text())
    assert data["identity"]["version"] == "0.1.0"
    assert data["targets"][0]["runtime"] == "posix"
    assert data["targets"][0]["delivery"]["sha256"] == publish.PLACEHOLDER_SHA
    # The skeleton itself validates (placeholder digests are valid hex).
    assert cli.main(["validate", str(manifest_path)]) == 0
    capsys.readouterr()
    # Refuses to clobber without --force.
    assert cli.main(["init", "--publisher", "pub.example", "--name", "tiny",
                     "--description", "x", "--dir", str(tmp_path)]) == 1
    capsys.readouterr()


def test_init_rejects_bad_identifiers(tmp_path, capsys):
    assert cli.main(["init", "--publisher", "NotADomain", "--name", "tiny",
                     "--description", "x", "--dir", str(tmp_path)]) == 1
    assert "lowercase DNS name" in capsys.readouterr().err


def test_release_end_to_end(tmp_path, capsys):
    # init → keygen → release --bump --key → verify: the whole publisher loop.
    assert cli.main(["init", "--publisher", "pub.example", "--name", "tiny",
                     "--description", "a tiny test extension", "--runtime", "posix",
                     "--runtime", "hermes", "--dir", str(tmp_path)]) == 0
    key_path = tmp_path / "signing.key"
    assert cli.main(["keygen", "--out", str(key_path)]) == 0
    public_key = capsys.readouterr().out.strip().splitlines()[-1]

    manifest_path = tmp_path / "agent-extension.json"
    data = json.loads(manifest_path.read_text())
    data["signing"] = {"public_key": public_key, "key_id": "tiny-2026", "next_key": None}
    manifest_path.write_text(json.dumps(data))

    artifact = tmp_path / "tiny-0.2.0.tar.gz"
    artifact.write_bytes(b"real artifact bytes")
    assert cli.main(["release", str(manifest_path), "--bump", "minor",
                     "--artifact", str(artifact), "--key", str(key_path)]) == 0
    out = capsys.readouterr()
    assert "released 0.2.0" in out.out and "UNSIGNED" not in out.err

    released = json.loads(manifest_path.read_text())
    digest = hashlib.sha256(b"real artifact bytes").hexdigest()
    assert released["identity"]["version"] == "0.2.0"
    # Version-in-URL followed the bump; every digest is the real file's.
    assert released["release"]["artifact"]["url"].endswith("tiny-0.2.0.tar.gz")
    assert released["release"]["artifact"]["sha256"] == digest
    for target in released["targets"]:
        assert target["delivery"]["sha256"] == digest
        assert "0.1.0" not in target["delivery"]["url"]
    assert released["release"]["published_at"].endswith("Z")
    assert released["release"]["valid_until"] > released["release"]["published_at"]
    # Signed and verifiable out of the box.
    assert signing.verify_manifest(released) is True
    assert cli.main(["verify", str(manifest_path), "--pinned", public_key]) == 0
    capsys.readouterr()


def test_release_unsigned_warns_but_succeeds(tmp_path, capsys):
    assert cli.main(["init", "--publisher", "pub.example", "--name", "tiny",
                     "--description", "x", "--dir", str(tmp_path)]) == 0
    artifact = tmp_path / "a.tar.gz"
    artifact.write_bytes(b"bytes")
    manifest_path = tmp_path / "agent-extension.json"
    assert cli.main(["release", str(manifest_path), "--version", "1.0.0",
                     "--artifact", str(artifact)]) == 0
    assert "UNSIGNED" in capsys.readouterr().err
    assert json.loads(manifest_path.read_text())["identity"]["version"] == "1.0.0"


def test_release_error_paths(tmp_path, example):
    key = None
    artifact = tmp_path / "a.tar.gz"
    artifact.write_bytes(b"bytes")
    with pytest.raises(publish.PublishError, match="not both"):
        publish.prepare_release(example, artifacts={None: artifact}, version="9.9.9", bump="patch")
    with pytest.raises(publish.PublishError, match="at least one"):
        publish.prepare_release(example, artifacts={})
    with pytest.raises(publish.PublishError, match="no archive target"):
        publish.prepare_release(example, artifacts={None: artifact, "openclaw": artifact})
    with pytest.raises(publish.PublishError, match="not found"):
        publish.parse_artifact_args([str(tmp_path / "missing.tar.gz")])
    with pytest.raises(publish.PublishError, match="duplicate"):
        publish.parse_artifact_args([str(artifact), str(artifact)])


def test_release_valid_days_zero_drops_freshness(tmp_path, example):
    artifact = tmp_path / "a.tar.gz"
    artifact.write_bytes(b"bytes")
    released = publish.prepare_release(example, artifacts={None: artifact}, bump="patch", valid_days=0)
    assert "valid_until" not in released["release"]
    assert released["identity"]["version"] == "0.3.1"
