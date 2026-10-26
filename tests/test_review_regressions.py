"""Regression coverage for independent publisher usability review."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

from axp import cli, manifest, package, publish, readiness, signing
from tests.test_usability import scaffold


@pytest.mark.parametrize("hook", ["upgrade", "health", "enable", "disable"])
@pytest.mark.parametrize("null", [False, True], ids=["absent", "null"])
def test_check_json_skips_optional_lifecycle_hooks(tmp_path, hook, null):
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    data = json.loads(path.read_text())
    data["targets"][0]["lifecycle"].pop(hook, None)
    expected = readiness.check(data, root=tmp_path)
    if null:
        data["targets"][0]["lifecycle"][hook] = None
    manifest.validate(data)
    path.write_text(json.dumps(data))
    result = subprocess.run([sys.executable, "-m", "axp", "check", str(path),
                             "--format", "json"], text=True, capture_output=True)
    assert "Traceback" not in result.stderr
    assert result.returncode == 1
    assert json.loads(result.stdout) == expected


def test_check_json_reports_missing_release_timezone(tmp_path):
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    data = json.loads(path.read_text())
    data["release"]["valid_until"] = "2027-01-01T00:00:00"
    manifest.validate(data)
    path.write_text(json.dumps(data))
    result = subprocess.run([sys.executable, "-m", "axp", "check", str(path),
                             "--format", "json"], text=True, capture_output=True)
    assert "Traceback" not in result.stderr
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["structurally_valid"] is True
    assert report["status"] == "draft"
    diagnostic = next(d for d in report["diagnostics"]
                      if d["code"] == "AXP_RELEASE_TIMEZONE_MISSING")
    assert diagnostic["field"] == "release.valid_until"
    assert "timezone" in diagnostic["message"].lower()
    assert "Z" in diagnostic["remedy"] and "+00:00" in diagnostic["remedy"]


def archive(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, content in entries:
            item = tarfile.TarInfo(name)
            item.size = len(content)
            tar.addfile(item, io.BytesIO(content))


@pytest.mark.parametrize("name,content", [(".env", b"TOKEN=secret"),
    ("innocent.txt", b"-----BEGIN PRIVATE KEY-----"), ("../escape", b"unsafe")])
def test_canonical_artifact_inspected_with_runtime_override(tmp_path, name, content):
    assert scaffold(tmp_path) == 0
    good = tmp_path / "good.tar.gz"
    assert cli.main(["pack", str(tmp_path / "agent-extension.json"), "-o", str(good)]) == 0
    bad = tmp_path / "canonical.tar.gz"
    archive(bad, [(name, content)])
    data = json.loads((tmp_path / "agent-extension.json").read_text())
    artifacts = {None: bad, "posix": good}
    data = publish.prepare_release(data, artifacts=artifacts)
    key = signing.generate_private_key_pem()
    data["signing"] = {"public_key": signing.public_key_from_private(key)}
    data = signing.sign_manifest(data, key)
    report = readiness.check(data, root=tmp_path, artifacts=artifacts)
    assert "AXP_ARCHIVE_UNSAFE" in {d["code"] for d in report["diagnostics"]}
    assert report["status"] == "draft"


@pytest.mark.parametrize("action", ["install", "uninstall"])
@pytest.mark.parametrize("hazard", ["directory-link", "file-link", "hardlink", "prefix-link", "ancestor-link"])
def test_lifecycle_rejects_unsafe_destinations(tmp_path, action, hazard):
    project = tmp_path / "project"
    assert scaffold(project) == 0
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "SKILL.md"
    victim.write_text("keep")
    prefix = tmp_path / "installed"
    prefix.mkdir()
    if hazard == "directory-link":
        (prefix / "payload").symlink_to(outside, target_is_directory=True)
    elif hazard in ("prefix-link", "ancestor-link"):
        prefix.rmdir()
        prefix.symlink_to(outside, target_is_directory=True)
        if hazard == "ancestor-link":
            prefix = prefix / "nested"
        (prefix / "payload").mkdir(parents=True)
        (prefix / "payload/SKILL.md").write_text("keep")
    else:
        (prefix / "payload").mkdir()
        dest = prefix / "payload/SKILL.md"
        if hazard == "file-link":
            dest.symlink_to(victim)
        else:
            os.link(victim, dest)
    # Preflight must reject before touching even an earlier, ordinary file.
    (project / "payload/first.txt").write_text("new")
    before = {str(p): p.read_bytes() for p in outside.rglob("*") if p.is_file()}
    result = subprocess.run([sys.executable, str(project / "lifecycle.py"), action],
                            env=dict(os.environ, AXP_PREFIX=str(prefix)), text=True, capture_output=True)
    assert result.returncode != 0
    assert "unsafe" in result.stderr.lower()
    assert before == {str(p): p.read_bytes() for p in outside.rglob("*") if p.is_file()}
    assert not (prefix / "payload/first.txt").exists()


@pytest.mark.parametrize("command", ["pack", "scaffold"])
@pytest.mark.parametrize("hazard", ["hardlink", "directory"])
def test_force_preserves_unsafe_output(tmp_path, command, hazard):
    project = tmp_path / "project"
    assert scaffold(project) == 0
    victim = tmp_path / "victim"
    victim.write_text("keep")
    output = project / ("archive.tar.gz" if command == "pack" else "install.sh")
    output.unlink(missing_ok=True)
    if hazard == "hardlink":
        os.link(victim, output)
    else:
        output.mkdir()
        (output / "unrelated").write_text("keep")
    if command == "pack":
        result = cli.main(["pack", str(project / "agent-extension.json"), "-o", str(output), "--force"])
    else:
        result = scaffold(project, extra=("--force",))
    assert result == 1
    assert victim.read_text() == "keep"
    if hazard == "directory":
        assert (output / "unrelated").read_text() == "keep"


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_archive_rejects_file_ancestor(tmp_path, reverse, kind):
    import zipfile
    entries = [("a", b"file"), ("a/b", b"child")]
    if reverse:
        entries.reverse()
    path = tmp_path / "artifact"
    if kind == "tar":
        archive(path, entries)
    else:
        with zipfile.ZipFile(path, "w") as output:
            for name, content in entries:
                output.writestr(name, content)
    with pytest.raises(package.UnsafePackage, match="ancestor|directory"):
        package.archive_files(path)


@pytest.mark.parametrize("kind", ["gzip-truncated", "zip-compression", "zip-corrupt"])
def test_check_reports_archive_decode_errors(tmp_path, capsys, kind):
    import struct
    import zipfile
    assert scaffold(tmp_path) == 0
    path = tmp_path / "broken.archive"
    if kind == "gzip-truncated":
        path.write_bytes(b"\x1f\x8b\x08\x00")
    else:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("data", b"payload")
        raw = bytearray(path.read_bytes())
        if kind == "zip-compression":
            struct.pack_into("<H", raw, 8, 99)
            struct.pack_into("<H", raw, raw.index(b"PK\x01\x02") + 10, 99)
        else:
            raw[34:37] = b"\xff\xff\xff"
        path.write_bytes(raw)
    capsys.readouterr()
    assert cli.main(["check", str(tmp_path / "agent-extension.json"), "--artifact", str(path),
                     "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert "AXP_ARCHIVE_INVALID" in {d["code"] for d in report["diagnostics"]}


@pytest.mark.parametrize("rpc_request,code", [
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": None}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []}, -32602),
    ([], -32600), (None, -32600), ("id", -32600),
    ({"jsonrpc": "2.0", "id": 1, "method": []}, -32600),
])
def test_mcp_bad_shapes_return_error_and_continue(tmp_path, rpc_request, code):
    assert scaffold(tmp_path, "mcp") == 0
    rpc_requests = [rpc_request, {"jsonrpc": "2.0", "id": 2, "method": "ping"}]
    result = subprocess.run([sys.executable, str(tmp_path / "payload/main.py")],
                            input="\n".join(map(json.dumps, rpc_requests)) + "\n", text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == 2
    assert responses[0]["error"]["code"] == code
    assert responses[0]["id"] == (rpc_request.get("id") if isinstance(rpc_request, dict) else None)
    assert responses[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


@pytest.mark.parametrize("command", ["scaffold", "init", "sign", "release"])
def test_write_failures_are_actionable_diagnostics(tmp_path, monkeypatch, capsys, command):
    project = tmp_path / "project"
    assert scaffold(project) == 0
    path = project / "agent-extension.json"
    key = tmp_path / "key.pem"
    key.write_bytes(signing.generate_private_key_pem())
    assert cli.main(["pack", str(path)]) == 0
    def denied(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(self))
    monkeypatch.setattr(Path, "write_text", denied)
    capsys.readouterr()
    if command == "scaffold":
        result = scaffold(tmp_path / "new")
    elif command == "init":
        result = cli.main(["init", "--publisher", "extensions.acme.org", "--name", "hello",
                           "--description", "Example", "--dir", str(tmp_path / "new")])
    else:
        result = cli.main([command, str(path), "--key", str(key), "-o", str(tmp_path / "output.json")])
    assert result == 1
    output = capsys.readouterr()
    assert "Permission denied" in output.err
    assert "axp:" in output.err and "Remedy:" in output.err
    assert "Traceback" not in output.err
