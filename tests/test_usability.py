"""Local publisher workflows: no network, builds, or implicit publishing."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from axp import cli, manifest


def scaffold(root, template="skill", extra=()):
    return cli.main(["init", "--publisher", "extensions.acme.org", "--name", "hello",
                     "--description", "A small local example", "--template", template,
                     "--dir", str(root), *extra])


@pytest.mark.parametrize("template,component", [
    ("skill", "skills"), ("cli", "tools"), ("mcp", "mcp_servers"), ("service", "services"),
])
def test_templates_install_health_uninstall(tmp_path, template, component):
    project = tmp_path / "project"
    assert scaffold(project, template) == 0
    data = json.loads((project / "agent-extension.json").read_text())
    assert component in manifest.validate(data)["provides"]
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1] / "schema/agent-extension.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(data)
    assert (project / "axp.toml").is_file()
    prefix = tmp_path / "installed"
    env = dict(os.environ, AXP_PREFIX=str(prefix))
    for script in ("install.sh", "install.sh", "healthcheck.sh", "uninstall.sh", "uninstall.sh"):
        result = subprocess.run(["sh", str(project / script)], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert subprocess.run(["sh", str(project / "healthcheck.sh")], env=env,
                          capture_output=True).returncode != 0
    if template != "skill":
        result = subprocess.run([sys.executable, str(project / "payload" / "main.py"), "--help"],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("collision", ["existing", "symlink", "parent-symlink"])
def test_template_preflight_leaves_existing_files_untouched(tmp_path, collision):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "SKILL.md"
    protected.write_text("keep")
    if collision == "existing":
        (project / "install.sh").write_text("keep")
        extra = ()
    elif collision == "symlink":
        (project / "install.sh").symlink_to(protected)
        extra = ("--force",)
    else:
        (project / "payload").symlink_to(outside, target_is_directory=True)
        extra = ("--force",)
    assert scaffold(project, extra=extra) == 1
    assert not (project / "agent-extension.json").exists()
    assert protected.read_text() == "keep"


def test_check_distinguishes_valid_draft_and_has_actionable_diagnostics(tmp_path, capsys):
    assert scaffold(tmp_path) == 0
    capsys.readouterr()
    assert cli.main(["validate", str(tmp_path / "agent-extension.json")]) == 0
    capsys.readouterr()
    assert cli.main(["check", str(tmp_path / "agent-extension.json"), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["structurally_valid"] is True
    assert report["status"] == "draft"
    codes = {d["code"] for d in report["diagnostics"]}
    assert {"AXP_PLACEHOLDER", "AXP_UNSIGNED", "AXP_ARTIFACT_MISSING"} <= codes
    assert all(set(d) == {"code", "field", "message", "remedy"} and all(d.values())
               for d in report["diagnostics"])


def test_check_signed_archive_content_and_runtime_without_execution(tmp_path, capsys, monkeypatch):
    import tarfile
    from axp import publish, signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    archive = tmp_path / "package.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("install.sh", "uninstall.sh", "healthcheck.sh", "lifecycle.py", "payload"):
            tar.add(tmp_path / name, arcname=name)
    data = publish.prepare_release(json.loads(path.read_text()), artifacts={None: archive})
    key = signing.generate_private_key_pem()
    data["signing"] = {"public_key": signing.public_key_from_private(key)}
    data = signing.sign_manifest(data, key)
    path.write_text(json.dumps(data))
    capsys.readouterr()
    def forbidden(*args, **kwargs):
        raise AssertionError("check must not execute or fetch")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr("axp.repository.http_fetch", forbidden)
    args = ["check", str(path), "--artifact", str(archive), "--format", "json"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "publish_ready"
    assert cli.main(args + ["--runtime", "hermes"]) == 1
    assert "AXP_RUNTIME_UNSUPPORTED" in capsys.readouterr().out
    # Source and delivered files are checked separately.
    (tmp_path / "install.sh").unlink()
    assert cli.main(args) == 1
    assert "AXP_FILE_MISSING" in capsys.readouterr().out
    archive.write_bytes(b"not an archive")
    assert cli.main(args) == 1
    codes = {d["code"] for d in json.loads(capsys.readouterr().out)["diagnostics"]}
    assert {"AXP_DIGEST_MISMATCH", "AXP_ARCHIVE_INVALID"} <= codes


@pytest.mark.parametrize("bad_name,kind", [("../escape", "file"), ("/absolute", "file"),
    ("payload/link", "symlink"), ("payload/hard", "hardlink"), ("payload/secret.pem", "file"),
    (".env", "file"), ("payload/innocent.txt", "secret"), ("install.sh", "duplicate")])
def test_check_rejects_unsafe_archives(tmp_path, capsys, bad_name, kind):
    import io
    import tarfile
    assert scaffold(tmp_path) == 0
    artifact = tmp_path / "bad.tar.gz"
    with tarfile.open(artifact, "w:gz") as tar:
        item = tarfile.TarInfo(bad_name)
        if kind in ("symlink", "hardlink"):
            item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            item.linkname = "../../outside"
            tar.addfile(item)
        else:
            content = b"-----BEGIN PRIVATE KEY-----" if kind == "secret" else b"test"
            item.size = len(content)
            tar.addfile(item, io.BytesIO(content))
            if kind == "duplicate":
                tar.addfile(item, io.BytesIO(content))
    capsys.readouterr()
    assert cli.main(["check", str(tmp_path / "agent-extension.json"), "--artifact", str(artifact),
                     "--format", "json"]) == 1
    codes = {d["code"] for d in json.loads(capsys.readouterr().out)["diagnostics"]}
    assert "AXP_ARCHIVE_UNSAFE" in codes


def test_check_release_digest_and_unknown_delivery_are_not_ready(tmp_path, capsys):
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    data = json.loads(path.read_text())
    data["targets"][0]["delivery"] = {"method": "x-private"}
    path.write_text(json.dumps(data))
    capsys.readouterr()
    assert cli.main(["check", str(path), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    codes = {d["code"] for d in report["diagnostics"]}
    assert {"AXP_DELIVERY_UNCHECKED", "AXP_PLACEHOLDER"} <= codes


@pytest.mark.parametrize("command", ["validate", "check"])
def test_diagnostics_formats_and_input_errors(tmp_path, capsys, command):
    path = tmp_path / "manifest.json"
    path.write_text('{"identity": {}}')
    assert cli.main([command, str(path), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "invalid"
    assert report["diagnostics"][0]["code"] == "AXP_MANIFEST_INVALID"
    assert cli.main([command, str(path), "--format", "compact"]) == 1
    output = capsys.readouterr().out
    assert "AXP_MANIFEST_INVALID" in output and "Remedy:" in output
    path.write_text('{broken')
    assert cli.main([command, str(path), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["diagnostics"][0]["code"] == "AXP_INPUT_INVALID"


@pytest.mark.parametrize("template", ["skill", "cli", "mcp", "service"])
def test_cli_smoke_local_pack_release_check(tmp_path, template):
    project = tmp_path / template
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    def run(*args, expected=0, cwd=tmp_path):
        result = subprocess.run([sys.executable, "-m", "axp", *args], cwd=cwd, env=env,
                                text=True, capture_output=True)
        assert result.returncode == expected, result.stdout + result.stderr
        return result.stdout
    run("init", "--template", template, "--publisher", "extensions.acme.org", "--name", "hello",
        "--description", "Local example", "--dir", str(project))
    run("check", expected=1, cwd=project)
    run("pack", cwd=project)
    artifact = project / "dist/package.tar.gz"
    assert artifact.is_file()
    original = artifact.read_bytes()
    run("pack", cwd=project, expected=1)
    assert artifact.read_bytes() == original
    key = tmp_path / "private.key"
    run("keygen", "--out", str(key))
    with (project / "axp.toml").open("a") as handle:
        handle.write('signing_key = "../private.key"\n')
    # Resolve config paths relative to the manifest, not the current directory.
    run("release", str(project / "agent-extension.json"), "--bump", "patch")
    report = json.loads(run("check", str(project / "agent-extension.json"), "--format", "json"))
    assert report["status"] == "publish_ready"
    assert report["summary"]["version"] == "0.1.1"
    run("verify", str(project / "agent-extension.json"), "--artifact", str(artifact))
    # Exercise exactly the delivered files, not just the source scaffold.
    import tarfile
    delivered = tmp_path / "delivered"
    with tarfile.open(artifact) as tar:
        tar.extractall(delivered, filter="data")
    lifecycle_env = dict(env, AXP_PREFIX=str(tmp_path / "installed"))
    for script in ("install.sh", "healthcheck.sh", "uninstall.sh"):
        result = subprocess.run(["sh", str(delivered / script)], env=lifecycle_env, capture_output=True)
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("hazard", ["symlink", "parent-symlink", "secret-key-path", "output-input",
                                    "output-symlink", "fifo", "env", "pem-content"])
def test_pack_rejects_unsafe_inputs_before_writing(tmp_path, capsys, hazard):
    project = tmp_path / "project"
    assert scaffold(project) == 0
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "data"
    victim.write_text("keep")
    config = project / "axp.toml"
    output = project / "dist/package.tar.gz"
    extra = []
    if hazard == "symlink":
        (project / "payload/link").symlink_to(victim)
    elif hazard == "parent-symlink":
        (project / "linked").symlink_to(outside, target_is_directory=True)
        extra = ["--file", "linked/data"]
    elif hazard == "secret-key-path":
        with config.open("a") as handle:
            handle.write('signing_key = "payload/SKILL.md"\n')
    elif hazard == "output-input":
        extra = ["--output", str(project / "install.sh"), "--force"]
    elif hazard == "output-symlink":
        output.parent.mkdir()
        output.symlink_to(victim)
        extra = ["--force"]
    elif hazard == "fifo":
        os.mkfifo(project / "payload/pipe")
    elif hazard == "env":
        (project / "payload/.env").write_text("TOKEN=secret")
    elif hazard == "pem-content":
        (project / "payload/data").write_text("-----BEGIN PRIVATE KEY-----")
    capsys.readouterr()
    import signal
    def timed_out(*_):
        raise AssertionError("pack blocked reading a special file")
    previous = signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(2)
    try:
        assert cli.main(["pack", str(project / "agent-extension.json"), *extra]) == 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert victim.read_text() == "keep"
    if hazard != "output-symlink":
        assert not output.exists()
    assert (project / "install.sh").read_text().startswith("#!/bin/sh")


@pytest.mark.parametrize("mutation,code", [
    ("missing-code", "AXP_FILE_MISSING"), ("source-symlink", "AXP_FILE_UNSAFE"),
    ("placeholder-url", "AXP_PLACEHOLDER"), ("unknown-runtime", "AXP_RUNTIME_UNCHECKED"),
])
def test_static_checks_cover_executable_components_and_local_safety(tmp_path, capsys, mutation, code):
    assert scaffold(tmp_path, "cli") == 0
    path = tmp_path / "agent-extension.json"
    data = json.loads(path.read_text())
    if mutation == "missing-code":
        (tmp_path / "payload/main.py").unlink()
    elif mutation == "source-symlink":
        (tmp_path / "install.sh").unlink()
        (tmp_path / "install.sh").symlink_to(tmp_path / "uninstall.sh")
    elif mutation == "placeholder-url":
        data["identity"]["publisher"] = "ext.example.com"
    else:
        data["targets"][0]["runtime"] = "future-runtime"
    path.write_text(json.dumps(data))
    capsys.readouterr()
    assert cli.main(["check", str(path), "--format", "json"]) == 1
    diagnostics = json.loads(capsys.readouterr().out)["diagnostics"]
    assert code in {d["code"] for d in diagnostics}
    if mutation == "placeholder-url":
        assert any(d["field"] == "identity.publisher" for d in diagnostics)


def test_release_cli_overrides_config_and_refuses_output_clobber(tmp_path, capsys):
    from axp import signing
    assert scaffold(tmp_path) == 0
    manifest_path = tmp_path / "agent-extension.json"
    artifact = tmp_path / "override.tar.gz"
    assert cli.main(["pack", str(manifest_path), "-o", str(artifact)]) == 0
    key = tmp_path / "override.key"
    key.write_bytes(signing.generate_private_key_pem())
    with (tmp_path / "axp.toml").open("a") as handle:
        handle.write('signing_key = "missing.key"\n')
    output = tmp_path / "release.json"
    output.write_text("keep")
    args = ["release", str(manifest_path), "--artifact", str(artifact), "--key", str(key), "-o", str(output)]
    before = manifest_path.read_bytes()
    assert cli.main(args) == 1
    assert output.read_text() == "keep"
    assert manifest_path.read_bytes() == before
    assert cli.main(args + ["--force"]) == 0
    assert signing.verify_manifest(json.loads(output.read_text()))


@pytest.mark.parametrize("config", ['[project]\nbuild = "touch owned"\n',
    '[build]\ncommand = "touch owned"\n', '[project]\nfiles = "*"\n',
    '[project]\nsigning_key = ""\n', '[project]\nsigning_key = "-----BEGIN PRIVATE KEY-----"\n'])
def test_config_rejects_commands_and_invalid_paths(tmp_path, config):
    from axp import project, publish
    (tmp_path / "axp.toml").write_text(config)
    with pytest.raises(publish.PublishError):
        project.load(str(tmp_path / "agent-extension.json"))
    assert cli.main(["pack", str(tmp_path / "agent-extension.json")]) == 1
    assert not (tmp_path / "owned").exists()


def test_check_stale_source_and_tampered_signature(tmp_path, capsys):
    from axp import signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    assert cli.main(["pack", str(path)]) == 0
    key = tmp_path / "signing.key"
    key.write_bytes(signing.generate_private_key_pem())
    assert cli.main(["release", str(path), "--key", str(key)]) == 0
    (tmp_path / "install.sh").write_text("#!/bin/sh\nexit 1\n")
    data = json.loads(path.read_text())
    data["identity"]["description"] = "Tampered"
    path.write_text(json.dumps(data))
    capsys.readouterr()
    assert cli.main(["check", str(path), "--format", "json"]) == 1
    codes = {d["code"] for d in json.loads(capsys.readouterr().out)["diagnostics"]}
    assert {"AXP_SIGNATURE_INVALID", "AXP_CONTENT_MISMATCH"} <= codes


@pytest.mark.parametrize("target", ["symlink", "artifact", "key"])
def test_release_never_overwrites_artifact_key_or_symlink(tmp_path, target):
    from axp import signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    assert cli.main(["pack", str(path)]) == 0
    artifact = tmp_path / "dist/package.tar.gz"
    key = tmp_path / "signing.key"
    key.write_bytes(signing.generate_private_key_pem())
    link = tmp_path / "link.json"
    link.symlink_to(path)
    output = {"symlink": link, "artifact": artifact, "key": key}[target]
    before = output.read_bytes()
    assert cli.main(["release", str(path), "--key", str(key), "-o", str(output), "--force"]) == 1
    assert output.read_bytes() == before


def test_pack_is_bounded_and_deterministic(tmp_path, monkeypatch):
    from axp import package
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    assert cli.main(["pack", str(path)]) == 0
    artifact = tmp_path / "dist/package.tar.gz"
    first = artifact.read_bytes()
    assert cli.main(["pack", str(path), "--force"]) == 0
    assert artifact.read_bytes() == first
    monkeypatch.setattr(package, "MAX_BYTES", 10)
    assert cli.main(["pack", str(path), "--force"]) == 1
    assert artifact.read_bytes() == first


def test_sign_uses_project_key_default_but_explicit_key_wins(tmp_path):
    from axp import signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    key = tmp_path / "signing.key"
    key.write_bytes(signing.generate_private_key_pem())
    with (tmp_path / "axp.toml").open("a") as handle:
        handle.write('signing_key = "signing.key"\n')
    assert cli.main(["sign", str(path), "--in-place"]) == 0
    assert signing.verify_manifest(json.loads(path.read_text()))
    key.rename(tmp_path / "renamed.key")
    assert cli.main(["sign", str(path), "--key", str(tmp_path / "renamed.key"), "--in-place"]) == 0


def test_check_unknown_fields_do_not_crash_placeholder_scan(tmp_path, capsys):
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    data = json.loads(path.read_text())
    data["x-not-a-url"] = "https://"
    path.write_text(json.dumps(data))
    capsys.readouterr()
    assert cli.main(["check", str(path), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["structurally_valid"] is True


def test_mcp_template_responds_to_initialize_and_tool_calls(tmp_path):
    assert scaffold(tmp_path, "mcp") == 0
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "hello"}}]
    result = subprocess.run([sys.executable, str(tmp_path / "payload/main.py")],
                            input="\n".join(map(json.dumps, requests)) + "\n", text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    assert responses[0]["result"]["capabilities"] == {"tools": {}}
    assert responses[1]["result"]["tools"][0]["name"] == "hello"
    assert responses[2]["result"]["content"][0]["text"] == "Hello, world!"


def test_service_template_serves_loopback_health(tmp_path):
    from urllib.request import urlopen
    import selectors
    assert scaffold(tmp_path, "service") == 0
    process = subprocess.Popen([sys.executable, str(tmp_path / "payload/main.py"), "--port", "0"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(5), "Service did not start"
        line = process.stdout.readline().strip()
        assert line.startswith("Listening on 127.0.0.1:")
        with urlopen("http://" + line.removeprefix("Listening on ") + "/health", timeout=3) as response:
            assert json.loads(response.read()) == {"status": "ok"}
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_pack_cannot_overwrite_configured_key(tmp_path):
    assert scaffold(tmp_path) == 0
    key = tmp_path / "private-data"
    key.write_text("keep")
    with (tmp_path / "axp.toml").open("a") as handle:
        handle.write('signing_key = "private-data"\n')
    assert cli.main(["pack", str(tmp_path / "agent-extension.json"), "-o", str(key), "--force"]) == 1
    assert key.read_text() == "keep"


def test_check_expired_release_is_draft(tmp_path, capsys):
    from axp import signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    assert cli.main(["pack", str(path)]) == 0
    key = tmp_path / "key.pem"
    key.write_bytes(signing.generate_private_key_pem())
    assert cli.main(["release", str(path), "--key", str(key)]) == 0
    data = json.loads(path.read_text())
    data["release"]["published_at"] = "2000-01-01T00:00:00Z"
    data["release"]["valid_until"] = "2000-02-01T00:00:00Z"
    path.write_text(json.dumps(signing.sign_manifest(data, key.read_bytes())))
    capsys.readouterr()
    assert cli.main(["check", str(path), "--format", "json"]) == 1
    assert "AXP_RELEASE_EXPIRED" in capsys.readouterr().out


@pytest.mark.parametrize("destination", ["existing", "key", "symlink"])
def test_sign_does_not_clobber_destinations(tmp_path, destination):
    from axp import signing
    assert scaffold(tmp_path) == 0
    path = tmp_path / "agent-extension.json"
    key = tmp_path / "key.pem"
    key.write_bytes(signing.generate_private_key_pem())
    output = tmp_path / "signed.json"
    if destination == "key":
        output = key
    elif destination == "symlink":
        output.symlink_to(path)
    else:
        output.write_text("keep")
    before = output.read_bytes()
    assert cli.main(["sign", str(path), "--key", str(key), "-o", str(output)]) == 1
    assert output.read_bytes() == before
