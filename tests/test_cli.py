"""axp.cli — end-to-end publisher/host flow through the command line."""

import json

from axp import cli


def test_keygen_validate_sign_verify_target(tmp_path, example, capsys):
    manifest_path = tmp_path / "agent-extension.json"
    key_path = tmp_path / "signing.key"

    assert cli.main(["keygen", "--out", str(key_path)]) == 0
    public_key = capsys.readouterr().out.strip()
    assert public_key.startswith("ed25519:")

    example["signing"] = {"public_key": public_key, "key_id": "cli-test", "next_key": None}
    example.pop("signature", None)
    manifest_path.write_text(json.dumps(example))

    assert cli.main(["validate", str(manifest_path)]) == 1  # signing block without signature
    capsys.readouterr()

    assert cli.main(["sign", str(manifest_path), "--key", str(key_path), "--in-place"]) == 0
    capsys.readouterr()
    assert cli.main(["validate", str(manifest_path)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["signed"] is True

    assert cli.main(["verify", str(manifest_path)]) == 0
    capsys.readouterr()
    assert cli.main(["verify", str(manifest_path), "--pinned", public_key]) == 0
    capsys.readouterr()

    # Tamper -> verify fails.
    data = json.loads(manifest_path.read_text())
    data["identity"]["version"] = "9.9.9"
    manifest_path.write_text(json.dumps(data))
    assert cli.main(["verify", str(manifest_path)]) == 1
    capsys.readouterr()


def test_target_selection_cli(tmp_path, example, capsys):
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(example))
    assert cli.main(["target", str(manifest_path), "--runtime", "hermes",
                     "--runtime", "posix", "--platform", "linux/amd64"]) == 0
    picked = json.loads(capsys.readouterr().out)
    assert picked["runtime"] == "hermes"
    assert cli.main(["target", str(manifest_path), "--runtime", "openclaw",
                     "--platform", "linux/amd64"]) == 1
