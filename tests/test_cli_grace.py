"""CLI grace policy: explicit override, manifest, protocol default."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from axp import cli, entitlements, signing


@pytest.fixture
def grace_command(tmp_path, example):
    issuing = signing.generate_private_key_pem()
    host = signing.generate_private_key_pem()
    pub = signing.public_key_from_private(issuing)
    expiry = datetime(2026, 10, 10, tzinfo=timezone.utc)
    doc = entitlements.issue(extension="ext.example.com/sample-memory",
                             holder=entitlements.holder_from_private(host), plan="pro",
                             issuer="ext.example.com", private_key_pem=issuing,
                             issued_at=expiry - timedelta(days=30), valid_until=expiry)
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(doc))

    def command(mode, grace, days_after, override=None, with_manifest=True):
        now = expiry + timedelta(days=days_after)
        if mode == "verify":
            args = ["entitlement", mode, str(path)]
        else:
            audience = "https://ext.example.com/artifact"
            presentation = entitlements.make_presentation(host_private_key_pem=host,
                audience=audience, entitlement=doc, now=now)
            args = ["entitlement", mode, entitlements.authorization_header(presentation),
                    "--audience", audience]
        args += ["--issuer-key", pub, "--at", entitlements.format_timestamp(now)]
        if with_manifest:
            example["commerce"] = {"entitlement": "required", "issuers": ["ext.example.com"]}
            if grace is not None:
                example["commerce"]["grace_days"] = grace
            example["signing"] = {"public_key": pub}
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(json.dumps(signing.sign_manifest(example, issuing)))
            args += ["--manifest", str(manifest_path)]
        if override is not None:
            args += ["--grace-days", str(override)]
        return args
    return command


@pytest.mark.parametrize("mode", ["verify", "inspect"])
@pytest.mark.parametrize("grace,days_after,override,with_manifest,status", [
    (0, 1, None, True, "expired"), (14, 10, None, True, "grace"),
    (14, 1, 0, True, "expired"), (0, 10, 14, True, "grace"),
    (None, 6, None, True, "grace"), (None, 8, None, True, "expired"),
    (None, 6, None, False, "grace"), (None, 8, None, False, "expired"),
    (None, 1, 0, False, "expired"), (None, 10, 14, False, "grace"),
])
def test_grace_resolution(grace_command, capsys, mode, grace, days_after, override, with_manifest, status):
    result = cli.main(grace_command(mode, grace, days_after, override, with_manifest))
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == status
    assert result == (0 if status == "grace" else 1)


@pytest.mark.parametrize("value", [None, -1, True, "7"])
def test_manifest_grace_rejects_malformed_policy(example, value):
    from axp.manifest import ManifestError, validate
    example["commerce"] = {"entitlement": "required", "grace_days": value}
    with pytest.raises(ManifestError, match="grace_days"):
        validate(example)


@pytest.mark.parametrize("mode", ["verify", "inspect"])
def test_negative_grace_is_usage_error(grace_command, capsys, mode):
    with pytest.raises(SystemExit) as exc:
        cli.main(grace_command(mode, 14, 1, override=-1))
    assert exc.value.code == 2
    assert "non-negative" in capsys.readouterr().err
