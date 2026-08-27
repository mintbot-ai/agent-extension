"""Publisher tooling: manifest skeletons (``axp init``) and release
preparation (``axp release``).

The goal is that publishing an extension takes minutes, not a reading of the
spec: ``init`` writes a structurally valid v0.3 manifest skeleton (all-zero
digest placeholders — valid hex, so validation passes before the first real
release), and ``release`` does everything a version bump needs in one step:

  1. set the new version (explicit or ``--bump patch|minor|major``),
  2. rewrite the old version substring inside artifact URLs,
  3. fill every ``archive`` target's ``sha256`` (and ``release.artifact``)
     from the real artifact files,
  4. stamp ``release.published_at`` / ``valid_until``,
  5. sign (optional) and validate the result before anything is written.

Pure functions; the CLI in :mod:`axp.cli` owns argument parsing and IO.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import manifest as manifest_mod

PLACEHOLDER_SHA = "0" * 64
_BUMP_PARTS = ("major", "minor", "patch")


class PublishError(ValueError):
    """A publisher-side problem (bad bump, missing artifact…). User-facing."""


def skeleton(
    *,
    publisher: str,
    name: str,
    display_name: str,
    description: str,
    runtimes: tuple[str, ...] = ("posix",),
    base_url: str | None = None,
) -> dict:
    """A structurally valid v0.3 manifest to start from.

    Digests are all-zero placeholders (valid hex, so ``axp validate`` passes
    immediately); ``axp release`` replaces them with real ones. The update
    source defaults to ``direct`` at the publisher's well-known URL — the
    zero-infrastructure option; switch to ``github``/``feed`` by hand.
    """
    if not manifest_mod.PUBLISHER_RE.match(publisher):
        raise PublishError(f"publisher {publisher!r} must be a lowercase DNS name")
    if not manifest_mod.NAME_RE.match(name) or len(name) > manifest_mod.NAME_MAX_LEN:
        raise PublishError(f"name {name!r} must match [a-z0-9][a-z0-9_-]* (max 64 chars)")
    base = (base_url or f"https://{publisher}").rstrip("/")
    if not base.lower().startswith("https://"):
        raise PublishError("base url must be https://")
    artifact_url = f"{base}/{name}-0.1.0.tar.gz"
    return {
        "spec_version": "0.3",
        "kind": "agent-extension",
        "identity": {
            "publisher": publisher,
            "name": name,
            "version": "0.1.0",
            "display_name": display_name,
            "description": description,
        },
        "provides": {},
        "permissions": {"network_egress": [], "filesystem": ["state:rw"], "root": False},
        "release": {
            "channel": "stable",
            "artifact": {"url": artifact_url, "sha256": PLACEHOLDER_SHA},
        },
        "updates": {
            "source": {"kind": "direct", "url": f"{base}/.well-known/agent-extension.json"},
            "check": "daily",
            "policy": "notify",
        },
        "targets": [
            {
                "runtime": runtime,
                "enforcement": "declared",
                "delivery": {"method": "archive", "url": artifact_url, "sha256": PLACEHOLDER_SHA},
                "lifecycle": {"install": "install.sh", "uninstall": "uninstall.sh",
                              "health": "healthcheck.sh"},
            }
            for runtime in runtimes
        ],
    }


def bump_version(version: str, part: str) -> str:
    """``1.2.3`` + ``minor`` → ``1.3.0``. Pre-release/build tags are dropped —
    a bump always lands on a plain release version."""
    if part not in _BUMP_PARTS:
        raise PublishError(f"bump must be one of {list(_BUMP_PARTS)} (got {part!r})")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if match is None:
        raise PublishError(f"cannot bump non-semver version {version!r}")
    major, minor, patch = (int(g) for g in match.groups())
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file, streamed (artifacts can be large)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_artifact_args(specs: list[str]) -> dict[str | None, Path]:
    """``[runtime=]path`` CLI specs → mapping. Key ``None`` = every runtime
    without its own entry (and ``release.artifact``)."""
    out: dict[str | None, Path] = {}
    for spec in specs:
        runtime, sep, raw_path = spec.partition("=")
        key, path = (runtime, Path(raw_path)) if sep else (None, Path(spec))
        if key in out:
            raise PublishError(f"duplicate artifact for {key or 'the default'}")
        if not path.is_file():
            raise PublishError(f"artifact file not found: {path}")
        out[key] = path
    return out


def prepare_release(
    data: dict,
    *,
    artifacts: dict[str | None, Path],
    version: str | None = None,
    bump: str | None = None,
    channel: str | None = None,
    valid_days: int | None = 30,
    now: datetime | None = None,
) -> dict:
    """Return a release-ready copy of ``data`` (unsigned; signing is a
    separate explicit step so the key never has to be present here).

    Every ``archive`` target must end up with a real digest: from its
    runtime-specific artifact, else the default one. A leftover placeholder
    digest is an error — a release must never ship unverifiable bytes.
    """
    if version is not None and bump is not None:
        raise PublishError("pass either an explicit version or --bump, not both")
    old_version = str((data.get("identity") or {}).get("version") or "")
    new_version = version or (bump_version(old_version, bump) if bump else old_version)
    if not manifest_mod.SEMVER_RE.match(new_version):
        raise PublishError(f"version {new_version!r} is not semver")
    if not artifacts:
        raise PublishError("at least one --artifact is required")

    out = {key: value for key, value in data.items() if key not in ("signature", "signature_prev")}
    out["identity"] = {**out["identity"], "version": new_version}

    def refresh_url(url: str) -> str:
        # The one deliberate bit of magic: version-in-filename URLs follow
        # the bump (…/x-1.2.0.tar.gz → …/x-1.3.0.tar.gz). Documented in
        # the module docstring; URLs without the old version are untouched.
        return url.replace(old_version, new_version) if old_version else url

    default = artifacts.get(None)
    used: set[str | None] = set()
    targets = []
    for target in out.get("targets") or []:
        target = dict(target)
        delivery = dict(target.get("delivery") or {})
        if delivery.get("method") == manifest_mod.DELIVERY_ARCHIVE:
            artifact = artifacts.get(target.get("runtime"), default)
            if artifact is None:
                raise PublishError(
                    f"no artifact for runtime {target.get('runtime')!r} and no default given"
                )
            used.add(target.get("runtime") if target.get("runtime") in artifacts else None)
            delivery["url"] = refresh_url(str(delivery.get("url") or ""))
            delivery["sha256"] = sha256_file(artifact)
            target["delivery"] = delivery
        targets.append(target)
    out["targets"] = targets

    unused = sorted(key for key in artifacts if key is not None and key not in used)
    if unused:
        raise PublishError(f"artifacts given for runtimes the manifest has no archive target for: {unused}")

    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    release: dict = dict(out.get("release") or {})
    release.setdefault("channel", "stable")
    if channel is not None:
        release["channel"] = channel
    release_artifact: dict = dict(release.get("artifact") or {})
    canonical = default or next(iter(artifacts.values()))
    release_artifact["url"] = refresh_url(str(release_artifact.get("url") or targets[0]["delivery"]["url"]))
    release_artifact["sha256"] = sha256_file(canonical)
    release["artifact"] = release_artifact
    release["published_at"] = stamp.isoformat().replace("+00:00", "Z")
    if valid_days:
        release["valid_until"] = (stamp + timedelta(days=valid_days)).isoformat().replace("+00:00", "Z")
    else:
        release.pop("valid_until", None)
    out["release"] = release
    return out
