"""Offline publisher readiness. A green report is not a host trust decision."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import tarfile
import zipfile
import zlib
import lzma
from urllib.parse import urlsplit

from . import manifest, publish, signing, package


def diagnostic(code: str, field: str, message: str, remedy: str) -> dict:
    return dict(code=code, field=field, message=message, remedy=remedy)


def structural(data: dict, *, origin: str | None = None) -> dict:
    try:
        summary = manifest.validate(data, origin=origin)
        return dict(status="structurally_valid", structurally_valid=True, diagnostics=[], summary=summary)
    except manifest.ManifestError as exc:
        field, _, message = str(exc).partition(": ")
        return dict(status="invalid", structurally_valid=False, diagnostics=[
            diagnostic("AXP_MANIFEST_INVALID", field or "manifest", message or str(exc),
                       "Correct this field according to the AXP manifest specification; run axp validate again.")])


def references(data: dict, target: dict) -> list[tuple[str, str]]:
    refs = [("lifecycle." + hook, path) for hook, path in target.get("lifecycle", {}).items()
            if path is not None]
    for kind, items in data.get("provides", {}).items():
        if isinstance(items, list):
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                prefix = f"provides.{kind}[{index}]"
                if isinstance(item.get("path"), str):
                    refs.append((prefix + ".path", item["path"]))
                command = item.get("command")
                if isinstance(command, str) and "/" in command:
                    refs.append((prefix + ".command", command))
                args = item.get("args")
                # Only a direct script invocation is statically identifiable;
                # never interpret shell command text or arbitrary argument paths.
                if command in ("python3", "python", "sh", "bash", "node") and isinstance(args, list):
                    if args and isinstance(args[0], str) and not args[0].startswith("-"):
                        refs.append((prefix + ".args[0]", args[0]))
    return refs


def placeholders(value, field=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from placeholders(item, f"{field}.{key}" if field else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from placeholders(item, f"{field}[{index}]")
    elif isinstance(value, str):
        try:
            host = ((urlsplit(value).hostname or "") if value.startswith(("http://", "https://")) else value).lower()
        except ValueError:
            return  # An opaque extension field need not contain a valid URL.
        if any(host == suffix or host.endswith("." + suffix)
               for suffix in ("example.com", "example.org", "example.net", "example", "invalid", "test")):
            yield diagnostic("AXP_PLACEHOLDER", field, "Reserved example/placeholder domain.",
                             "Replace with a publisher or delivery address you control before release.")


def check(data: dict, *, root: Path = Path("."), artifacts: dict | None = None,
          runtimes: list[str] | None = None) -> dict:
    report = structural(data)
    if not report["structurally_valid"]:
        return report
    problems = report["diagnostics"]
    problems.extend(placeholders(data))
    deadline = (data.get("release") or {}).get("valid_until")
    if deadline:
        expires = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        if expires.tzinfo is None:
            problems.append(diagnostic("AXP_RELEASE_TIMEZONE_MISSING", "release.valid_until",
                                       "Release freshness deadline is missing a timezone.",
                                       "Add a timezone suffix such as Z or +00:00 to release.valid_until, then re-sign the manifest."))
        elif expires <= datetime.now(timezone.utc):
            problems.append(diagnostic("AXP_RELEASE_EXPIRED", "release.valid_until", "Release freshness window has expired.",
                                       "Review the package and run axp release to renew dates and signature."))
    artifacts = artifacts or {}
    release_artifact = (data.get("release") or {}).get("artifact") or {}
    if release_artifact.get("sha256") == publish.PLACEHOLDER_SHA:
        problems.append(diagnostic("AXP_PLACEHOLDER", "release.artifact.sha256", "Digest is a template placeholder.",
                                   "Pack the artifact and run axp release."))
    inspected = {}

    def inspect(archive):
        key = archive.resolve()
        if key not in inspected:
            inspected[key] = None
            try:
                inspected[key] = package.archive_files(archive)
            except package.UnsafePackage as exc:
                problems.append(diagnostic("AXP_ARCHIVE_UNSAFE", "artifact", str(exc),
                                           "Remove unsafe paths, links, duplicate entries and secrets; repack and release."))
            except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError,
                    NotImplementedError, zlib.error, lzma.LZMAError) as exc:
                problems.append(diagnostic("AXP_ARCHIVE_INVALID", "artifact", str(exc),
                                           "Supply a readable tar.gz or ZIP artifact."))
        return inspected[key]

    canonical = artifacts.get(None) or next(iter(artifacts.values()), None)
    if canonical is not None:
        inspect(canonical)
    if canonical is not None and canonical.is_file() and release_artifact.get("sha256"):
        if publish.sha256_file(canonical) != release_artifact["sha256"].lower():
            problems.append(diagnostic("AXP_DIGEST_MISMATCH", "release.artifact.sha256", "Release artifact digest does not match.",
                                       "Supply the canonical artifact as a bare --artifact PATH and run axp release."))
    if runtimes and not any(t.get("runtime") in runtimes for t in data.get("targets", [])):
        problems.append(diagnostic("AXP_RUNTIME_UNSUPPORTED", "targets", "No target matches the requested runtimes.",
                                   "Choose a declared --runtime or add a compatible target."))
    for index, target in enumerate(data.get("targets", [])):
        if target.get("runtime") not in ("posix", "hermes", "openclaw", "claude-code"):
            problems.append(diagnostic("AXP_RUNTIME_UNCHECKED", f"targets[{index}].runtime",
                                       "This runtime has no bundled runtime profile document.",
                                       "Review its runtime profile separately; structural validity alone is not readiness."))
        delivery = target.get("delivery", {})
        if delivery.get("sha256") == publish.PLACEHOLDER_SHA:
            problems.append(diagnostic("AXP_PLACEHOLDER", f"targets[{index}].delivery.sha256",
                                       "Digest is a template placeholder.", "Pack the artifact and run axp release."))
        refs = references(data, target)
        safe_sources = set()
        for field, name in refs:
            try:
                package.safe_name(name)
                if any(p.is_symlink() for p in (root / name, *(root / name).parents)):
                    raise package.UnsafePackage(f"Symlink source is not allowed: {name}")
            except package.UnsafePackage as exc:
                problems.append(diagnostic("AXP_FILE_UNSAFE", field, str(exc),
                                           "Use a regular file at a safe project-relative path, without symlinks."))
                continue
            if not (root / name).is_file():
                problems.append(diagnostic("AXP_FILE_MISSING", field, f"Local file is missing: {name}",
                                           "Create the declared file or correct the manifest path."))
            else:
                safe_sources.add(name)
        if delivery.get("method") != "archive":
            problems.append(diagnostic("AXP_DELIVERY_UNCHECKED", f"targets[{index}].delivery",
                                       "Local readiness cannot inspect this delivery method.",
                                       "Use runtime-specific validation; this check cannot certify publish readiness."))
            continue
        archive = artifacts.get(target.get("runtime"), artifacts.get(None))
        if archive is None or not archive.is_file():
            problems.append(diagnostic("AXP_ARTIFACT_MISSING", f"targets[{index}].delivery",
                                       "No readable local artifact was supplied.", "Run axp pack, then axp check --artifact PATH."))
            continue
        if publish.sha256_file(archive) != delivery.get("sha256", "").lower():
            problems.append(diagnostic("AXP_DIGEST_MISMATCH", f"targets[{index}].delivery.sha256",
                                       "Artifact digest does not match.", "Repack if necessary and run axp release before signing."))
        try:
            names = inspect(archive)
            if names is None:
                continue
            for field, name in refs:
                if name not in names:
                    problems.append(diagnostic("AXP_ARCHIVE_CONTENT", field, f"Artifact is missing {name}.",
                                               "Add the declared file to the package file list, then pack and release again."))
                elif name in safe_sources:
                    with (root / name).open("rb") as handle:
                        if handle.read(package.MAX_BYTES + 1) != names[name]:
                            problems.append(diagnostic("AXP_CONTENT_MISMATCH", field, f"Source differs from the archive: {name}.",
                                                       "Repack the current source and run axp release again."))
        except package.UnsafePackage as exc:
            problems.append(diagnostic("AXP_ARCHIVE_UNSAFE", "artifact", str(exc),
                                       "Remove unsafe paths, links, duplicate entries and secrets; repack and release."))
        except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError,
                    NotImplementedError, zlib.error, lzma.LZMAError) as exc:
            problems.append(diagnostic("AXP_ARCHIVE_INVALID", "artifact", str(exc), "Supply a readable tar.gz or ZIP artifact."))
    if not data.get("signature"):
        problems.append(diagnostic("AXP_UNSIGNED", "signature", "Manifest is unsigned.",
                                   "Run axp release --key PATH or axp sign --key PATH --in-place."))
    else:
        try:
            if not signing.verify_manifest(data):
                raise signing.SigningError("Signature does not match the manifest.")
        except signing.SigningError as exc:
            problems.append(diagnostic("AXP_SIGNATURE_INVALID", "signature", str(exc), "Review the manifest and sign with its declared key."))
    report["status"] = "draft" if problems else "publish_ready"
    return report


def render(report: dict, format: str) -> None:
    import json
    if format == "json":
        print(json.dumps(report, indent=2))
        return
    print(report["status"] + (" (offline checks only; no execution or remote trust checks)" if format == "text" else ""))
    for item in report["diagnostics"]:
        print(f"{item['code']} {item['field']}: {item['message']} Remedy: {item['remedy']}")
