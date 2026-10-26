"""The ``axp`` command-line tool.

Publisher side::

    axp init --publisher ext.example.com --name my-ext --description "…"
    axp keygen --out signing.key            # prints the ed25519:… public form
    axp validate agent-extension.json
    axp release agent-extension.json --bump patch --artifact dist/my-ext.tar.gz --key signing.key
    axp sign agent-extension.json --key signing.key --in-place
    axp sign agent-extension.json --key new.key --prev-key old.key --in-place   # rotation release
    axp resolve https://github.com/you/my-ext    # the document a host installs from the repo, verified
    axp resolve https://github.com/you/my-ext --installed 1.2.0 --tracked stable   # what it would update to

Host side::

    axp verify agent-extension.json                     # against its own key (TOFU first use)
    axp verify agent-extension.json --pinned ed25519:…  # against the pinned key
    axp verify agent-extension.json --keydir agent-extension-keys.json  # key listed by the publisher?
    axp verify agent-extension.json --artifact dist/my-ext.tar.gz       # digest matches the manifest?
    axp target agent-extension.json --runtime hermes --runtime posix
    axp canonicalize agent-extension.json > canonical.bin

Commerce (SPEC 14) — issuer, host and artifact-server side::

    axp keygen --out issuing.key                # an ONLINE entitlement key; list it with --entitlement-key
    axp keydir --publisher ext.example.com --key ed25519:MANIFEST…@my-ext \
        --entitlement-key ed25519:ISSUING…@my-ext -o agent-extension-keys.json
    axp entitlement issue --key issuing.key --issuer ext.example.com --extension ext.example.com/my-ext \
        --holder ed25519:HOST… --plan pro --valid-days 30 -o entitlement.json
    axp entitlement verify entitlement.json --manifest agent-extension.json --holder ed25519:HOST…
    axp entitlement present entitlement.json --host-key host.key --audience https://…/my-ext-1.0.0.tar.gz
    axp entitlement inspect "AXP-Entitlement eyJ…" --audience https://…/my-ext-1.0.0.tar.gz --keydir keys.json

Exit codes: 0 success, 1 validation/verification failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, entitlements, jcs, manifest, publish, repository, signing, templates, readiness
from . import project, package


def _read_key(path: str | None) -> bytes | None:
    if not path:
        return None
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise SystemExit(f"axp: cannot read key {path}: {exc}")


def _load(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"axp: cannot read {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"axp: {path} is not a JSON object")
    return data


def _cmd_validate(args: argparse.Namespace) -> int:
    if args.format != "legacy":
        try:
            report = readiness.structural(_load(args.manifest), origin=args.origin)
        except (SystemExit, UnicodeError) as exc:
            report = _input_report(exc)
        readiness.render(report, args.format)
        return 0 if report["structurally_valid"] else 1
    data = _load(args.manifest)
    try:
        summary = manifest.validate(data, origin=args.origin)
    except manifest.ManifestError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


def _input_report(exc: BaseException) -> dict:
    return dict(status="invalid", structurally_valid=False, diagnostics=[readiness.diagnostic(
        "AXP_INPUT_INVALID", "input", str(exc), "Supply a readable JSON object and existing local artifact paths.")])


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        root, config = project.load(args.manifest, args.config)
        artifact_args = args.artifact
        if not artifact_args and config.get("artifact"):
            default = project.path_default(root, config, "artifact")
            artifact_args = [default] if Path(default).is_file() else []
        report = readiness.check(_load(args.manifest), root=Path(args.manifest).parent,
                                 artifacts=publish.parse_artifact_args(artifact_args or []), runtimes=args.runtime)
    except (SystemExit, OSError, ValueError) as exc:
        report = _input_report(exc)
    readiness.render(report, args.format)
    return 0 if report["status"] == "publish_ready" else 1


def _cmd_canonicalize(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        sys.stdout.buffer.write(jcs.signing_input(data))
    except jcs.JCSError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"axp: {out} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    pem = signing.generate_private_key_pem()
    out.touch(mode=0o600)
    out.write_bytes(pem)
    print(signing.public_key_from_private(pem))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        target = args.manifest if args.in_place else args.output
        if target and any(p.is_symlink() for p in (Path(target), *Path(target).parents)):
            raise publish.PublishError("Refusing symlink signing destination.")
        if args.output and Path(args.output).exists():
            raise publish.PublishError("Signing output already exists; choose a new path or use --in-place on the manifest.")
        root, config = project.load(args.manifest, args.config)
        key = args.key or project.path_default(root, config, "signing_key")
        if not key:
            raise publish.PublishError("Pass --key PATH or set project.signing_key in axp.toml.")
        pem = Path(key).read_bytes()
        if not data.get("signing"):
            data["signing"] = {"public_key": signing.public_key_from_private(pem)}
        # Sign first, validate the signed result: the input is legitimately
        # "invalid" until the signature exists, but nothing broken may be
        # published, so validation gates the write.
        signed = signing.sign_manifest(
            data, pem, prev_private_key_pem=_read_key(args.prev_key),
        )
        manifest.validate(signed, origin=args.origin)
        text = json.dumps(signed, indent=2, ensure_ascii=False) + "\n"
        if target:
            Path(target).write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"axp: {exc}. Remedy: check destination parents, permissions and available disk space.", file=sys.stderr)
        return 1
    except (manifest.ManifestError, signing.SigningError, publish.PublishError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    if target:
        print(f"signed: {target}")
    else:
        sys.stdout.write(text)
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    out_dir = Path(args.dir)
    manifest_path = out_dir / "agent-extension.json"
    if manifest_path.exists() and not args.force:
        print(f"axp: {manifest_path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    try:
        data = publish.skeleton(
            publisher=args.publisher,
            name=args.name,
            display_name=args.display_name or args.name,
            description=args.description,
            runtimes=tuple(args.runtime or ["posix"]),
            base_url=args.base_url,
        )
        manifest.validate(data)
        if args.template:
            templates.write(out_dir, templates.files(data, args.template), force=args.force)
            print(f"created: {manifest_path} (draft {args.template} project; next: axp check, axp pack)")
            return 0
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"axp: {exc}. Remedy: check destination parents, permissions and available disk space.", file=sys.stderr)
        return 1
    except (publish.PublishError, manifest.ManifestError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print(f"created: {manifest_path}")
    return 0


def _cmd_pack(args: argparse.Namespace) -> int:
    try:
        root, config = project.load(args.manifest, args.config)
        output = args.output or project.path_default(root, config, "artifact")
        if not output:
            raise publish.PublishError("Set project.artifact in axp.toml or pass --output PATH.")
        names = package.pack(root, args.file or config.get("files", []), Path(output), force=args.force,
                             signing_key=Path(project.path_default(root, config, "signing_key")) if config.get("signing_key") else None)
    except (OSError, ValueError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print(f"packed {len(names)} files: {output}; next: axp release {args.manifest} --key PATH (local only)")
    return 0


def _cmd_release(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        target = Path(args.output or args.manifest)
        if any(p.is_symlink() for p in (target, *target.parents)):
            raise publish.PublishError("Refusing symlink release destination.")
        if args.output and target.exists() and not args.force:
            raise publish.PublishError(f"{target} already exists (use --force to overwrite)")
        root, config = project.load(args.manifest, args.config)
        artifact_args = args.artifact or ([project.path_default(root, config, "artifact")] if config.get("artifact") else [])
        key = args.key or project.path_default(root, config, "signing_key")
        artifacts = publish.parse_artifact_args(artifact_args)
        protected = [*artifacts.values(), *[Path(p) for p in (key, args.prev_key) if p]]
        if any(target.resolve() == p.resolve() or (target.exists() and p.exists() and target.samefile(p)) for p in protected):
            raise publish.PublishError("Release destination must not overwrite an artifact or signing key.")
        released = publish.prepare_release(
            data,
            artifacts=artifacts,
            version=args.set_version,
            bump=args.bump,
            channel=args.channel,
            valid_days=args.valid_days,
        )
        if key:
            pem = Path(key).read_bytes()
            if not released.get("signing"):
                released["signing"] = {"public_key": signing.public_key_from_private(pem)}
            released = signing.sign_manifest(
                released, pem, prev_private_key_pem=_read_key(args.prev_key),
            )
        elif args.prev_key:
            print("axp: --prev-key needs --key (the new key signs, the old one countersigns)", file=sys.stderr)
            return 2
        manifest.validate(released)
        target.write_text(json.dumps(released, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"axp: {exc}. Remedy: check destination parents, permissions and available disk space.", file=sys.stderr)
        return 1
    except (publish.PublishError, manifest.ManifestError, signing.SigningError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    if not key:
        print("warning: release is UNSIGNED (pass --key to sign)", file=sys.stderr)
    print(f"released {released['identity']['version']}: {target}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        ok = signing.verify_manifest(data, args.pinned)
    except signing.SigningError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    if not ok:
        print("signature INVALID")
        return 1
    if args.keydir:
        # SPEC 8.5: the manifest's key must be one the publisher lists for
        # this extension. Checked after the signature so the message names
        # the more specific problem.
        identity = data.get("identity") or {}
        try:
            listed = signing.parse_key_directory(
                _load(args.keydir), publisher=str(identity.get("publisher") or ""),
                name=str(identity.get("name") or "") or None,
            )
        except signing.SigningError as exc:
            print(f"axp: {exc}", file=sys.stderr)
            return 1
        key = (data.get("signing") or {}).get("public_key")
        if key not in listed:
            print(f"signature OK, but {key} is not listed in the publisher key directory for this extension",
                  file=sys.stderr)
            return 1
        print("signature OK; key listed in the publisher key directory")
    else:
        print("signature OK")
    if args.artifact:
        # The signature binds the digests; this closes the loop for the file
        # the publisher is about to upload ("is this the tarball I signed?").
        try:
            digest = publish.sha256_file(Path(args.artifact))
        except OSError as exc:
            print(f"axp: cannot read artifact {args.artifact}: {exc}", file=sys.stderr)
            return 1
        expected = {str(((data.get("release") or {}).get("artifact") or {}).get("sha256") or "").lower()}
        for target in data.get("targets") or []:
            delivery = (target.get("delivery") or {}) if isinstance(target, dict) else {}
            if delivery.get("method") == manifest.DELIVERY_ARCHIVE:
                expected.add(str(delivery.get("sha256") or "").lower())
        expected.discard("")
        if digest not in expected:
            print(f"artifact {args.artifact} has sha256 {digest}, which matches none of the "
                  f"manifest's archive digests", file=sys.stderr)
            return 1
        print(f"artifact digest OK ({digest[:12]}…)")
    return 0


def _cmd_target(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        runtime_versions = {}
        for spec in args.runtime_version:
            runtime, sep, version = spec.partition("=")
            if not sep or not version:
                print(f"axp: --runtime-version expects RUNTIME=VERSION, got {spec!r}", file=sys.stderr)
                return 2
            runtime_versions[runtime] = version
        target, runtime = manifest.select_target(
            data, runtimes=tuple(args.runtime), platform=args.platform,
            runtime_versions=runtime_versions,
        )
    except manifest.ManifestError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"runtime": runtime, "target": target}, indent=2))
    return 0


def _load_key_directory(source: str) -> dict:
    """A key directory from a local file or an https URL."""
    if source.startswith("https://"):
        try:
            body = repository.http_fetch(source, repository.MAX_MANIFEST_BYTES)
        except repository.RepositoryError as exc:
            raise SystemExit(f"axp: cannot fetch key directory {source}: {exc}")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise SystemExit(f"axp: key directory {source} is not valid JSON: {exc}")
        if not isinstance(data, dict):
            raise SystemExit(f"axp: key directory {source} is not a JSON object")
        return data
    return _load(source)


def _cmd_resolve(args: argparse.Namespace) -> int:
    """Preview the SPEC 3.1 repository walk and the checks a host runs on
    its outcome, so a publisher sees the document hosts will install BEFORE
    a host does: which candidate answered, whether the signature verifies
    and whether the key is listed in the publisher's key directory."""
    try:
        resolution = repository.resolve(args.locator, repository.http_fetch)
    except repository.RepositoryError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    data = resolution.manifest
    identity = data.get("identity") or {}
    publisher = str(identity.get("publisher") or "")
    name = str(identity.get("name") or "")
    problems: list[str] = []
    report: dict = {
        "locator": args.locator,
        "source": resolution.source,
        "manifest_url": resolution.manifest_url,
        "tried": resolution.tried,
        "publisher": publisher,
        "name": name,
        "version": identity.get("version"),
        "channel": (data.get("release") or {}).get("channel") or "stable",
        "signature_valid": False,
        "key_listed": None,
        "problems": problems,
    }
    try:
        manifest.validate(data)
    except manifest.ManifestError as exc:
        problems.append(f"invalid manifest: {exc}")
    try:
        report["signature_valid"] = signing.verify_manifest(data, args.pinned)
    except signing.SigningError as exc:
        problems.append(f"signature: {exc}")
    if not report["signature_valid"] and not any(p.startswith("signature") for p in problems):
        problems.append("signature INVALID" + (" against the pinned key" if args.pinned else ""))
    if not args.no_keydir:
        # SPEC 8.5: a host on the Trusted profile refuses a key the publisher
        # does not list. Default: the publisher's own well-known directory -
        # the one hosts read.
        source = args.keydir or signing.key_directory_url(publisher)
        report["key_directory"] = source
        key = (data.get("signing") or {}).get("public_key")
        try:
            listed = signing.parse_key_directory(_load_key_directory(source), publisher=publisher, name=name or None)
            report["key_listed"] = key in listed
            if key not in listed:
                problems.append(f"{key} is not listed in {source} for this extension")
        except SystemExit as exc:
            report["key_listed"] = False
            problems.append(str(exc).removeprefix("axp: "))
        except signing.SigningError as exc:
            report["key_listed"] = False
            problems.append(f"key directory {source}: {exc}")
    if args.installed:
        tracked = args.tracked or str(report["channel"])
        try:
            found = repository.resolve_update(args.locator, tracked, args.installed, repository.http_fetch)
        except repository.RepositoryError as exc:
            problems.append(f"update source: {exc}")
            found = None
        report["update"] = {
            "installed": args.installed, "tracked": tracked,
            "candidate": (found.manifest.get("identity") or {}).get("version") if found else None,
            "manifest_url": found.manifest_url if found else None,
        }
    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        report["saved"] = args.output
    print(json.dumps(report, indent=2))
    return 1 if problems else 0


def _keydir_entry(spec: str, *, roles: list[str] | None = None) -> dict:
    """``ed25519:…[@name,name]`` → a key directory entry. Names may be bare
    (the publisher's own extensions) or full ``<publisher>/<name>`` ids."""
    # '@' separates the key from its extension names: base64 keys end in '='.
    public_key, sep, names = spec.partition("@")
    signing._raw_public_key(public_key)
    entry: dict = {"public_key": public_key}
    if sep and names:
        entry["extensions"] = [n for n in names.split(",") if n]
    if roles:
        entry["roles"] = roles
    return entry


def _cmd_keydir(args: argparse.Namespace) -> int:
    keys = []
    try:
        for spec in args.key or []:
            keys.append(_keydir_entry(spec))
        for spec in args.entitlement_key:
            # SPEC 14.3: an issuing key is online and says so; it never signs manifests.
            keys.append(_keydir_entry(spec, roles=[signing.ROLE_ENTITLEMENT]))
    except signing.SigningError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    if not keys and not args.revoked:
        print("axp: keydir needs at least one --key, --entitlement-key or --revoked", file=sys.stderr)
        return 2
    for public_key in args.revoked:
        keys.append({"public_key": public_key, "revoked": True})
    document = {"publisher": args.publisher, "keys": keys}
    # Round-trip through the parser so a broken document is caught here.
    signing.parse_key_directory(document, publisher=args.publisher, name=None)
    text = json.dumps(document, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote: {args.output} (serve it at {signing.key_directory_url(args.publisher)})")
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------------------
# Commerce (SPEC 14): entitlements
# ---------------------------------------------------------------------------

def _parse_at(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = entitlements.parse_timestamp(value)
    if parsed is None:
        raise SystemExit(f"axp: {value!r} is not an ISO-8601 timestamp")
    return parsed


def _deadline(explicit: str | None, days: int | None, *, now: datetime) -> str | None:
    if explicit:
        return explicit
    if days is not None:
        return entitlements.format_timestamp(now + timedelta(days=days))
    return None


def _cmd_entitlement_issue(args: argparse.Namespace) -> int:
    now = _parse_at(args.at) or datetime.now(timezone.utc)
    try:
        document = entitlements.issue(
            extension=args.extension, holder=args.holder, plan=args.plan, issuer=args.issuer,
            private_key_pem=Path(args.key).read_bytes(), key_id=args.key_id, issued_at=now,
            valid_until=_deadline(args.valid_until, args.valid_days, now=now),
            updates_until=_deadline(args.updates_until, args.updates_days, now=now),
            serial=args.serial,
        )
    except (entitlements.EntitlementError, signing.SigningError, OSError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"issued {document['serial']} to {document['holder']}: {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def _issuer_keys(args: argparse.Namespace, *, issuer: str, extension: str) -> list[str]:
    """The entitlement-role keys the caller trusts for ``issuer``: explicit
    ``--issuer-key`` values, a ``--keydir`` file/URL, or (default) the
    issuer's own well-known directory — the one hosts read (SPEC 14.3)."""
    if args.issuer_key:
        return list(args.issuer_key)
    source = args.keydir or signing.key_directory_url(issuer)
    try:
        return signing.parse_key_directory(_load_key_directory(source), publisher=issuer,
                                           name=extension, role=signing.ROLE_ENTITLEMENT)
    except signing.SigningError as exc:
        raise SystemExit(f"axp: key directory {source}: {exc}")


def _commerce_context(args: argparse.Namespace, document: dict) -> tuple[str, list[str] | None, int]:
    """Resolve extension, issuers and grace (CLI override > manifest > default)."""
    grace = args.grace_days
    if args.manifest:
        data = _load(args.manifest)
        try:
            summary = manifest.validate(data)
        except manifest.ManifestError as exc:
            raise SystemExit(f"axp: manifest: {exc}")
        commerce = summary.get("commerce") or {}
        if grace is None:
            grace = (data.get("commerce") or {}).get("grace_days", entitlements.DEFAULT_GRACE_DAYS)
        return summary["ext_id"], commerce.get("issuers") or [summary["publisher"]], grace
    return (args.extension or str(document.get("extension") or ""), None,
            entitlements.DEFAULT_GRACE_DAYS if grace is None else grace)


def _report(verdict: entitlements.Verdict, extra: dict | None = None) -> int:
    report = {"valid": verdict.valid, "status": verdict.status, "reason": verdict.reason, **(extra or {})}
    if verdict.entitlement is not None:
        report["entitlement"] = {k: verdict.entitlement.get(k) for k in
                                 ("extension", "holder", "plan", "serial", "issuer",
                                  "issued_at", "valid_until", "updates_until")}
    print(json.dumps(report, indent=2))
    return 0 if verdict.valid else 1


def _cmd_entitlement_verify(args: argparse.Namespace) -> int:
    document = _load(args.entitlement)
    try:
        entitlements.validate_entitlement(document)
    except entitlements.EntitlementError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    extension, issuers, grace_days = _commerce_context(args, document)
    issuer = str(document["issuer"])
    if issuers is not None and issuer not in issuers:
        # Refused before any fetch: never ask a stranger's directory to vouch.
        return _report(entitlements.Verdict(False, "untrusted_issuer",
                                            f"{issuer} is not an issuer the manifest names", document))
    verdict = entitlements.verify_entitlement(
        document, extension=extension, holder=args.holder,
        issuer_keys=_issuer_keys(args, issuer=issuer, extension=extension), issuers=issuers,
        now=_parse_at(args.at), grace_days=grace_days,
    )
    extra = {}
    if args.manifest and verdict.valid:
        extra["covers_release"] = entitlements.covers_release(document, _load(args.manifest))
    return _report(verdict, extra)


def _cmd_entitlement_present(args: argparse.Namespace) -> int:
    try:
        presentation = entitlements.make_presentation(
            host_private_key_pem=Path(args.host_key).read_bytes(), audience=args.audience,
            entitlement=_load(args.entitlement) if args.entitlement else None,
            extension=args.extension, now=_parse_at(args.at), ttl_seconds=args.ttl,
        )
        header = entitlements.authorization_header(presentation)
    except (entitlements.EntitlementError, signing.SigningError, OSError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print(header if args.value_only else f"Authorization: {header}")
    return 0


def _cmd_entitlement_inspect(args: argparse.Namespace) -> int:
    """What an artifact server or issuer does with an incoming request."""
    token = args.token
    if token.startswith("@"):
        try:
            token = Path(token[1:]).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"axp: cannot read {token[1:]}: {exc}")
    token = token.removeprefix("Authorization:").strip()
    now = _parse_at(args.at)
    try:
        presentation = entitlements.verify_presentation(token, audience=args.audience, now=now)
    except entitlements.EntitlementError as exc:
        return _report(entitlements.Verdict(False, "malformed", f"presentation: {exc}"))
    extension, issuers, grace_days = _commerce_context(args, presentation)
    extra = {"holder": presentation["holder"], "presented_for": presentation["extension"]}
    entitlement = presentation.get("entitlement")
    if entitlement is None:
        return _report(entitlements.Verdict(False, "no_entitlement", "presentation carries no entitlement"), extra)
    issuer = str(entitlement["issuer"])
    if issuers is not None and issuer not in issuers:
        return _report(entitlements.Verdict(False, "untrusted_issuer",
                                            f"{issuer} is not an issuer the manifest names", entitlement), extra)
    verdict = entitlements.verify_presented_entitlement(
        presentation, audience=args.audience, extension=extension,
        issuer_keys=_issuer_keys(args, issuer=issuer, extension=extension), issuers=issuers,
        now=now, grace_days=grace_days,
    )
    return _report(verdict, extra)


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return number


def _add_trust_options(p: argparse.ArgumentParser) -> None:
    """Where the entitlement-role keys come from (SPEC 14.3)."""
    group = p.add_mutually_exclusive_group()
    group.add_argument("--keydir", help="the issuer's key directory, file or https URL "
                                        "(default: the issuer's own well-known directory)")
    group.add_argument("--issuer-key", action="append", metavar="ed25519:...",
                       help="trust exactly this issuing key (repeatable; skips the directory)")
    p.add_argument("--manifest", help="the extension's manifest: supplies id, issuers and grace policy")
    p.add_argument("--extension", help="<publisher>/<name> when no --manifest is given (default: the document's)")
    p.add_argument("--grace-days", type=_non_negative_int, default=None,
                   help="override days past valid_until accepted as grace "
                        f"(otherwise commerce.grace_days, then {entitlements.DEFAULT_GRACE_DAYS})")
    p.add_argument("--at", metavar="ISO", help="evaluate at this time instead of now")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="axp", description="Agent Extension Protocol tooling")
    parser.add_argument("--version", action="version", version=f"axp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="offline static publish readiness (never executes package code)")
    p.add_argument("manifest", nargs="?", default="agent-extension.json")
    p.add_argument("--config", help="local axp.toml (default: beside manifest)")
    p.add_argument("--artifact", action="append", metavar="[RUNTIME=]PATH")
    p.add_argument("--runtime", action="append", help="require a matching runtime (repeatable)")
    p.add_argument("--format", choices=["text", "compact", "json"], default="text")
    p.set_defaults(func=_cmd_check)

    p = sub.add_parser("validate", help="structurally validate a manifest")
    p.add_argument("manifest")
    p.add_argument("--format", choices=["legacy", "compact", "json"], default="legacy")
    p.add_argument("--origin", help="domain the manifest was fetched from (derives a missing v0.2 publisher)")
    p.set_defaults(func=_cmd_validate)

    p = sub.add_parser("canonicalize", help="print the JCS signing input (manifest minus signatures)")
    p.add_argument("manifest")
    p.set_defaults(func=_cmd_canonicalize)

    p = sub.add_parser("init", help="write a valid manifest skeleton to start from")
    p.add_argument("--publisher", required=True, help="your DNS name, e.g. ext.example.com")
    p.add_argument("--name", required=True, help="extension slug, e.g. graph-memory")
    p.add_argument("--description", required=True)
    p.add_argument("--display-name", help="human label (default: the slug)")
    p.add_argument("--runtime", action="append",
                   help="target runtime (repeatable; default: posix)")
    p.add_argument("--base-url", help="where artifacts + the well-known manifest are served (default: https://<publisher>)")
    p.add_argument("--dir", default=".", help="directory to write agent-extension.json into")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_init)
    p.add_argument("--template", choices=templates.KINDS, help="create a runnable local example project")

    p = sub.add_parser("pack", help="pack an explicit local file list; never runs a build or publishes")
    p.add_argument("manifest", nargs="?", default="agent-extension.json")
    p.add_argument("--config", help="local axp.toml (default: beside manifest)")
    p.add_argument("--file", action="append", help="explicit relative file/directory (repeatable; overrides project.files)")
    p.add_argument("-o", "--output", help="tar.gz destination (overrides project.artifact)")
    p.add_argument("--force", action="store_true", help="replace an existing archive")
    p.set_defaults(func=_cmd_pack)

    p = sub.add_parser("release", help="locally bump, hash, date and sign; never uploads or runs builds")
    p.add_argument("manifest")
    p.add_argument("--config", help="local axp.toml (default: beside manifest)")
    p.add_argument("--artifact", action="append", metavar="[RUNTIME=]PATH",
                   help="artifact file; bare PATH is the default for every archive target, "
                        "RUNTIME=PATH overrides one runtime (repeatable)")
    p.add_argument("--force", action="store_true", help="allow replacing an existing --output file")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--version", dest="set_version", help="explicit new semver")
    group.add_argument("--bump", choices=["major", "minor", "patch"])
    p.add_argument("--channel", help="release channel (default: keep the manifest's)")
    p.add_argument("--valid-days", type=int, default=180,
                   help="freshness window for valid_until; 0 drops the field (default: 180 - "
                        "SPEC 7.4: generous, you commit to re-releasing before it lapses)")
    p.add_argument("--key", help="private key PEM from `axp keygen`; omitting leaves the release unsigned")
    p.add_argument("--prev-key", help="the OLD key for a rotation release (SPEC 8.3): adds signature_prev")
    p.add_argument("-o", "--output", help="write here instead of in place")
    p.set_defaults(func=_cmd_release)

    p = sub.add_parser("keygen", help="generate an ed25519 signing key (prints the public form)")
    p.add_argument("--out", required=True, help="private key PEM path (written 0600)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("sign", help="validate + sign a manifest")
    p.add_argument("manifest")
    p.add_argument("--config", help="local axp.toml (default: beside manifest)")
    p.add_argument("--key", help="private key PEM path (overrides project.signing_key)")
    p.add_argument("--prev-key", help="the OLD key for a rotation release (SPEC 8.3): adds signature_prev")
    p.add_argument("--origin", help="as in validate")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--in-place", action="store_true", help="write the signature back into the manifest file")
    group.add_argument("-o", "--output", help="write the signed manifest here (default: stdout)")
    p.set_defaults(func=_cmd_sign)

    p = sub.add_parser("verify", help="verify a manifest signature")
    p.add_argument("manifest")
    p.add_argument("--pinned", help="verify against this pinned key instead of the manifest's own")
    p.add_argument("--keydir", help="a publisher key directory file (SPEC 8.5); the signing key must be listed for this extension")
    p.add_argument("--artifact", help="an artifact file whose sha256 must match release.artifact or an archive target")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("target", help="pick the target a host would install")
    p.add_argument("manifest")
    p.add_argument("--runtime", action="append", required=True,
                   help="host runtimes in preference order (repeatable; add posix last for the fallback)")
    p.add_argument("--platform", help="os/arch, default: this machine")
    p.add_argument("--runtime-version", action="append", default=[], metavar="RUNTIME=VERSION",
                   help="the version of a runtime this host runs, e.g. hermes=2026.8 (repeatable); "
                        "targets whose runtime_version constraint it fails are skipped")
    p.set_defaults(func=_cmd_target)

    p = sub.add_parser("resolve", help="the manifest a host would install from a repository locator, verified")
    p.add_argument("locator", help="https://github.com/<owner>/<repo>[.git | /tree/<ref> | /releases/tag/<tag>]")
    p.add_argument("--pinned", help="verify the signature against this pinned key instead of the manifest's own")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--keydir", help="key directory file or https URL (default: the publisher's well-known one)")
    group.add_argument("--no-keydir", action="store_true", help="skip the SPEC 8.5 key-directory check")
    p.add_argument("--installed", metavar="VERSION",
                   help="also show what the github update source offers a host that has VERSION installed")
    p.add_argument("--tracked", metavar="CHANNEL",
                   help="the channel that host tracks (default: the resolved manifest's channel)")
    p.add_argument("-o", "--output", help="save the resolved manifest here")
    p.set_defaults(func=_cmd_resolve)

    p = sub.add_parser("keydir", help="write a publisher key directory (SPEC 8.5 / 14.3) from public keys")
    p.add_argument("--publisher", required=True)
    p.add_argument("--key", action="append", default=[], metavar="ed25519:...[@NAME,NAME]",
                   help="a manifest signing key, optionally restricted to extension names after '@' (repeatable)")
    p.add_argument("--entitlement-key", action="append", default=[], metavar="ed25519:...[@NAME,NAME]",
                   help="an entitlement issuing key (SPEC 14.3; roles: [entitlement]); names may be full "
                        "<publisher>/<name> ids when issuing for other publishers (repeatable)")
    p.add_argument("--revoked", action="append", default=[], metavar="ed25519:...",
                   help="a key to list as revoked (repeatable)")
    p.add_argument("-o", "--output", help="write here (default: stdout)")
    p.set_defaults(func=_cmd_keydir)

    ent = sub.add_parser("entitlement", help="commerce (SPEC 14): issue, verify and present entitlements")
    ent_sub = ent.add_subparsers(dest="entitlement_command", required=True)

    p = ent_sub.add_parser("issue", help="sign an entitlement for one host (the issuer side)")
    p.add_argument("--key", required=True, help="the issuing key PEM (list its public form with keydir --entitlement-key)")
    p.add_argument("--issuer", required=True, help="DNS name whose key directory lists the issuing key")
    p.add_argument("--extension", required=True, help="<publisher>/<name>")
    p.add_argument("--holder", required=True, help="the host key, ed25519:... (what the host sent to checkout)")
    p.add_argument("--plan", required=True, help="plan id from the manifest's commerce.plans")
    p.add_argument("--key-id", help="human label of the issuing key")
    p.add_argument("--serial", help="issuer's unique id for this entitlement (default: random)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--valid-until", metavar="ISO", help="end of use (omit both for perpetual use)")
    group.add_argument("--valid-days", type=int, help="end of use, days from now (a subscription period / trial)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--updates-until", metavar="ISO", help="last release date covered (omit both for all updates)")
    group.add_argument("--updates-days", type=int, help="update window, days from now")
    p.add_argument("--at", metavar="ISO", help="issue as of this time instead of now")
    p.add_argument("-o", "--output", help="write here (default: stdout)")
    p.set_defaults(func=_cmd_entitlement_issue)

    p = ent_sub.add_parser("verify", help="check an entitlement as a host would (SPEC 14.3)")
    p.add_argument("entitlement", help="the entitlement document")
    p.add_argument("--holder", help="this host's key; omitted = do not check the binding")
    _add_trust_options(p)
    p.set_defaults(func=_cmd_entitlement_verify)

    p = ent_sub.add_parser("present", help="the Authorization header a host sends (SPEC 14.4 / 14.5)")
    p.add_argument("entitlement", nargs="?", help="the entitlement to present; omit to request one from an issuer")
    p.add_argument("--host-key", required=True, help="the host key PEM (axp keygen)")
    p.add_argument("--audience", required=True, help="the exact https URL the request goes to")
    p.add_argument("--extension", help="<publisher>/<name> (required when no entitlement is presented)")
    p.add_argument("--ttl", type=int, default=entitlements.DEFAULT_PRESENTATION_TTL_SECONDS,
                   help=f"lifetime in seconds (default {entitlements.DEFAULT_PRESENTATION_TTL_SECONDS})")
    p.add_argument("--at", metavar="ISO", help="issue as of this time instead of now")
    p.add_argument("--value-only", action="store_true", help="print only the header value")
    p.set_defaults(func=_cmd_entitlement_present)

    p = ent_sub.add_parser("inspect", help="check a presented header as an artifact server or issuer would")
    p.add_argument("token", help="the Authorization header value, or @FILE holding it")
    p.add_argument("--audience", required=True, help="the exact https URL that received it")
    _add_trust_options(p)
    p.set_defaults(func=_cmd_entitlement_inspect)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
