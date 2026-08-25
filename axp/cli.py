"""The ``axp`` command-line tool.

Publisher side::

    axp init --publisher ext.example.com --name my-ext --description "…"
    axp keygen --out signing.key            # prints the ed25519:… public form
    axp validate agent-extension.json
    axp release agent-extension.json --bump patch --artifact dist/my-ext.tar.gz --key signing.key
    axp sign agent-extension.json --key signing.key --in-place

Host side::

    axp verify agent-extension.json                     # against its own key (TOFU first use)
    axp verify agent-extension.json --pinned ed25519:…  # against the pinned key
    axp verify agent-extension.json --keydir agent-extension-keys.json  # key listed by the publisher?
    axp target agent-extension.json --runtime hermes --runtime posix
    axp canonicalize agent-extension.json > canonical.bin

Exit codes: 0 success, 1 validation/verification failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, jcs, manifest, publish, signing


def _load(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"axp: cannot read {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"axp: {path} is not a JSON object")
    return data


def _cmd_validate(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        summary = manifest.validate(data, origin=args.origin)
    except manifest.ManifestError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


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
        # Sign first, validate the signed result: the input is legitimately
        # "invalid" until the signature exists, but nothing broken may be
        # published, so validation gates the write.
        signed = signing.sign_manifest(data, Path(args.key).read_bytes())
        manifest.validate(signed, origin=args.origin)
    except (manifest.ManifestError, signing.SigningError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(signed, indent=2, ensure_ascii=False) + "\n"
    target = args.manifest if args.in_place else args.output
    if target:
        Path(target).write_text(text, encoding="utf-8")
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
    except (publish.PublishError, manifest.ManifestError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"created: {manifest_path}")
    return 0


def _cmd_release(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        released = publish.prepare_release(
            data,
            artifacts=publish.parse_artifact_args(args.artifact),
            version=args.set_version,
            bump=args.bump,
            channel=args.channel,
            valid_days=args.valid_days,
        )
        if args.key:
            released = signing.sign_manifest(released, Path(args.key).read_bytes())
        manifest.validate(released)
    except (publish.PublishError, manifest.ManifestError, signing.SigningError) as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    if not args.key:
        print("warning: release is UNSIGNED (pass --key to sign)", file=sys.stderr)
    target = args.output or args.manifest
    Path(target).write_text(json.dumps(released, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
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
        return 0
    print("signature OK")
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


def _cmd_keydir(args: argparse.Namespace) -> int:
    keys = []
    for spec in args.key:
        # '@' separates the key from its extension names: base64 keys end in '='.
        public_key, sep, names = spec.partition("@")
        try:
            signing._raw_public_key(public_key)
        except signing.SigningError as exc:
            print(f"axp: {exc}", file=sys.stderr)
            return 1
        entry = {"public_key": public_key}
        if sep and names:
            entry["extensions"] = [n for n in names.split(",") if n]
        keys.append(entry)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="axp", description="Agent Extension Protocol tooling")
    parser.add_argument("--version", action="version", version=f"axp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="structurally validate a manifest")
    p.add_argument("manifest")
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

    p = sub.add_parser("release", help="bump version, fill artifact digests, stamp dates, sign")
    p.add_argument("manifest")
    p.add_argument("--artifact", action="append", required=True, metavar="[RUNTIME=]PATH",
                   help="artifact file; bare PATH is the default for every archive target, "
                        "RUNTIME=PATH overrides one runtime (repeatable)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--version", dest="set_version", help="explicit new semver")
    group.add_argument("--bump", choices=["major", "minor", "patch"])
    p.add_argument("--channel", help="release channel (default: keep the manifest's)")
    p.add_argument("--valid-days", type=int, default=180,
                   help="freshness window for valid_until; 0 drops the field (default: 180 - "
                        "SPEC 7.4: generous, you commit to re-releasing before it lapses)")
    p.add_argument("--key", help="private key PEM from `axp keygen`; omitting leaves the release unsigned")
    p.add_argument("-o", "--output", help="write here instead of in place")
    p.set_defaults(func=_cmd_release)

    p = sub.add_parser("keygen", help="generate an ed25519 signing key (prints the public form)")
    p.add_argument("--out", required=True, help="private key PEM path (written 0600)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("sign", help="validate + sign a manifest")
    p.add_argument("manifest")
    p.add_argument("--key", required=True, help="private key PEM from `axp keygen`")
    p.add_argument("--origin", help="as in validate")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--in-place", action="store_true", help="write the signature back into the manifest file")
    group.add_argument("-o", "--output", help="write the signed manifest here (default: stdout)")
    p.set_defaults(func=_cmd_sign)

    p = sub.add_parser("verify", help="verify a manifest signature")
    p.add_argument("manifest")
    p.add_argument("--pinned", help="verify against this pinned key instead of the manifest's own")
    p.add_argument("--keydir", help="a publisher key directory file (SPEC 8.5); the signing key must be listed for this extension")
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

    p = sub.add_parser("keydir", help="write a publisher key directory (SPEC 8.5) from public keys")
    p.add_argument("--publisher", required=True)
    p.add_argument("--key", action="append", required=True, metavar="ed25519:...[@NAME,NAME]",
                   help="a public key, optionally restricted to extension names after '@' (repeatable)")
    p.add_argument("--revoked", action="append", default=[], metavar="ed25519:...",
                   help="a key to list as revoked (repeatable)")
    p.add_argument("-o", "--output", help="write here (default: stdout)")
    p.set_defaults(func=_cmd_keydir)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
