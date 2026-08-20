"""The ``axp`` command-line tool.

Publisher side::

    axp keygen --out signing.key            # prints the ed25519:… public form
    axp validate agent-extension.json
    axp sign agent-extension.json --key signing.key --in-place

Host side::

    axp verify agent-extension.json                     # against its own key (TOFU first use)
    axp verify agent-extension.json --pinned ed25519:…  # against the pinned key
    axp target agent-extension.json --runtime hermes --runtime posix
    axp canonicalize agent-extension.json > canonical.bin

Exit codes: 0 success, 1 validation/verification failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, jcs, manifest, signing


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


def _cmd_verify(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        ok = signing.verify_manifest(data, args.pinned)
    except signing.SigningError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print("signature OK" if ok else "signature INVALID")
    return 0 if ok else 1


def _cmd_target(args: argparse.Namespace) -> int:
    data = _load(args.manifest)
    try:
        target, runtime = manifest.select_target(
            data, runtimes=tuple(args.runtime), platform=args.platform,
        )
    except manifest.ManifestError as exc:
        print(f"axp: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"runtime": runtime, "target": target}, indent=2))
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
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("target", help="pick the target a host would install")
    p.add_argument("manifest")
    p.add_argument("--runtime", action="append", required=True,
                   help="host runtimes in preference order (repeatable; add posix last for the fallback)")
    p.add_argument("--platform", help="os/arch, default: this machine")
    p.set_defaults(func=_cmd_target)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
