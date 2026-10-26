"""Conservative local package policy shared by check and pack. Never extracts."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import gzip
import io
import re
import stat
import tarfile
import zipfile

MAX_FILES = 10000
MAX_BYTES = 128 * 1024 * 1024


class UnsafePackage(ValueError):
    pass


def safe_name(name: str) -> str:
    name = name.rstrip("/")
    parts = name.split("/")
    if (not name or name.startswith("/") or "\\" in name or ":" in name
            or any(part in ("", ".", "..") for part in parts)
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise UnsafePackage(f"Unsafe package path: {name!r}")
    return name


def check_secret(name: str, content: bytes = b"") -> None:
    path = PurePosixPath(name.lower())
    if (any(part in (".git", ".ssh", ".aws", ".gnupg", "__pycache__") for part in path.parts)
            or path.name == ".env" or path.name.startswith(".env.")
            or path.suffix in (".key", ".pem", ".p12", ".pfx")
            or path.name in ("id_rsa", "id_ed25519", "credentials", "axp.toml")
            or re.search(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", content)):
        raise UnsafePackage(f"Potential secret or local-only file must not be packaged: {name}")


def archive_files(path) -> dict[str, bytes]:
    """Bounded inspection of regular files, rejecting links, specials and aliases."""
    seen = set()
    files = {}
    total = 0

    def accept(name, size):
        nonlocal total
        name = safe_name(name)
        if name in seen:
            raise UnsafePackage(f"Duplicate archive path: {name}")
        seen.add(name)
        total += size
        if len(seen) > MAX_FILES or total > MAX_BYTES or size < 0:
            raise UnsafePackage("Archive exceeds inspection limits (10000 entries / 128 MiB).")
        check_secret(name)
        return name

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                name = accept(item.filename, item.file_size)
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or item.flag_bits & 1:
                    raise UnsafePackage(f"Links, special or encrypted entries are not allowed: {name}")
                if not item.is_dir():
                    content = archive.read(item)
                    check_secret(name, content)
                    files[name] = content
    else:
        with tarfile.open(path, "r:gz") as archive:
            for item in archive:
                name = accept(item.name, item.size)
                if not (item.isfile() or item.isdir()):
                    raise UnsafePackage(f"Links and special entries are not allowed: {name}")
                if item.isfile():
                    extracted = archive.extractfile(item)
                    assert extracted is not None  # regular member, never a link
                    with extracted as handle:
                        content = handle.read(MAX_BYTES + 1)
                    check_secret(name, content)
                    files[name] = content
    for name in seen:
        if any(str(parent) in files for parent in PurePosixPath(name).parents):
            raise UnsafePackage(f"Archive file ancestor must be a directory: {name}")
    return files


def pack(root: Path, names: list[str], output: Path, *, force: bool = False,
         signing_key: Path | None = None) -> list[str]:
    """Pack an explicit allowlist only. Inspect everything before opening output."""
    if not names:
        raise UnsafePackage("No files selected. Set project.files or repeat --file PATH.")
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise UnsafePackage("Refusing symlink output or output directory.")
    if output.exists() and (not output.is_file() or output.stat().st_nlink > 1):
        raise UnsafePackage("Output must be a regular, non-hardlinked file.")
    if signing_key and (output.resolve() == signing_key.resolve()
                        or (output.exists() and signing_key.exists() and output.samefile(signing_key))):
        raise UnsafePackage("Output must never overwrite the configured signing key.")
    if output.exists() and not force:
        raise UnsafePackage(f"{output} already exists (use --force to overwrite)")
    selected = {}
    total = 0
    for name in names:
        safe_name(name)
        source = root / name
        if any(p.is_symlink() for p in (source, *source.parents)):
            raise UnsafePackage(f"Refusing symlink input: {name}")
        if not source.exists():
            raise UnsafePackage(f"Package input is missing: {name}")
        for path in ([source, *source.rglob("*")] if source.is_dir() else [source]):
            relative = path.relative_to(root).as_posix()
            safe_name(relative)
            if path.is_symlink():
                raise UnsafePackage(f"Refusing symlink input: {relative}")
            if path.resolve() == output.resolve():
                raise UnsafePackage("Output cannot also be a package input.")
            if signing_key and (path.resolve() == signing_key.resolve()
                                or (signing_key.exists() and path.samefile(signing_key))):
                raise UnsafePackage("The configured signing key must never be packaged.")
            if path.is_dir():
                continue
            if not path.is_file() or path.stat().st_nlink > 1:
                raise UnsafePackage(f"Only regular, non-hardlinked files may be packaged: {relative}")
            total += path.stat().st_size
            if total > MAX_BYTES or len(selected) >= MAX_FILES:
                raise UnsafePackage("Package exceeds limits (10000 files / 128 MiB).")
            with path.open("rb") as handle:
                content = handle.read(MAX_BYTES + 1)
            if len(content) > MAX_BYTES:
                raise UnsafePackage("Package file exceeds size limit.")
            check_secret(relative, content)
            selected[relative] = (content, path.stat().st_mode & 0o777)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Canonical metadata and gzip timestamp: repeated packs of identical files match.
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, (content, mode) in sorted(selected.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(content), mode
                archive.addfile(item, io.BytesIO(content))
    with output.open("wb" if force else "xb") as handle:
        handle.write(buffer.getvalue())
    return sorted(selected)
