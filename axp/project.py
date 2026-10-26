"""Local axp.toml defaults. No command expansion or build/publish hooks."""
from __future__ import annotations

from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .publish import PublishError


def load(manifest_path: str, config_path: str | None = None) -> tuple[Path, dict]:
    path = Path(config_path) if config_path else Path(manifest_path).parent / "axp.toml"
    root = path.absolute().parent
    if not path.exists() and config_path is None:
        return root, {}
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PublishError(f"Cannot read axp.toml: {exc}") from exc
    if set(document) - {"project"}:
        raise PublishError("axp.toml supports only [project]; shell/build/publish hooks are not supported")
    config = document.get("project", {})
    if not isinstance(config, dict) or set(config) - {"artifact", "signing_key", "files"}:
        raise PublishError("[project] accepts only artifact, signing_key (paths) and files (explicit file/directory list)")
    for key in ("artifact", "signing_key"):
        if key in config and (not isinstance(config[key], str) or not config[key].strip()
                              or any(ord(c) < 32 for c in config[key]) or "-----BEGIN" in config[key]):
            raise PublishError(f"project.{key} must be a non-empty local PATH, never key material")
    if "files" in config and (not isinstance(config["files"], list) or not config["files"]
                              or not all(isinstance(x, str) and x for x in config["files"])):
        raise PublishError("project.files must be a non-empty list of explicit relative paths")
    return root, config


def path_default(root: Path, config: dict, key: str) -> str:
    value = config.get(key)
    return str(root / Path(value).expanduser()) if value else ""
