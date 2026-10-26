"""Small, dependency-free POSIX examples; never run during init/check/pack."""
from __future__ import annotations

import json
from pathlib import Path

from . import manifest, publish

KINDS = ("skill", "cli", "mcp", "service")

_LIFECYCLE = '''#!/usr/bin/env python3
"""Local example lifecycle. State is preserved; no daemon is started."""
import os
from pathlib import Path
import shutil
import sys

source = Path(__file__).resolve().parent / "payload"
prefix = Path(os.environ.get("AXP_PREFIX", str(Path.home() / ".local/share/axp/NAME")))
files = [p for p in source.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
action = sys.argv[1]
destinations = [(src, prefix / "payload" / src.relative_to(source)) for src in files]
# Validate the entire destination set before changing anything, including prefix ancestors.
for src, dest in destinations:
    if (any(p.is_symlink() for p in (dest, *dest.parents))
            or any(p.exists() and not p.is_dir() for p in dest.parents)
            or (dest.exists() and (not dest.is_file() or dest.stat().st_nlink > 1))):
        sys.exit("Unsafe installed destination; use regular, non-linked paths: " + str(dest))
for src, dest in destinations:
    if action == "install":
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    elif action == "uninstall":
        dest.unlink(missing_ok=True)
    elif action == "health" and not dest.is_file():
        sys.exit("Missing installed component: " + str(dest))
print(action + " OK (local files only; service processes are managed separately)")
'''

_CLI = '''#!/usr/bin/env python3
import argparse
parser = argparse.ArgumentParser(description="A local greeting tool")
parser.add_argument("name", nargs="?", default="world")
args = parser.parse_args()
print("Hello, " + args.name + "!")
'''

_MCP = '''#!/usr/bin/env python3
"""Minimal newline-delimited JSON-RPC stdio MCP greeting server."""
import argparse
import json
import sys
argparse.ArgumentParser(description=__doc__).parse_args()
for line in sys.stdin:
    try:
        request = json.loads(line)
        if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)):
            print(json.dumps({"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                              "error": {"code": -32600, "message": "Invalid request object"}}), flush=True)
            continue
        if "id" not in request:
            continue
        if not isinstance(request.get("params", {}), dict):
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32602, "message": "Params must be an object"}}), flush=True)
            continue
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "hello", "version": "0.1.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": "hello", "description": "Say hello",
                       "inputSchema": {"type": "object", "properties": {}}}]}
        elif method == "tools/call" and request.get("params", {}).get("name") == "hello":
            result = {"content": [{"type": "text", "text": "Hello, world!"}]}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32601, "message": "Unknown method or tool"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
    except (ValueError, TypeError, KeyError):
        print(json.dumps({"jsonrpc": "2.0", "id": None,
                          "error": {"code": -32700, "message": "Invalid request"}}), flush=True)
'''

_SERVICE = '''#!/usr/bin/env python3
"""Foreground loopback-only example. Stop with Ctrl-C; no daemon install."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", type=int, default=8765)
args = parser.parse_args()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}\\n'
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = HTTPServer(("127.0.0.1", args.port), Handler)
print("Listening on 127.0.0.1:" + str(server.server_port), flush=True)
server.serve_forever()
'''


def files(data: dict, kind: str) -> dict[str, str]:
    """Complete template file set; modifies only core manifest fields."""
    name = data["identity"]["name"]
    component = {"name": name}
    if kind == "skill":
        component["path"] = "payload/SKILL.md"
        data["provides"] = {"skills": [component]}
        payload = {"payload/SKILL.md": f"---\nname: {name}\ndescription: Say hello when asked for a greeting.\n---\n\nRespond with a friendly hello.\n"}
    else:
        component["command"] = "python3"
        component["args"] = ["payload/main.py"]
        if kind == "mcp":
            component["transport"] = "stdio"
        if kind == "service":
            component.update(kind="daemon", endpoint="http://127.0.0.1:8765")
            data["permissions"]["network_ingress"] = ["127.0.0.1:8765/tcp"]
        data["provides"] = { {"cli": "tools", "mcp": "mcp_servers", "service": "services"}[kind]: [component] }
        payload = {"payload/main.py": {"cli": _CLI, "mcp": _MCP, "service": _SERVICE}[kind]}
    data["requires"] = {"commands": ["python3", "sh"]}
    data["permissions"]["filesystem"] = ["prefix:rw", "state:rw"]
    result = {"lifecycle.py": _LIFECYCLE.replace("NAME", name), **payload}
    for filename, action in (("install.sh", "install"), ("uninstall.sh", "uninstall"), ("healthcheck.sh", "health")):
        result[filename] = '#!/bin/sh\nset -eu\nexec python3 "$(dirname "$0")/lifecycle.py" ' + action + '\n'
    result["axp.toml"] = ('# Local tooling only; not part of the AXP manifest. No shell commands.\n'
                          '[project]\nartifact = "dist/package.tar.gz"\n'
                          '# signing_key = "../signing.key" # PATH to a PEM, never key material\n'
                          'files = ["install.sh", "uninstall.sh", "healthcheck.sh", "lifecycle.py", "payload"]\n')
    result["README.md"] = (f"# {name}: {kind} example\n\nRequires Python 3 and a POSIX shell.\n\n"
                           "Run `sh install.sh`, then `sh healthcheck.sh`; `sh uninstall.sh` removes only the example files.\n"
                           f"Default prefix: `~/.local/share/axp/{name}`; override with `AXP_PREFIX`. State is preserved.\n"
                           "For executable examples run `python3 payload/main.py` from the prefix (or source directory).\n"
                           "The service runs in the foreground, loopback port 8765; it is not automatically started.\n"
                           "Health checks installed files, not process liveness. No host-specific registration is performed.\n\n"
                           "Local release: `axp check`, `axp pack`, `axp keygen --out ../signing.key`,\n"
                           "`axp release agent-extension.json --key ../signing.key`, `axp check`.\n"
                           "Review permissions and URLs before uploading anything. These commands never publish.\n")
    manifest.validate(data)
    result["agent-extension.json"] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return result


def write(root: Path, content: dict[str, str], *, force: bool = False) -> None:
    for name in content:
        path = root / name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise publish.PublishError(f"refusing symlink destination: {path}")
        if path.exists() and (not path.is_file() or path.stat().st_nlink > 1):
            raise publish.PublishError(f"destination must be a regular, non-hardlinked file: {path}")
        if any(p.exists() and not p.is_dir() for p in path.parents):
            raise publish.PublishError(f"destination parent is not a directory: {path}")
        if path.exists() and not force:
            raise publish.PublishError(f"{path} already exists (use --force to overwrite)")
    root.mkdir(parents=True, exist_ok=True)
    for name, text in content.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if path.suffix == ".sh":
            path.chmod(0o755)
