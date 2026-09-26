"""Repository locators (SPEC 3.1 step 3): which document a host installs.

A GitHub-style repository is never the publisher's origin, so a host resolves
it to the manifest the repository *publishes* - most authoritative first -
and trusts only the signature. Pure functions plus an injected ``fetch`` so a
host reuses the walk with its own HTTP client (SSRF rules, size caps) and a
publisher previews the outcome with ``axp resolve`` before cutting a release.

Order for a bare repository URL:

1. ``releases/latest/download/agent-extension.json`` - the newest *stable*
   release (GitHub's ``latest`` skips pre-releases).
2. The release listing (``api.github.com/repos/<o>/<r>/releases``): the
   newest non-draft release carrying the asset, pre-releases included - what
   a repository on the ``beta`` channel publishes.
3. ``agent-extension.json`` on the default branch (``HEAD``) - a repository
   that has cut no release at all.

Only an absent document (:class:`Absent`: HTTP 404/410) moves the walk on.
Every other failure surfaces, so a flaky release URL never downgrades an
install to a mutable branch. An asset the listing advertises that cannot be
fetched, or whose version differs from its tag, is the publisher's error.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import manifest as _manifest
from . import updates, versions

MANIFEST_FILENAME = "agent-extension.json"
GIT_FORGE_HOSTS = ("github.com", "www.github.com")
GITHUB_API = "https://api.github.com"
RELEASE_LISTING_PAGE = 30
# How many listed releases (newest first) are fetched before giving up on a
# listing whose newest entries all sit on a channel the host does not track.
MAX_RELEASE_CANDIDATES = 5

# SPEC 3.1: a manifest is a small document; a listing of 30 releases is not.
MAX_MANIFEST_BYTES = 64 * 1024
MAX_LISTING_BYTES = 1024 * 1024

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

# Where a resolved document came from (``Resolution.source``).
SOURCE_RELEASE_LATEST = "release-latest"
SOURCE_RELEASE_LISTING = "release-listing"
SOURCE_REPOSITORY_HEAD = "repository-head"
SOURCE_PINNED = "pinned"


class RepositoryError(ValueError):
    """The repository publishes nothing a host may install. User-facing."""


class Absent(RepositoryError):
    """Raised by ``fetch`` for HTTP 404/410: the document does not exist and
    the walk may move on to the next candidate. Any other failure a
    ``fetch`` raises (as :class:`RepositoryError`) stops the walk."""


# ``fetch(url, max_bytes) -> bytes``; raises Absent / RepositoryError.
Fetch = Callable[[str, int], bytes]


# ---------------------------------------------------------------------------
# Locators
# ---------------------------------------------------------------------------

def release_listing_url(owner: str, repo: str) -> str:
    return f"{GITHUB_API}/repos/{owner}/{repo}/releases?per_page={RELEASE_LISTING_PAGE}"


def is_release_listing(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme, parsed.hostname) == ("https", "api.github.com") and parsed.path.endswith("/releases")


def manifest_candidates(url: str) -> list[str]:
    """The manifest URLs a repository locator publishes, most authoritative
    first; ``[]`` when ``url`` is not a repository locator (a host then
    fetches it as an ordinary manifest URL).

    ``…/tree/<ref>`` pins a branch or tag, ``…/blob/<ref>/agent-extension.json``
    that file, ``…/releases/tag/<tag>`` one release's asset and a full asset
    URL is honoured as given - the developer chose a document; no fallback.
    """
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in GIT_FORGE_HOSTS:
        return []
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return []
    owner, repo, rest = parts[0], parts[1], parts[2:]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not (_SEGMENT_RE.match(owner) and _SEGMENT_RE.match(repo)):
        return []
    if any(segment in (".", "..") for segment in (owner, repo, *rest)):
        return []
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}"
    defaults = [
        f"https://github.com/{owner}/{repo}/releases/latest/download/{MANIFEST_FILENAME}",
        release_listing_url(owner, repo),
        f"{raw}/HEAD/{MANIFEST_FILENAME}",
    ]
    if not rest:
        return defaults
    kind, args = rest[0], rest[1:]
    if kind == "tree" and args:
        return [f"{raw}/{'/'.join(args)}/{MANIFEST_FILENAME}"]
    if kind == "blob" and len(args) >= 2 and args[-1] == MANIFEST_FILENAME:
        return [f"{raw}/{'/'.join(args)}"]
    if kind == "releases":
        if args and args[-1] == MANIFEST_FILENAME:
            return [str(url)]
        if len(args) == 2 and args[0] == "tag":
            return [f"https://github.com/{owner}/{repo}/releases/download/{args[1]}/{MANIFEST_FILENAME}"]
        return defaults
    return []


def is_repository_locator(url: str) -> bool:
    return bool(manifest_candidates(url))


def _source_of(url: str) -> str:
    if is_release_listing(url):
        return SOURCE_RELEASE_LISTING
    if url.endswith(f"/releases/latest/download/{MANIFEST_FILENAME}"):
        return SOURCE_RELEASE_LATEST
    if re.match(rf"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/HEAD/{re.escape(MANIFEST_FILENAME)}$", url):
        return SOURCE_REPOSITORY_HEAD
    return SOURCE_PINNED


# ---------------------------------------------------------------------------
# Release listing (SPEC 7.1 ``github`` shape)
# ---------------------------------------------------------------------------

def release_version(tag: Any) -> str | None:
    """``v1.2.3`` -> ``1.2.3``; None for a tag that is not a version."""
    tag = str(tag or "").strip()
    if tag.startswith("v"):
        tag = tag[1:]
    return tag if versions.is_version(tag) else None


def parse_manifest(body: bytes, url: str) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RepositoryError(f"{url} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RepositoryError(f"{url} is not a JSON object")
    return data


def resolve_release_listing(
    releases: Any, tracked_channel: str | None, installed_version: str,
    fetch_manifest: Callable[[str], dict], *, max_candidates: int = MAX_RELEASE_CANDIDATES,
) -> tuple[dict, str] | None:
    """Walk a GitHub-shaped release listing newest-version-first and fetch
    the ``agent-extension.json`` asset of each release until one sits on an
    accepted channel. ``tracked_channel=None`` accepts every channel - the
    install path, where the newest release is the answer whatever channel it
    is on; the ``github`` update source passes the tracked channel and the
    installed version (SPEC 7.2, 7.4). Drafts, releases without the asset
    and tags that are not versions are skipped. Returns ``(manifest,
    asset_url)`` or None when no listed release qualifies.
    """
    if not isinstance(releases, list):
        raise RepositoryError("release listing is not a JSON array")
    candidates: list[tuple[Any, str, str]] = []
    for entry in releases:
        if not isinstance(entry, dict) or entry.get("draft"):
            continue
        version = release_version(entry.get("tag_name"))
        if version is None or not versions.is_newer(version, installed_version):
            continue
        asset_url = next(
            (
                str(asset.get("browser_download_url") or "")
                for asset in (entry.get("assets") or [])
                if isinstance(asset, dict) and asset.get("name") == MANIFEST_FILENAME
            ),
            "",
        )
        if asset_url.lower().startswith("https://"):
            candidates.append((versions.sort_key(version), version, asset_url))
    candidates.sort(reverse=True)
    for _key, advertised, asset_url in candidates[:max_candidates]:
        document = fetch_manifest(asset_url)
        served = str((document.get("identity") or {}).get("version") or "")
        if served != advertised:
            raise RepositoryError(
                f"release {advertised} served a manifest for {served!r}; refusing an inconsistent listing"
            )
        channel = str((document.get("release") or {}).get("channel") or updates.DEFAULT_CHANNEL)
        if tracked_channel is None or updates.channel_accepts(tracked_channel, channel):
            return document, asset_url
    return None


# ---------------------------------------------------------------------------
# The discovery walk
# ---------------------------------------------------------------------------

@dataclass
class Resolution:
    """What a host would install from a repository locator."""

    manifest: dict
    manifest_url: str
    source: str  # one of the SOURCE_* constants
    tried: list[dict] = field(default_factory=list)  # {"url": …, "outcome": …} in walk order


def _fetch_advertised(fetch: Fetch, asset_url: str) -> dict:
    try:
        body = fetch(asset_url, MAX_MANIFEST_BYTES)
    except RepositoryError as exc:
        # The listing advertised this asset: its absence is the publisher's
        # error, never a reason to install HEAD instead.
        raise RepositoryError(f"could not fetch the advertised release asset {asset_url}: {exc}") from exc
    return parse_manifest(body, asset_url)


def resolve(locator: str, fetch: Fetch) -> Resolution:
    """Resolve a repository locator to the manifest a host installs.

    ``fetch(url, max_bytes)`` returns the body, raises :class:`Absent` for a
    document that does not exist and :class:`RepositoryError` for anything
    else (timeouts, TLS, refused addresses, server errors). The result is a
    signed AXP manifest or a :class:`RepositoryError`; it is never a
    document the walk could not vouch for.
    """
    candidates = manifest_candidates(locator)
    if not candidates:
        raise RepositoryError(
            f"{locator} is not a repository locator (expected https://github.com/<owner>/<repo>"
            "[/tree/<ref> | /releases/tag/<tag>])"
        )
    tried: list[dict] = []
    for url in candidates:
        listing = is_release_listing(url)
        source = _source_of(url)
        try:
            body = fetch(url, MAX_LISTING_BYTES if listing else MAX_MANIFEST_BYTES)
        except Absent as exc:
            tried.append({"url": url, "outcome": f"absent: {exc}"})
            continue
        except RepositoryError as exc:
            raise RepositoryError(f"could not fetch authoritative repository manifest {url}: {exc}") from exc
        if listing:
            found = resolve_release_listing(
                parse_manifest_listing(body, url), None, "0.0.0", lambda u: _fetch_advertised(fetch, u),
            )
            if found is None:
                tried.append({"url": url, "outcome": f"lists no release carrying {MANIFEST_FILENAME}"})
                continue
            document, url = found
        else:
            document = parse_manifest(body, url)
        if not (_manifest.is_axp_manifest(document) and document.get("signature")):
            raise RepositoryError(
                f"the manifest at {url} is not a signed AXP manifest; a repository is never the "
                "publisher's origin, so only a signature can bind it to identity.publisher (SPEC 8) - refusing"
            )
        tried.append({"url": url, "outcome": "resolved"})
        return Resolution(document, url, source, tried)
    raise RepositoryError(
        f"{locator} publishes no {MANIFEST_FILENAME} - expected a release asset or a file at the "
        f"repository root (tried: {'; '.join(t['url'] + ' (' + t['outcome'] + ')' for t in tried)})"
    )


def parse_manifest_listing(body: bytes, url: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RepositoryError(f"release listing {url} is not valid JSON: {exc}") from exc


def resolve_update(locator: str, tracked_channel: str, installed_version: str, fetch: Fetch) -> tuple[dict, str] | None:
    """What the ``github`` update source (SPEC 7.1) would offer a host that
    has ``installed_version`` and tracks ``tracked_channel``: the newest
    strictly-higher release on an accepted channel, or None when the host is
    current. Reads only the release listing - the root file and ``latest``
    play no part in updates."""
    candidates = manifest_candidates(locator)
    listing_url = next((u for u in candidates if is_release_listing(u)), None)
    if listing_url is None:
        raise RepositoryError(f"{locator} pins one document; the github update source needs the bare repository URL")
    try:
        body = fetch(listing_url, MAX_LISTING_BYTES)
    except Absent:
        return None
    return resolve_release_listing(
        parse_manifest_listing(body, listing_url), tracked_channel, installed_version,
        lambda u: _fetch_advertised(fetch, u),
    )


# ---------------------------------------------------------------------------
# A plain HTTPS fetch for the CLI (hosts bring their own)
# ---------------------------------------------------------------------------

def http_fetch(url: str, max_bytes: int, *, timeout: float = 20.0) -> bytes:
    """stdlib HTTPS GET honouring the :data:`Fetch` contract. No SSRF
    rules - this is the publisher's workstation, not a host."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise RepositoryError(f"{url}: only https:// is fetched")
    from . import __version__

    request = urllib.request.Request(url, headers={
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1",
        "User-Agent": f"axp/{__version__}",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise Absent(f"{url} returned HTTP {exc.code}") from exc
        raise RepositoryError(f"{url} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RepositoryError(f"{url}: {exc}") from exc
    if len(body) > max_bytes:
        raise RepositoryError(f"{url} exceeds {max_bytes} bytes")
    return body
