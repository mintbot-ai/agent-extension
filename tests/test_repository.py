"""axp.repository — the SPEC 3.1 repository walk and ``axp resolve``."""

import json

import pytest

from axp import cli, repository, signing

REPO = "https://github.com/pub-example/my-ext"
LATEST = f"{REPO}/releases/latest/download/agent-extension.json"
LISTING = "https://api.github.com/repos/pub-example/my-ext/releases?per_page=30"
HEAD = "https://raw.githubusercontent.com/pub-example/my-ext/HEAD/agent-extension.json"


def asset_url(tag):
    return f"{REPO}/releases/download/{tag}/agent-extension.json"


@pytest.fixture(scope="module")
def keypair():
    pem = signing.generate_private_key_pem()
    return pem, signing.public_key_from_private(pem)


@pytest.fixture
def signed(example, keypair):
    """A signed copy of the example at a given version/channel, as bytes."""
    pem, pub = keypair

    def build(version="1.0.0", channel="stable", *, unsigned=False):
        data = json.loads(json.dumps(example))
        data["identity"]["version"] = version
        data["release"]["channel"] = channel
        data["signing"] = {"public_key": pub, "key_id": "test", "next_key": None}
        data.pop("signature", None)
        if unsigned:
            return json.dumps(data).encode()
        return json.dumps(signing.sign_manifest(data, pem)).encode()

    return build


def release(tag, *, draft=False, with_asset=True):
    entry = {"tag_name": tag, "draft": draft, "assets": []}
    if with_asset:
        entry["assets"].append({"name": "agent-extension.json", "browser_download_url": asset_url(tag)})
    return entry


def listing(*entries):
    return json.dumps(list(entries)).encode()


class FakeFetch:
    """A world of documents; anything else is Absent, a URL in ``broken`` errors."""

    def __init__(self, documents, broken=()):
        self.documents, self.broken, self.calls = documents, set(broken), []

    def __call__(self, url, max_bytes):
        self.calls.append(url)
        if url in self.broken:
            raise repository.RepositoryError(f"{url} returned HTTP 503")
        if url not in self.documents:
            raise repository.Absent(f"{url} returned HTTP 404")
        return self.documents[url]


# --- locators ---------------------------------------------------------------

def test_bare_repository_walks_latest_then_listing_then_head():
    assert repository.manifest_candidates(REPO) == [LATEST, LISTING, HEAD]
    assert repository.manifest_candidates(REPO + ".git") == [LATEST, LISTING, HEAD]
    assert repository.manifest_candidates(REPO + "/releases") == [LATEST, LISTING, HEAD]


def test_pinned_locators_name_one_document():
    assert repository.manifest_candidates(f"{REPO}/tree/v1.2.0") == [
        "https://raw.githubusercontent.com/pub-example/my-ext/v1.2.0/agent-extension.json"]
    assert repository.manifest_candidates(f"{REPO}/blob/main/agent-extension.json") == [
        "https://raw.githubusercontent.com/pub-example/my-ext/main/agent-extension.json"]
    assert repository.manifest_candidates(f"{REPO}/releases/tag/v1.2.0") == [asset_url("v1.2.0")]
    assert repository.manifest_candidates(asset_url("v1.2.0")) == [asset_url("v1.2.0")]


@pytest.mark.parametrize("url", [
    "https://example.com/agent-extension.json", "http://github.com/a/b", "https://github.com/onlyowner",
    f"{REPO}/issues/1", "https://github.com/../b", "https://github.com/a/b/tree",
    f"{REPO}/blob/main/other.json",
])
def test_non_repository_locators_yield_nothing(url):
    assert repository.manifest_candidates(url) == []
    assert not repository.is_repository_locator(url)


# --- the walk ---------------------------------------------------------------

def test_latest_release_wins_when_present(signed):
    fetch = FakeFetch({LATEST: signed("2.0.0"), HEAD: signed("9.9.9")})
    got = repository.resolve(REPO, fetch)
    assert (got.source, got.manifest_url) == (repository.SOURCE_RELEASE_LATEST, LATEST)
    assert got.manifest["identity"]["version"] == "2.0.0"
    assert fetch.calls == [LATEST]


def test_prerelease_only_repository_resolves_through_the_listing(signed):
    fetch = FakeFetch({
        LISTING: listing(release("v0.1.1"), release("v0.1.0")),
        asset_url("v0.1.1"): signed("0.1.1", "beta"),
        HEAD: signed("0.0.1"),
    })
    got = repository.resolve(REPO, fetch)
    assert (got.source, got.manifest_url) == (repository.SOURCE_RELEASE_LISTING, asset_url("v0.1.1"))
    assert got.manifest["release"]["channel"] == "beta"
    assert [t["outcome"] for t in got.tried] == ["absent: " + LATEST + " returned HTTP 404", "resolved"]
    assert HEAD not in fetch.calls


def test_listing_is_walked_newest_version_first_skipping_drafts_and_bare_releases(signed):
    fetch = FakeFetch({
        LISTING: listing(release("v1.0.0"), release("v3.0.0", draft=True), release("v2.5.0", with_asset=False),
                         release("not-a-version"), release("v2.0.0")),
        asset_url("v1.0.0"): signed("1.0.0"), asset_url("v2.0.0"): signed("2.0.0"),
    })
    assert repository.resolve(REPO, fetch).manifest["identity"]["version"] == "2.0.0"


def test_repository_without_releases_falls_back_to_head(signed):
    fetch = FakeFetch({LISTING: listing(), HEAD: signed("0.3.0")})
    got = repository.resolve(REPO, fetch)
    assert (got.source, got.manifest_url) == (repository.SOURCE_REPOSITORY_HEAD, HEAD)
    assert "lists no release" in got.tried[1]["outcome"]


def test_repository_publishing_nothing_is_a_typed_error():
    """The one outcome a host may answer with another path (an unmanaged
    install) is distinguishable from every other failure."""
    with pytest.raises(repository.NoManifest, match="publishes no agent-extension.json"):
        repository.resolve(REPO, FakeFetch({}))
    assert issubclass(repository.NoManifest, repository.RepositoryError)


def test_fetch_error_never_downgrades_to_a_lower_candidate(signed):
    fetch = FakeFetch({HEAD: signed("1.0.0")}, broken=[LATEST])
    with pytest.raises(repository.RepositoryError, match="could not fetch authoritative"):
        repository.resolve(REPO, fetch)
    assert fetch.calls == [LATEST]


def test_advertised_asset_that_cannot_be_fetched_is_the_publishers_error(signed):
    fetch = FakeFetch({LISTING: listing(release("v1.0.0")), HEAD: signed("1.0.0")})
    with pytest.raises(repository.RepositoryError, match="authoritative repository manifest .* advertised by the release listing"):
        repository.resolve(REPO, fetch)


def test_release_whose_manifest_version_differs_from_its_tag_is_refused(signed):
    fetch = FakeFetch({LISTING: listing(release("v1.0.0")), asset_url("v1.0.0"): signed("1.0.1")})
    with pytest.raises(repository.RepositoryError, match="inconsistent listing"):
        repository.resolve(REPO, fetch)


def test_unsigned_document_from_a_repository_is_refused(signed):
    with pytest.raises(repository.Unsigned, match="not a signed AXP manifest"):
        repository.resolve(REPO, FakeFetch({LATEST: signed(unsigned=True)}))
    with pytest.raises(repository.Unsigned, match="not a signed AXP manifest"):
        repository.resolve(REPO, FakeFetch({LATEST: b'{"hello": 1}'}))
    assert issubclass(repository.Unsigned, repository.RepositoryError)


def test_resolution_carries_the_exact_bytes_and_honours_a_host_parse_hook(signed):
    """A host that validates and flattens manifests its own way plugs that in
    as ``parse``; the walk's own checks keep reading the document as
    published, so a reshaped result never breaks them."""
    body = signed("1.0.0")
    seen = []

    def parse(raw, url):
        seen.append((raw, url))
        return {"flat_version": json.loads(raw)["identity"]["version"]}

    got = repository.resolve(REPO, FakeFetch({LATEST: body}), parse=parse)
    assert got.body == body and got.manifest == {"flat_version": "1.0.0"}
    assert seen == [(body, LATEST)]

    beta = signed("2.0.0", "beta")
    fetch = FakeFetch({asset_url("v2.0.0"): beta})
    got = repository.resolve_release_listing([release("v2.0.0")], "beta", "1.0.0", fetch, parse=parse)
    assert (got.source, got.manifest_url, got.body) == (repository.SOURCE_RELEASE_LISTING, asset_url("v2.0.0"), beta)
    assert got.manifest == {"flat_version": "2.0.0"}
    assert repository.resolve_release_listing([release("v2.0.0")], "stable", "1.0.0", fetch, parse=parse) is None


def test_pinned_locator_has_no_fallback(signed):
    with pytest.raises(repository.RepositoryError, match="publishes no"):
        repository.resolve(f"{REPO}/releases/tag/v9.0.0", FakeFetch({LATEST: signed("1.0.0")}))


def test_non_repository_locator_is_rejected_up_front():
    with pytest.raises(repository.RepositoryError, match="not a repository locator"):
        repository.resolve("https://example.com/agent-extension.json", FakeFetch({}))


# --- the github update source ----------------------------------------------

def test_update_offers_only_newer_releases_on_an_accepted_channel(signed):
    fetch = FakeFetch({
        LISTING: listing(release("v1.2.0"), release("v1.1.0"), release("v1.0.0")),
        asset_url("v1.2.0"): signed("1.2.0", "beta"), asset_url("v1.1.0"): signed("1.1.0", "stable"),
        asset_url("v1.0.0"): signed("1.0.0"),
    })
    stable = repository.resolve_update(REPO, "stable", "1.0.0", fetch)
    assert stable.manifest["identity"]["version"] == "1.1.0"
    beta = repository.resolve_update(REPO, "beta", "1.0.0", fetch)
    assert beta.manifest["identity"]["version"] == "1.2.0"
    assert repository.resolve_update(REPO, "beta", "1.2.0", fetch) is None
    assert repository.resolve_update(REPO, "stable", "1.1.0", fetch) is None


def test_update_reads_only_the_listing(signed):
    fetch = FakeFetch({LATEST: signed("5.0.0"), HEAD: signed("6.0.0")})
    assert repository.resolve_update(REPO, "stable", "1.0.0", fetch) is None
    assert fetch.calls == [LISTING]
    with pytest.raises(repository.RepositoryError, match="pins one document"):
        repository.resolve_update(f"{REPO}/tree/main", "stable", "1.0.0", fetch)


# --- axp resolve ------------------------------------------------------------

def _report(capsys):
    return json.loads(capsys.readouterr().out)


def test_resolve_cli_reports_source_signature_and_key_directory(tmp_path, signed, keypair, monkeypatch, capsys, example):
    publisher = example["identity"]["publisher"]
    fetch = FakeFetch({
        LISTING: listing(release("v0.2.0"), release("v0.1.0")),
        asset_url("v0.2.0"): signed("0.2.0", "beta"), asset_url("v0.1.0"): signed("0.1.0", "stable"),
        signing.key_directory_url(publisher): json.dumps(
            {"publisher": publisher, "keys": [{"public_key": keypair[1], "key_id": "test"}]}).encode(),
    })
    monkeypatch.setattr(repository, "http_fetch", fetch)
    out = tmp_path / "resolved.json"

    assert cli.main(["resolve", REPO, "-o", str(out)]) == 0
    report = _report(capsys)
    assert report["source"] == "release-listing"
    assert report["manifest_url"] == asset_url("v0.2.0")
    assert (report["version"], report["channel"]) == ("0.2.0", "beta")
    assert report["signature_valid"] is True
    assert report["key_listed"] is True
    assert report["key_directory"] == signing.key_directory_url(publisher)
    assert report["problems"] == []
    assert json.loads(out.read_text())["identity"]["version"] == "0.2.0"

    # A host on 0.1.0 tracking stable is current; one tracking beta gets 0.2.0.
    assert cli.main(["resolve", REPO, "--no-keydir", "--installed", "0.1.0", "--tracked", "stable"]) == 0
    assert _report(capsys)["update"]["candidate"] is None
    assert cli.main(["resolve", REPO, "--no-keydir", "--installed", "0.1.0"]) == 0
    update = _report(capsys)["update"]
    assert (update["tracked"], update["candidate"], update["manifest_url"]) == ("beta", "0.2.0", asset_url("v0.2.0"))


def test_resolve_cli_flags_an_unlisted_key_and_a_foreign_pin(tmp_path, signed, monkeypatch, capsys, example):
    publisher = example["identity"]["publisher"]
    other = signing.public_key_from_private(signing.generate_private_key_pem())
    monkeypatch.setattr(repository, "http_fetch", FakeFetch({LATEST: signed("1.0.0")}))
    keydir = tmp_path / "keys.json"
    keydir.write_text(json.dumps({"publisher": publisher, "keys": [{"public_key": other, "key_id": "x"}]}))

    assert cli.main(["resolve", REPO, "--keydir", str(keydir)]) == 1
    report = _report(capsys)
    assert report["signature_valid"] is True and report["key_listed"] is False
    assert any("is not listed in" in p for p in report["problems"])

    assert cli.main(["resolve", REPO, "--no-keydir", "--pinned", other]) == 1
    report = _report(capsys)
    assert report["signature_valid"] is False
    assert any("pinned key" in p for p in report["problems"])

    # An unreachable well-known directory is a problem, not a crash.
    assert cli.main(["resolve", REPO]) == 1
    assert any("key directory" in p for p in _report(capsys)["problems"])


def test_resolve_cli_fails_cleanly_when_nothing_is_published(monkeypatch, capsys):
    monkeypatch.setattr(repository, "http_fetch", FakeFetch({}))
    assert cli.main(["resolve", REPO]) == 1
    assert "publishes no agent-extension.json" in capsys.readouterr().err
    assert cli.main(["resolve", "https://example.com/x"]) == 1
    assert "not a repository locator" in capsys.readouterr().err
