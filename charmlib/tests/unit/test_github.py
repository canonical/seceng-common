# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Unit tests for the GitHub release asset client."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import tempfile
import typing
import urllib.error
import urllib.request

import pytest

from charmlibs.seceng.github import (
    GitHubAuthError,
    GitHubChecksumError,
    GitHubClient,
    GitHubError,
    GitHubNetworkError,
    GitHubNotFoundError,
    Token,
)

_REPO = 'canonical/seceng-common'
_TAG = '1.2.3'
_ASSET = 'wheelhouse.tar.gz'
_ASSET_URL = 'https://api.github.com/repos/canonical/seceng-common/releases/assets/42'
_PAYLOAD = b'wheelhouse payload bytes'
_PAYLOAD_SHA256 = hashlib.sha256(_PAYLOAD).hexdigest()
_TOKEN = 'ghp_secretTokenValue123'


class _FakeResponse:
    """Stand-in for the file-like object urlopen returns."""

    def __init__(self, data: bytes):
        self._stream = io.BytesIO(data)

    def read(self, amt: int | None = None) -> bytes:
        return self._stream.read(amt if amt is not None else -1)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class _TruncatedResponse:
    """A response that yields one chunk and then fails, as a dropped connection does."""

    def __init__(self) -> None:
        self._served = False

    def read(self, amt: int | None = None) -> bytes:
        if self._served:
            raise OSError('connection reset by peer')
        self._served = True
        return b'partial'

    def __enter__(self) -> _TruncatedResponse:
        return self

    def __exit__(self, *args: object) -> None:
        pass


def _release_json(asset_name: str = _ASSET, asset_url: str = _ASSET_URL) -> bytes:
    return json.dumps({'assets': [{'name': asset_name, 'url': asset_url}]}).encode('utf-8')


def _fake_github(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lookup: bytes | Exception | None = None,
    download: bytes | Exception | None = None,
) -> list[urllib.request.Request]:
    """Route the release lookup and the asset download to canned outcomes.

    Returns the list the requests are recorded into, in call order.
    """
    lookup_result: bytes | Exception = _release_json() if lookup is None else lookup
    download_result: bytes | Exception = _PAYLOAD if download is None else download
    recorded: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> _FakeResponse:
        recorded.append(request)
        result = lookup_result if '/releases/tags/' in request.full_url else download_result
        if isinstance(result, Exception):
            raise result
        return _FakeResponse(result)

    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)
    return recorded


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(_ASSET_URL, code, 'boom', hdrs=None, fp=None)  # type: ignore[arg-type]


def _fetch(
    repo: str = _REPO,
    tag: str = _TAG,
    asset_name: str = _ASSET,
    *,
    expected_sha256: str | None = None,
) -> None:
    """Run a fetch to completion and discard the artifact.

    Nothing is retrieved until the context is entered, so a test that expects a
    failure has to enter the context to provoke it.
    """
    with GitHubClient(_TOKEN).fetch_release_asset(repo, tag, asset_name, expected_sha256=expected_sha256):
        pass


@pytest.fixture
def temp_root(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> pathlib.Path:
    """Redirect the platform temporary directory to a test-isolated path."""
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    return tmp_path


# ============================================================================
# Token
# ============================================================================


def test_token_accepts_printable_ascii() -> None:
    assert Token('ghp_abc123-_.~') == 'ghp_abc123-_.~'
    # Idempotent, so a client can normalise without caring what it was given.
    assert Token(Token(_TOKEN)) == _TOKEN


@pytest.mark.parametrize(
    'invalid',
    [
        '',
        'has space',
        'trailing ',
        'with\ttab',
        'with\nnewline: X-Injected',
        'with\rcarriage',
        'nul\x00byte',
        'caf\xe9',
        '\x7f',
    ],
)
def test_token_rejects_header_injection_vectors(invalid: str) -> None:
    with pytest.raises(ValueError, match='github token must'):
        Token(invalid)


def test_token_repr_is_redacted_but_str_is_not() -> None:
    token = Token(_TOKEN)

    assert repr(token) == '<Token [REDACTED]>'
    assert _TOKEN not in repr([token])
    assert _TOKEN not in f'{token!r}'
    # str must still yield the credential; the Authorization header needs it.
    assert str(token) == _TOKEN


def test_client_rejects_an_invalid_token_at_construction() -> None:
    with pytest.raises(ValueError, match='github token must not be empty'):
        GitHubClient('')


# ============================================================================
# Request shape
# ============================================================================


def test_fetch_release_asset_keeps_the_credential_off_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _fake_github(monkeypatch)

    _fetch()

    assert len(recorded) == 2
    for request in recorded:
        # urllib replays request.headers to a redirect target but never
        # unredirected_hdrs, which is where the bearer token has to live.
        assert request.unredirected_hdrs['Authorization'] == f'Bearer {_TOKEN}'
        assert 'Authorization' not in request.headers


def test_fetch_release_asset_sends_the_expected_api_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _fake_github(monkeypatch)

    _fetch()

    lookup, download = recorded
    # urllib capitalises header names as it stores them.
    assert lookup.headers['User-agent'] == 'canonical-seceng-workload'
    assert lookup.headers['X-github-api-version'] == '2022-11-28'
    assert lookup.headers['Accept'] == 'application/vnd.github+json'
    assert lookup.full_url == f'https://api.github.com/repos/canonical/seceng-common/releases/tags/{_TAG}'
    assert download.headers['Accept'] == 'application/octet-stream'
    assert download.full_url == _ASSET_URL


def test_fetch_release_asset_percent_encodes_url_segments(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _fake_github(monkeypatch)

    _fetch('org name/repo?x', 'v1.0/rc 1#f')

    expected = 'https://api.github.com/repos/org%20name/repo%3Fx/releases/tags/v1.0%2Frc%201%23f'
    assert recorded[0].full_url == expected


@pytest.mark.parametrize(
    ('repo', 'tag', 'message'),
    [
        (_REPO, '..', 'release tag must not be a relative path segment'),
        (_REPO, '.', 'release tag must not be a relative path segment'),
        (_REPO, '', 'release tag must not be empty'),
        ('../evil', _TAG, 'repository owner must not be a relative path segment'),
        ('canonical/..', _TAG, 'repository name must not be a relative path segment'),
        ('no-slash', _TAG, 'repository name must not be empty'),
        ('/repo', _TAG, 'repository owner must not be empty'),
    ],
)
def test_fetch_release_asset_rejects_path_traversal_segments(
    monkeypatch: pytest.MonkeyPatch, repo: str, tag: str, message: str
) -> None:
    """Percent-encoding leaves '.' and '..' intact, so they must be refused outright."""
    recorded = _fake_github(monkeypatch)

    with pytest.raises(ValueError, match=message):
        _fetch(repo, tag)

    assert recorded == []


# ============================================================================
# Download and temporary file lifetime
# ============================================================================


def test_fetch_release_asset_retrieves_nothing_until_the_context_is_entered(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    """Forgetting the with cannot strand an artifact, because it downloads nothing."""
    recorded = _fake_github(monkeypatch)

    unentered = GitHubClient(_TOKEN).fetch_release_asset(_REPO, _TAG, _ASSET)

    assert recorded == []
    assert list(temp_root.iterdir()) == []

    with unentered as artifact:
        assert artifact.read_bytes() == _PAYLOAD
    assert len(recorded) == 2


def test_fetch_release_asset_yields_a_readable_path_and_deletes_it_on_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_github(monkeypatch)

    with GitHubClient(_TOKEN).fetch_release_asset(_REPO, _TAG, _ASSET) as artifact:
        # Read by name, as a consumer taking a path does: the whole payload has
        # to be on disk, not sitting in the writer's buffer.
        assert artifact.read_bytes() == _PAYLOAD
        escaped = artifact

    # A path that outlives the block names nothing, so misuse fails loudly.
    assert not escaped.exists()


def test_fetch_release_asset_places_the_artifact_in_the_platform_temporary_directory(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    """Placement follows gettempdir(), so TMPDIR picks the filesystem."""
    _fake_github(monkeypatch)

    with GitHubClient(_TOKEN).fetch_release_asset(_REPO, _TAG, _ASSET) as artifact:
        assert artifact.parent == temp_root

    assert list(temp_root.iterdir()) == []


def test_fetch_release_asset_streams_a_payload_larger_than_one_chunk(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = bytes(range(256)) * 1024  # 256 KiB, four 64 KiB reads
    _fake_github(monkeypatch, download=payload)

    with GitHubClient(_TOKEN).fetch_release_asset(
        _REPO, _TAG, _ASSET, expected_sha256=hashlib.sha256(payload).hexdigest()
    ) as artifact:
        assert artifact.read_bytes() == payload


# ============================================================================
# Checksum verification
# ============================================================================


def test_fetch_release_asset_accepts_a_matching_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch)

    with GitHubClient(_TOKEN).fetch_release_asset(
        _REPO, _TAG, _ASSET, expected_sha256=f'  {_PAYLOAD_SHA256.upper()}\n'
    ) as artifact:
        assert artifact.read_bytes() == _PAYLOAD


def test_fetch_release_asset_discards_a_payload_with_the_wrong_digest(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    _fake_github(monkeypatch)

    with pytest.raises(GitHubChecksumError, match='sha256 mismatch'):
        _fetch(expected_sha256='e' * 64)

    # No unverified payload is left behind for a caller to pick up.
    assert list(temp_root.iterdir()) == []


@pytest.mark.parametrize('malformed', ['', '   ', 'abc', _PAYLOAD_SHA256[:-1], _PAYLOAD_SHA256 + 'a', 'SHA256\ufffd'])
def test_fetch_release_asset_treats_a_malformed_expected_digest_as_a_mismatch(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path, malformed: str
) -> None:
    """A truncated, mistyped, or undecodable digest fails closed, never with a TypeError."""
    _fake_github(monkeypatch)

    with pytest.raises(GitHubChecksumError, match='sha256 mismatch'):
        _fetch(expected_sha256=malformed)

    assert list(temp_root.iterdir()) == []


# ============================================================================
# Failure translation
# ============================================================================


def test_fetch_release_asset_reports_a_rejected_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=_http_error(401))

    with pytest.raises(GitHubAuthError, match='github rejected the token') as raised:
        _fetch()

    assert _TOKEN not in str(raised.value)


def test_fetch_release_asset_reports_a_missing_release(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=_http_error(404))

    with pytest.raises(GitHubNotFoundError, match="github returned 404 for release '1.2.3'"):
        _fetch()


def test_fetch_release_asset_reports_an_unexpected_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=_http_error(500))

    with pytest.raises(GitHubError, match='github returned http 500') as raised:
        _fetch()

    assert not isinstance(raised.value, GitHubNotFoundError | GitHubAuthError)


def test_fetch_release_asset_reports_a_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=OSError('connection reset'))

    with pytest.raises(GitHubNetworkError, match='network error while fetching'):
        _fetch()


def test_fetch_release_asset_reports_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=b'<html>not json</html>')

    with pytest.raises(GitHubError, match='github returned invalid json'):
        _fetch()


def test_fetch_release_asset_reports_a_payload_without_assets(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=json.dumps({'tag_name': _TAG}).encode('utf-8'))

    with pytest.raises(GitHubError, match='github returned no assets list'):
        _fetch()


def test_fetch_release_asset_reports_an_asset_missing_from_the_release(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=_release_json(asset_name='something-else.tar.gz'))

    with pytest.raises(GitHubNotFoundError, match="has no asset named 'wheelhouse.tar.gz'"):
        _fetch()


def test_fetch_release_asset_reports_an_asset_without_an_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, lookup=json.dumps({'assets': [{'name': _ASSET}]}).encode('utf-8'))

    with pytest.raises(GitHubError, match='has no api url'):
        _fetch()


def test_fetch_release_asset_cleans_up_when_the_download_fails(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    _fake_github(monkeypatch, download=_http_error(404))

    with pytest.raises(GitHubNotFoundError, match='github returned 404'):
        _fetch()

    assert list(temp_root.iterdir()) == []


def test_fetch_release_asset_never_leaks_a_presigned_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """A redirect target's query string is itself a credential."""
    presigned = 'https://objects.githubusercontent.com/asset?X-Amz-Signature=deadbeef'
    _fake_github(monkeypatch, lookup=_release_json(asset_url=presigned), download=OSError('reset'))

    with pytest.raises(GitHubNetworkError) as raised:
        _fetch()

    assert 'X-Amz-Signature' not in str(raised.value)
    assert str(raised.value) == f"network error while fetching asset '{_ASSET}' of {_REPO}@{_TAG}"


def test_fetch_release_asset_aborts_a_download_that_outruns_its_deadline(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    _fake_github(monkeypatch, download=b'x' * (128 * 1024))
    clock = iter([0.0, 1.0, 10_000.0])
    monkeypatch.setattr('charmlibs.seceng.github.time.monotonic', lambda: next(clock))

    with pytest.raises(GitHubNetworkError, match='exceeded 300 seconds'):
        _fetch()

    assert list(temp_root.iterdir()) == []


def test_fetch_release_asset_translates_a_read_failure_mid_stream(
    monkeypatch: pytest.MonkeyPatch, temp_root: pathlib.Path
) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> typing.IO[bytes]:
        if '/releases/tags/' in request.full_url:
            return typing.cast(typing.IO[bytes], _FakeResponse(_release_json()))
        return typing.cast(typing.IO[bytes], _TruncatedResponse())

    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)

    with pytest.raises(GitHubNetworkError, match='network error while fetching'):
        _fetch()

    assert list(temp_root.iterdir()) == []
