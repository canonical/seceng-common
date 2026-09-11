# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Authenticated retrieval of GitHub release assets.

Two invariants govern this module. The bearer token is attached with
``add_unredirected_header`` so that it is not replayed to the presigned object
storage an asset download redirects to, and no exception message ever contains
a URL, because a presigned URL is itself a credential.
"""

from __future__ import annotations

__all__ = [
    'GitHubAuthError',
    'GitHubChecksumError',
    'GitHubClient',
    'GitHubError',
    'GitHubNetworkError',
    'GitHubNotFoundError',
    'Token',
]

import collections.abc
import contextlib
import hashlib
import hmac
import http.client
import json
import pathlib
import tempfile
import time
import typing
import urllib.error
import urllib.parse
import urllib.request

_API_ROOT = 'https://api.github.com'
_USER_AGENT = 'canonical-seceng-workload'
_API_VERSION = '2022-11-28'
_HTTP_TIMEOUT_SECONDS = 30
_DOWNLOAD_MAX_SECONDS = 300
_DOWNLOAD_CHUNK_BYTES = 64 * 1024


class GitHubError(Exception):
    """Base error for GitHub operations, safe for Juju status messages."""


class GitHubAuthError(GitHubError):
    """GitHub rejected the credential as invalid, expired, or insufficient."""


class GitHubNotFoundError(GitHubError):
    """The requested repository, release, or asset does not exist."""


class GitHubNetworkError(GitHubError):
    """The request failed or stalled before a complete response arrived."""


class GitHubChecksumError(GitHubError):
    """A downloaded asset did not match its expected digest."""


class Token(str):
    """A GitHub credential that is safe to interpolate into an HTTP header.

    Accepts only printable ASCII without spaces: a token carrying CR, LF, or a
    control character could otherwise append headers of its own. ``repr`` is
    redacted so a traceback or a logged argument list cannot disclose it;
    ``str`` is not, because the Authorization header needs the real value.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> Token:
        """Validate value and return it as a Token, or raise ValueError."""
        if not value:
            raise ValueError('github token must not be empty')
        if any(not '\x21' <= character <= '\x7e' for character in value):
            raise ValueError('github token must contain only printable ASCII characters and no spaces')
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return '<Token [REDACTED]>'


def _url_segment(value: str, subject: str) -> str:
    """Percent-encode value as a single URL path segment.

    Rejects '.' and '..': both are made up entirely of unreserved characters,
    so encoding leaves them intact and they would traverse the API path rather
    than name a resource. Raises ValueError.
    """
    if not value:
        raise ValueError(f'{subject} must not be empty')
    if value in {'.', '..'}:
        raise ValueError(f'{subject} must not be a relative path segment')
    return urllib.parse.quote(value, safe='')


class GitHubClient:
    """Read-only access to a GitHub repository's release assets."""

    def __init__(self, token: str):
        """Bind to the credential token, or raise ValueError if it cannot be a header value."""
        self._token = Token(token)

    @contextlib.contextmanager
    def fetch_release_asset(
        self,
        repo: str,
        tag: str,
        asset_name: str,
        *,
        expected_sha256: str | None = None,
    ) -> collections.abc.Iterator[pathlib.Path]:
        """Download a named asset of a release tag to a temporary path.

        Yields the path of the complete artifact and deletes it when the with
        block exits: a path that escapes the block names nothing.

        The artifact is created under tempfile.gettempdir(). Because the
        artifact is yielded as a path rather than an open file descriptor,
        the directory must not be writable outside the trust boundary to
        prevent payload substitution after digest verification.

        When expected_sha256 is given the digest is computed as the bytes
        arrive and verified before the path is yielded, so an unverified
        payload is never reachable under a name the caller knows. Whitespace
        and case are ignored; anything else that is not the artifact's digest
        is a mismatch.

        Nothing is retrieved until the context is entered. Raises ValueError
        for a malformed repo, tag, or asset name, and GitHubAuthError,
        GitHubNotFoundError, GitHubNetworkError, GitHubChecksumError, or
        GitHubError for a failed retrieval.
        """
        expected = None
        if expected_sha256 is not None:
            expected = expected_sha256.strip().lower()

        asset_url = self._locate_asset(repo, tag, asset_name)
        subject = f'asset {asset_name!r} of {repo}@{tag}'

        # Closing unlinks, and the with covers every exit including one thrown
        # in at the yield, so no failure path can leave the artifact behind.
        with tempfile.NamedTemporaryFile(mode='wb', delete=True) as artifact:
            digest = self._stream(asset_url, artifact, subject)
            # Compared as bytes: an expected digest that is not ASCII hex is
            # then a mismatch like any other, where comparing as str would
            # raise TypeError on a non-ASCII character.
            if expected is not None and not hmac.compare_digest(digest.encode(), expected.encode()):
                raise GitHubChecksumError(f'sha256 mismatch for {subject}: expected {expected}, computed {digest}')
            # The caller reads the artifact by name, so buffered bytes must
            # reach the file before the path is of any use.
            artifact.flush()
            yield pathlib.Path(artifact.name)

    def _locate_asset(self, repo: str, tag: str, asset_name: str) -> str:
        """Return the API URL of a named asset on a release tag.

        Raises GitHubNotFoundError if the release exists but carries no asset
        under that name.
        """
        owner, _, name = repo.partition('/')
        url = (
            f'{_API_ROOT}/repos/{_url_segment(owner, "repository owner")}'
            f'/{_url_segment(name, "repository name")}'
            f'/releases/tags/{_url_segment(tag, "release tag")}'
        )
        subject = f'release {tag!r} of {repo}'

        with self._open(url, 'application/vnd.github+json', subject) as response:
            try:
                payload = json.loads(response.read())
            except json.JSONDecodeError as err:
                raise GitHubError(f'github returned invalid json for {subject}') from err

        if not isinstance(payload, dict) or not isinstance(payload.get('assets'), list):
            raise GitHubError(f'github returned no assets list for {subject}')
        asset = next((a for a in payload['assets'] if isinstance(a, dict) and a.get('name') == asset_name), None)
        if asset is None:
            raise GitHubNotFoundError(f'{subject} has no asset named {asset_name!r}')
        asset_url = asset.get('url')
        if not isinstance(asset_url, str):
            raise GitHubError(f'asset {asset_name!r} of {subject} has no api url')
        return asset_url

    def _stream(self, url: str, sink: typing.IO[bytes], subject: str) -> str:
        """Copy url into sink, returning the hex sha-256 of everything written."""
        hasher = hashlib.sha256()
        deadline = time.monotonic() + _DOWNLOAD_MAX_SECONDS
        with self._open(url, 'application/octet-stream', subject) as response:
            while chunk := response.read(_DOWNLOAD_CHUNK_BYTES):
                hasher.update(chunk)
                sink.write(chunk)
                if time.monotonic() > deadline:
                    raise GitHubNetworkError(f'download of {subject} exceeded {_DOWNLOAD_MAX_SECONDS} seconds')
        return hasher.hexdigest()

    @contextlib.contextmanager
    def _open(self, url: str, accept: str, subject: str) -> collections.abc.Iterator[typing.IO[bytes]]:
        """Open an authenticated GitHub URL, translating transport failures.

        subject names the resource for error messages; it must never be derived
        from url, which for an asset download carries a presigned credential.
        Failures raised while reading the response inside the with body are
        translated too.
        """
        request = urllib.request.Request(
            url,
            headers={
                'Accept': accept,
                'User-Agent': _USER_AGENT,
                'X-GitHub-Api-Version': _API_VERSION,
            },
        )
        # Unredirected, so urllib does not replay the credential to the
        # presigned storage host an asset download redirects to.
        request.add_unredirected_header('Authorization', f'Bearer {self._token}')
        try:
            with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
                yield response
        except urllib.error.HTTPError as err:
            err.close()
            if err.code == 401:
                raise GitHubAuthError(f'github rejected the token while fetching {subject}') from err
            if err.code == 404:
                raise GitHubNotFoundError(f'github returned 404 for {subject}') from err
            raise GitHubError(f'github returned http {err.code} for {subject}') from err
        except (OSError, http.client.HTTPException) as err:
            raise GitHubNetworkError(f'network error while fetching {subject}') from err
