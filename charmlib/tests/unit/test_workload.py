# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Unit tests for the ops-free wheelhouse workload helpers."""

import collections.abc
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import tarfile
import typing
from unittest import mock

import pytest

from charmlibs.seceng import utils
from charmlibs.seceng import workload


def _spec(tmp_path: pathlib.Path, *, extras: tuple[str, ...] = ()) -> workload.Wheelhouse:
    """Return a test specification rooted in a temporary directory."""
    return workload.Wheelhouse(
        name='example-worker',
        repo='canonical/example-worker',
        extras=extras,
        install_root=tmp_path / 'opt' / 'example-worker',
    )


def _github_result(payload: object, status: int = 200, returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    """Return a fake curl result for a GitHub API response."""
    output = json.dumps(payload).encode('utf-8') + f'\n{status}'.encode('ascii')
    return subprocess.CompletedProcess(['/usr/bin/curl'], returncode, stdout=output, stderr=b'')


def _add_tar_member(archive: tarfile.TarFile, name: str, data: bytes = b'') -> None:
    """Add a directory or regular file to a test tarball."""
    info = tarfile.TarInfo(name)
    if name.endswith('/'):
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        archive.addfile(info)
    else:
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))


def _make_tarball(path: pathlib.Path, members: collections.abc.Iterable[tuple[str, bytes]]) -> None:
    """Create a gzipped tarball with the supplied members."""
    with tarfile.open(path, mode='w:gz') as archive:
        for name, data in members:
            _add_tar_member(archive, name, data)


def test_wheelhouse_properties_and_asset_name(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)

    assert spec.resolved_install_root == tmp_path / 'opt' / 'example-worker'
    assert spec.venvs_dir == spec.resolved_install_root / 'venvs'
    assert spec.current_link == spec.resolved_install_root / 'current'
    assert spec.venv_dir('v1.2.3') == spec.resolved_install_root / 'venvs' / 'v1.2.3'
    assert spec.venv_python('v1.2.3') == spec.resolved_install_root / 'venvs' / 'v1.2.3' / 'bin' / 'python'
    assert spec.venv_pip('v1.2.3') == spec.resolved_install_root / 'venvs' / 'v1.2.3' / 'bin' / 'pip'
    assert spec.wheelhouse_dir == spec.resolved_install_root / 'wheelhouse'
    assert spec.version_stamp == spec.resolved_install_root / 'installed-version'
    assert spec.source_stamp == spec.resolved_install_root / 'installed-source'
    assert spec.resolved_service_name == 'example-worker'
    derived = workload.Wheelhouse(name='example-worker-agent', repo='canonical/example-worker-agent')
    assert derived.resolved_import_name == 'example_worker_agent'
    assert spec.requirement_string == 'example-worker'
    assert spec.asset_name('v1.2.3') == 'worker-bundle-v1.2.3-cp312-linux-x86_64.tar.gz'
    assert spec.version_config_key == 'worker-version'
    assert spec.source_secret_key == 'source-credentials'
    assert spec.token_key == 'github-token'

    custom = workload.Wheelhouse(
        name='agent',
        repo='canonical/agent',
        install_root=None,
        service_name='agent-worker',
        import_name='agent_pkg',
        asset_template='agent-bundle-{version}.tar.gz',
    )
    assert custom.resolved_install_root == pathlib.Path('/opt/agent')
    assert custom.resolved_service_name == 'agent-worker'
    assert custom.resolved_import_name == 'agent_pkg'
    assert custom.asset_name('v9') == 'agent-bundle-v9.tar.gz'


@pytest.mark.parametrize('version', ['v1', 'v1.2.3', 'v1.2.3-rc1', '0.1.0rc2', 'a_b'])
def test_validate_version_accepts_release_tags(version: str) -> None:
    assert workload.validate_version(version) == version


@pytest.mark.parametrize(
    'version',
    ['', '..', '.', 'v1/../../etc', 'v1/v2', '-v1', '../v1', 'v1 v2', 'v1;rm -rf /', 'v1\nv2', 'v${x}'],
)
def test_validate_version_rejects_paths_options_and_metacharacters(version: str) -> None:
    with pytest.raises(workload.WheelhouseError):
        workload.validate_version(version)


def test_venv_dir_validates_the_version_so_no_caller_can_escape_venvs(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    with pytest.raises(workload.WheelhouseError):
        spec.venv_dir('../../../etc')


def test_wheelhouse_is_frozen_keyword_only_and_rejects_relative_install_roots(
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path)

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(spec, 'name', 'other')

    constructor: typing.Callable[..., workload.Wheelhouse] = workload.Wheelhouse
    with pytest.raises(TypeError):
        constructor('agent', 'canonical/agent')

    with pytest.raises(ValueError, match='absolute'):
        workload.Wheelhouse(name='agent', repo='canonical/agent', install_root=pathlib.Path('relative'))


@pytest.mark.parametrize(
    ('extras', 'expected'),
    [
        ((), 'agent'),
        (('server',), 'agent[server]'),
        (('server', 'metrics'), 'agent[server,metrics]'),
    ],
)
def test_requirement_string_for_zero_one_and_two_extras(
    tmp_path: pathlib.Path,
    extras: tuple[str, ...],
    expected: str,
) -> None:
    assert (
        workload.Wheelhouse(
            name='agent', repo='canonical/agent', install_root=tmp_path, extras=extras
        ).requirement_string
        == expected
    )


def test_clean_env_forwards_proxies_and_strips_charm_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HTTP_PROXY', 'http://upper-http:3128')
    monkeypatch.setenv('HTTPS_PROXY', 'http://upper-https:3128')
    monkeypatch.setenv('NO_PROXY', '10.0.0.0/8')
    monkeypatch.setenv('ALL_PROXY', 'http://upper-all:3128')
    monkeypatch.setenv('http_proxy', 'http://lower-http:3128')
    monkeypatch.setenv('https_proxy', 'http://lower-https:3128')
    monkeypatch.setenv('no_proxy', 'localhost')
    monkeypatch.setenv('all_proxy', 'http://lower-all:3128')
    monkeypatch.setenv('VIRTUAL_ENV', '/charm/venv')
    monkeypatch.setenv('PYTHONPATH', '/charm/site-packages')

    env = workload.clean_env({'VIRTUAL_ENV': '/extra/venv', 'PYTHONPATH': '/extra/path'})

    assert env['PATH'] == '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    assert env['HOME'] == '/root'
    assert env['LANG'] == 'C.UTF-8'
    assert env['HTTP_PROXY'] == 'http://upper-http:3128'
    assert env['HTTPS_PROXY'] == 'http://upper-https:3128'
    assert env['NO_PROXY'] == '10.0.0.0/8'
    assert env['ALL_PROXY'] == 'http://upper-all:3128'
    assert env['http_proxy'] == 'http://lower-http:3128'
    assert env['https_proxy'] == 'http://lower-https:3128'
    assert env['no_proxy'] == 'localhost'
    assert env['all_proxy'] == 'http://lower-all:3128'
    assert 'VIRTUAL_ENV' not in env
    assert 'PYTHONPATH' not in env


def test_clean_env_omits_unset_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'NO_PROXY',
        'ALL_PROXY',
        'http_proxy',
        'https_proxy',
        'no_proxy',
        'all_proxy',
    ):
        monkeypatch.delenv(variable, raising=False)
    assert set(workload.clean_env()) == {'PATH', 'HOME', 'LANG'}


def test_run_uses_clean_environment_and_encodes_input(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = subprocess.CompletedProcess(['/usr/bin/example'], 0, stdout=b'', stderr=b'')
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((args, kwargs))
        return completed

    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = workload.run(['/usr/bin/example'], input_text='not a secret log message', capture=True, timeout=2.0)

    assert result is completed
    assert calls == [
        (
            (['/usr/bin/example'],),
            {
                'check': True,
                'env': workload.clean_env(),
                'capture_output': True,
                'timeout': 2.0,
                'input': b'not a secret log message',
            },
        )
    ]


def test_auth_config_quotes_the_bearer_header() -> None:
    assert workload._auth_config('ghp_test_token') == 'header = "Authorization: Bearer ghp_test_token"\n'


@pytest.mark.parametrize(
    ('token', 'message'),
    [
        ('', 'must not be empty'),
        ('tok"en', 'double quote or a backslash'),
        ('tok\\en', 'double quote or a backslash'),
        ('token value', 'whitespace, newlines, or non-ASCII'),
        ('token\nvalue', 'whitespace, newlines, or non-ASCII'),
        ('token\tvalue', 'whitespace, newlines, or non-ASCII'),
        ('token\x7f', 'whitespace, newlines, or non-ASCII'),
        ('tokén', 'whitespace, newlines, or non-ASCII'),
    ],
)
def test_auth_config_rejects_unsafe_tokens_without_echoing_them(token: str, message: str) -> None:
    with pytest.raises(workload.WheelhouseError, match=message) as raised:
        workload._auth_config(token)
    assert token not in str(raised.value) or not token


def test_auth_config_rejects_a_token_that_would_splice_a_second_curl_option() -> None:
    # A double quote would close the header value, leaving the rest of the line
    # to be parsed as further curl configuration.
    with pytest.raises(workload.WheelhouseError):
        workload._auth_config('x"\noutput = /etc/cron.d/pwn')


def test_resolve_asset_url_returns_the_api_url_not_browser_url(monkeypatch: pytest.MonkeyPatch) -> None:
    api_url = 'https://api.github.com/repos/canonical/agent/releases/assets/42'
    browser_url = 'https://github.com/canonical/agent/releases/download/v1/worker.tar.gz'
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((cmd, kwargs))
        return _github_result(
            {
                'assets': [
                    {'name': 'other.tar.gz', 'url': 'https://api.github.com/other'},
                    {'name': 'worker.tar.gz', 'url': api_url, 'browser_download_url': browser_url},
                ]
            }
        )

    monkeypatch.setattr(workload, 'run', fake_run)

    assert workload.resolve_asset_url('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret') == api_url
    assert calls == [
        (
            [
                '/usr/bin/curl',
                '-q',
                '-sSL',
                '--connect-timeout',
                '30',
                '--max-time',
                '300',
                '--config',
                '-',
                '-H',
                'Accept: application/vnd.github+json',
                '--write-out',
                '\n%{http_code}',
                'https://api.github.com/repos/canonical/agent/releases/tags/v1',
            ],
            {
                'check': False,
                'capture': True,
                'timeout': 305.0,
                'input_text': 'header = "Authorization: Bearer ghp_secret"\n',
            },
        )
    ]


@pytest.mark.parametrize(
    'call',
    [
        lambda: workload.resolve_asset_url('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret'),
        lambda: workload.fetch_checksum('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret'),
    ],
)
def test_release_lookups_keep_the_token_out_of_argv(
    monkeypatch: pytest.MonkeyPatch,
    call: collections.abc.Callable[[], object],
) -> None:
    # A command line is world-readable through ps, so the credential must reach
    # curl on stdin and never as an argument.
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.append(cmd)
        assert kwargs['input_text'] == 'header = "Authorization: Bearer ghp_secret"\n'
        if '-o' in cmd:
            pathlib.Path(cmd[cmd.index('-o') + 1]).write_text('a' * 64 + '  worker.tar.gz\n', encoding='ascii')
            return subprocess.CompletedProcess(cmd, 0)
        return _github_result(
            {
                'assets': [
                    {'name': 'worker.tar.gz', 'url': 'https://api.github.com/assets/1'},
                    {'name': 'worker.tar.gz.sha256', 'url': 'https://api.github.com/assets/2'},
                ]
            }
        )

    monkeypatch.setattr(workload, 'run', fake_run)
    call()

    assert seen
    for cmd in seen:
        assert not any('ghp_secret' in argument for argument in cmd)
        assert '--netrc' not in cmd


@pytest.mark.parametrize(
    ('status', 'message'),
    [
        (401, 'the github-token was rejected as invalid or expired'),
        (404, r"tag or asset 'worker.tar.gz' is missing"),
    ],
)
def test_resolve_asset_url_has_distinct_401_and_404_advice(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    message: str,
) -> None:
    monkeypatch.setattr(workload, 'run', lambda cmd, **kwargs: _github_result({'message': 'error'}, status))

    with pytest.raises(workload.WheelhouseError, match=message):
        workload.resolve_asset_url('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret')


def test_resolve_asset_url_reports_a_missing_exact_asset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        workload, 'run', lambda cmd, **kwargs: _github_result({'assets': [{'name': 'worker.tar.gz.bak'}]})
    )

    with pytest.raises(workload.WheelhouseError, match='worker.tar.gz'):
        workload.resolve_asset_url('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret')


@pytest.mark.parametrize(
    ('status', 'message'),
    [(None, 'without an HTTP status'), (503, 'HTTP 503')],
)
def test_github_error_reports_missing_and_generic_statuses(
    status: int | None,
    message: str,
) -> None:
    error = workload._github_error('canonical/agent', 'v1', 'worker.tar.gz', status)
    assert message in str(error)


@pytest.mark.parametrize(
    ('output', 'message'),
    [
        (b'not json\n200', 'invalid JSON'),
        (b'[]\n200', 'invalid release response'),
        (b'{"assets": {}}\n200', 'no valid asset list'),
    ],
)
def test_release_assets_rejects_malformed_release_responses(
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
    message: str,
) -> None:
    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr=b'')

    monkeypatch.setattr(workload, 'run', fake_run)

    with pytest.raises(workload.WheelhouseError, match=message):
        workload._release_assets('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret')


def test_asset_api_url_requires_an_api_url() -> None:
    with pytest.raises(workload.WheelhouseError, match='no API url'):
        workload._asset_api_url({}, 'canonical/agent', 'v1', 'worker.tar.gz')


def test_download_asset_removes_partial_file_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    dest = tmp_path / 'nested' / 'worker.tar.gz'

    def fake_run(cmd: list[str], **kwargs: object) -> typing.NoReturn:
        dest.write_bytes(b'partial')
        raise RuntimeError('curl failed')

    monkeypatch.setattr(workload, 'run', fake_run)

    with pytest.raises(workload.WheelhouseError):
        workload.download_asset('https://api.github.com/assets/42', dest, 'ghp_secret')
    assert not dest.exists()


def test_download_asset_asks_for_bytes_and_authenticates_on_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((cmd, kwargs))
        pathlib.Path(cmd[cmd.index('-o') + 1]).write_bytes(b'asset')
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(workload, 'run', fake_run)
    dest = tmp_path / 'worker.tar.gz'
    workload.download_asset('https://api.github.com/assets/42', dest, 'ghp_secret')

    assert calls == [
        (
            [
                '/usr/bin/curl',
                '-q',
                '-fsSL',
                '--connect-timeout',
                '30',
                '--max-time',
                '3600',
                '--speed-limit',
                '1024',
                '--speed-time',
                '120',
                '-H',
                'Accept: application/octet-stream',
                '--config',
                '-',
                '-o',
                str(dest),
                'https://api.github.com/assets/42',
            ],
            {
                'check': False,
                'timeout': 3605.0,
                'input_text': 'header = "Authorization: Bearer ghp_secret"\n',
            },
        )
    ]


def test_fetch_checksum_returns_the_first_whitespace_separated_token(monkeypatch: pytest.MonkeyPatch) -> None:
    checksum_url = 'https://api.github.com/repos/canonical/agent/releases/assets/99'
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: _github_result({'assets': [{'name': 'worker.tar.gz.sha256', 'url': checksum_url}]}),
    )

    def fake_download(url: str, dest: pathlib.Path, token: str) -> None:
        assert url == checksum_url
        assert token == 'ghp_secret'
        dest.write_text('a' * 64 + '  worker.tar.gz\n', encoding='ascii')

    monkeypatch.setattr(workload, 'download_asset', fake_download)

    assert workload.fetch_checksum('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret') == 'a' * 64


def test_fetch_checksum_rejects_an_empty_checksum_asset(monkeypatch: pytest.MonkeyPatch) -> None:
    checksum_url = 'https://api.github.com/repos/canonical/agent/releases/assets/99'
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: _github_result({'assets': [{'name': 'worker.tar.gz.sha256', 'url': checksum_url}]}),
    )
    monkeypatch.setattr(
        workload,
        'download_asset',
        lambda url, dest, token: dest.write_text(' \n\t', encoding='ascii'),
    )

    with pytest.raises(workload.WheelhouseError, match='checksum asset.*empty'):
        workload.fetch_checksum('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret')


def test_fetch_checksum_returns_none_when_the_sibling_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workload, 'run', lambda cmd, **kwargs: _github_result({'assets': []}))
    assert workload.fetch_checksum('canonical/agent', 'v1', 'worker.tar.gz', 'ghp_secret') is None


def test_verify_sha256_reads_in_chunks_and_raises_on_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    read_sizes: list[int] = []

    class ChunkReader:
        def __init__(self) -> None:
            self.calls = 0

        def __enter__(self) -> 'ChunkReader':
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self, size: int) -> bytes:
            read_sizes.append(size)
            self.calls += 1
            if self.calls == 1:
                return b'ab'
            if self.calls == 2:
                return b'cd'
            return b''

    monkeypatch.setattr(pathlib.Path, 'open', lambda self, *args, **kwargs: ChunkReader())
    path = tmp_path / 'worker.tar.gz'

    workload.verify_sha256(path, hashlib.sha256(b'abcd').hexdigest())
    assert read_sizes == [1024 * 1024, 1024 * 1024, 1024 * 1024]
    workload.verify_sha256(path, hashlib.sha256(b'abcd').hexdigest().upper())

    with pytest.raises(workload.WheelhouseError, match='SHA-256 mismatch'):
        workload.verify_sha256(path, '0' * 64)


def test_unpack_wheelhouse_strips_one_component_and_replaces_destination(tmp_path: pathlib.Path) -> None:
    tarball = tmp_path / 'worker.tar.gz'
    _make_tarball(
        tarball,
        (
            ('bundle/', b''),
            ('bundle/wheelhouse/', b''),
            ('bundle/wheelhouse/worker.whl', b'wheel'),
            ('bundle/installed-source', b'repo'),
        ),
    )
    dest = tmp_path / 'wheelhouse'
    (dest / 'stale').mkdir(parents=True)
    (dest / 'stale' / 'file').write_text('stale', encoding='ascii')

    workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'wheelhouse' / 'worker.whl').read_bytes() == b'wheel'
    assert (dest / 'installed-source').read_bytes() == b'repo'
    assert not (dest / 'stale').exists()
    assert not tarball.exists()


def test_unpack_wheelhouse_refuses_a_member_escaping_destination(tmp_path: pathlib.Path) -> None:
    tarball = tmp_path / 'unsafe.tar.gz'
    _make_tarball(tarball, (('bundle/', b''), ('bundle/../../outside', b'bad')))
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    with pytest.raises(workload.WheelhouseError, match='unsafe member'):
        workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert not (tmp_path / 'outside').exists()
    assert tarball.exists()


@pytest.mark.parametrize('members', [(), (('worker.whl', b'flat'),)])
def test_unpack_wheelhouse_keeps_the_old_install_and_tarball_when_wheelhouse_is_missing(
    tmp_path: pathlib.Path,
    members: tuple[tuple[str, bytes], ...],
) -> None:
    tarball = tmp_path / 'invalid.tar.gz'
    _make_tarball(tarball, members)
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    with pytest.raises(workload.WheelhouseError, match='wheelhouse is missing wheelhouse/'):
        workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert tarball.exists()


def test_unpack_wheelhouse_rejects_multiple_archive_roots(tmp_path: pathlib.Path) -> None:
    tarball = tmp_path / 'multiple-roots.tar.gz'
    _make_tarball(
        tarball,
        (
            ('a/wheelhouse/first.whl', b'first'),
            ('b/wheelhouse/second.whl', b'second'),
        ),
    )
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    with pytest.raises(workload.WheelhouseError, match='top-level component'):
        workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert tarball.exists()


@pytest.mark.parametrize(
    ('name', 'member_type', 'linkname'),
    [
        ('bundle/link', tarfile.SYMTYPE, '../../outside'),
        ('bundle/hardlink', tarfile.LNKTYPE, '../outside'),
        ('/bundle/wheelhouse/absolute', tarfile.REGTYPE, None),
        ('bundle/wheelhouse/device', tarfile.CHRTYPE, None),
    ],
)
def test_unpack_wheelhouse_rejects_unsafe_data_members(
    tmp_path: pathlib.Path,
    name: str,
    member_type: bytes,
    linkname: str | None,
) -> None:
    tarball = tmp_path / 'unsafe-data.tar.gz'
    with tarfile.open(tarball, mode='w:gz') as archive:
        _add_tar_member(archive, 'bundle/wheelhouse/worker.whl', b'wheel')
        info = tarfile.TarInfo(name)
        info.type = member_type
        if linkname is not None:
            info.linkname = linkname
        archive.addfile(info)

    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    with pytest.raises(workload.WheelhouseError):
        workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert not (tmp_path / 'outside').exists()
    assert tarball.exists()


def test_unpack_wheelhouse_cleans_stray_swap_artifacts(tmp_path: pathlib.Path) -> None:
    tarball = tmp_path / 'worker.tar.gz'
    _make_tarball(tarball, (('bundle/wheelhouse/worker.whl', b'wheel'),))
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')
    for name in ('.wheelhouse.interrupted', '.wheelhouse.old.interrupted'):
        (tmp_path / name / 'leftover').mkdir(parents=True)

    workload.unpack_wheelhouse(tarball, dest)

    assert not (tmp_path / '.wheelhouse.interrupted').exists()
    assert not (tmp_path / '.wheelhouse.old.interrupted').exists()


def test_unpack_wheelhouse_restores_old_install_when_destination_swap_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    tarball = tmp_path / 'worker.tar.gz'
    _make_tarball(tarball, (('bundle/wheelhouse/worker.whl', b'wheel'),))
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    original_replace = os.replace
    calls = 0

    def fake_replace(source: pathlib.Path, target: pathlib.Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('new destination swap failed')
        original_replace(source, target)

    monkeypatch.setattr(os, 'replace', fake_replace)

    with pytest.raises(OSError, match='new destination swap failed'):
        workload.unpack_wheelhouse(tarball, dest)

    assert (dest / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert not list(tmp_path.glob('.wheelhouse.old.*'))
    assert tarball.exists()


def test_unpack_wheelhouse_preserves_backup_when_restore_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    tarball = tmp_path / 'worker.tar.gz'
    _make_tarball(tarball, (('bundle/wheelhouse/worker.whl', b'wheel'),))
    dest = tmp_path / 'wheelhouse'
    (dest / 'old').mkdir(parents=True)
    (dest / 'old' / 'file').write_text('old', encoding='ascii')

    original_replace = os.replace
    calls = 0

    def fake_replace(source: pathlib.Path, target: pathlib.Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('new destination swap failed')
        if calls == 3:
            raise OSError('restore failed')
        original_replace(source, target)

    monkeypatch.setattr(os, 'replace', fake_replace)

    with pytest.raises(OSError, match='new destination swap failed'):
        workload.unpack_wheelhouse(tarball, dest)

    backups = list(tmp_path.glob('.wheelhouse.old.*'))
    assert len(backups) == 1
    assert (backups[0] / 'old' / 'file').read_text(encoding='ascii') == 'old'
    assert not dest.exists()
    assert tarball.exists()


def test_remove_path_unlinks_a_symlink_without_removing_its_target(tmp_path: pathlib.Path) -> None:
    target = tmp_path / 'target'
    target.write_text('target', encoding='ascii')
    link = tmp_path / 'link'
    link.symlink_to(target)

    workload._remove_path(link)

    assert not link.exists()
    assert target.read_text(encoding='ascii') == 'target'


def test_venv_lifecycle_is_per_version(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        python = pathlib.Path(cmd[-1]) / 'bin' / 'python'
        python.parent.mkdir(parents=True, exist_ok=True)
        python.touch()
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(workload, 'run', fake_run)
    assert not workload.is_venv_created(spec, 'v1')

    workload.create_venv(spec, 'v1')
    workload.create_venv(spec, 'v2')

    # The venv is built at its final path: a venv records absolute paths in
    # pyvenv.cfg and in console-script shebangs, so it cannot be moved there.
    assert calls == [
        ['/usr/bin/python3', '-m', 'venv', str(spec.venvs_dir / 'v1')],
        ['/usr/bin/python3', '-m', 'venv', str(spec.venvs_dir / 'v2')],
    ]
    assert workload.is_venv_created(spec, 'v1')
    assert workload.is_venv_created(spec, 'v2')

    workload.remove_venv(spec, 'v2')

    assert workload.is_venv_created(spec, 'v1')
    assert not workload.is_venv_created(spec, 'v2')


def test_current_version_reads_the_symlink_target(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    assert workload.current_version(spec) is None

    workload.flip_current(spec, 'v1')

    assert workload.current_version(spec) == 'v1'
    # Relative, so the whole tree can be relocated or bind-mounted.
    assert os.readlink(spec.current_link) == 'venvs/v1'


def test_current_version_reports_a_dangling_link_but_not_a_foreign_one(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    spec.resolved_install_root.mkdir(parents=True)

    # A version whose directory was removed must still be reported, so a caller
    # can tell "active but missing" apart from "nothing active".
    os.symlink('venvs/v9', spec.current_link)
    assert workload.current_version(spec) == 'v9'

    spec.current_link.unlink()
    os.symlink('/usr/lib/python3', spec.current_link)
    assert workload.current_version(spec) is None


def test_current_version_is_none_for_a_real_directory(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    spec.current_link.mkdir(parents=True)
    assert workload.current_version(spec) is None


def test_flip_current_replaces_an_existing_link_without_an_empty_window(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    (spec.venvs_dir / 'v1' / 'bin').mkdir(parents=True)
    (spec.venvs_dir / 'v2' / 'bin').mkdir(parents=True)
    (spec.venvs_dir / 'v1' / 'bin' / 'python').touch()
    (spec.venvs_dir / 'v2' / 'bin' / 'python').touch()
    interpreter = spec.current_link / 'bin' / 'python'

    workload.flip_current(spec, 'v1')
    replaced: list[bool] = []
    real_replace = os.replace

    def watching_replace(src: object, dst: object) -> None:
        # At the moment of the rename the old target must still be resolvable:
        # an unlink-then-symlink sequence would leave the service without an
        # interpreter in between.
        replaced.append(interpreter.exists())
        real_replace(src, dst)  # type: ignore[arg-type]  # Testing invalid runtime argument type

    with mock.patch.object(os, 'replace', watching_replace):
        workload.flip_current(spec, 'v2')

    assert replaced == [True]
    assert workload.current_version(spec) == 'v2'
    assert interpreter.exists()
    assert not list(spec.resolved_install_root.glob('.current.*'))


def test_flip_current_refuses_to_replace_a_real_directory(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    spec.current_link.mkdir(parents=True)

    with pytest.raises(workload.WheelhouseError, match='not a symlink'):
        workload.flip_current(spec, 'v1')

    assert spec.current_link.is_dir()


def test_flip_current_cleans_a_stale_temporary_link(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    spec.resolved_install_root.mkdir(parents=True)
    stale = spec.resolved_install_root / '.current.new'
    os.symlink('venvs/leftover', stale)

    workload.flip_current(spec, 'v1')

    assert workload.current_version(spec) == 'v1'
    assert not stale.exists(follow_symlinks=False)


def test_flip_current_rejects_an_unsafe_version(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    with pytest.raises(workload.WheelhouseError):
        workload.flip_current(spec, '../../etc')
    assert workload.current_version(spec) is None


def test_self_check_imports_the_workload_package(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path)
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=b'', stderr=b'')

    monkeypatch.setattr(workload, 'run', fake_run)
    workload.self_check(spec, 'v1')

    assert calls == [[str(spec.venv_python('v1')), '-c', 'import example_worker']]


def test_self_check_reports_the_last_stderr_line_of_a_failed_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path)
    stderr = b'Traceback (most recent call last):\n  ...\nImportError: libssl.so.3: cannot open shared object\n\n'
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout=b'', stderr=stderr),
    )

    with pytest.raises(workload.WheelhouseError, match='libssl.so.3') as raised:
        workload.self_check(spec, 'v1')
    assert 'example_worker' in str(raised.value)
    assert 'v1' in str(raised.value)


def test_self_check_truncates_a_pathological_error_so_a_status_stays_readable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path)
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout=b'', stderr=b'x' * 5000),
    )

    with pytest.raises(workload.WheelhouseError) as raised:
        workload.self_check(spec, 'v1')
    assert len(str(raised.value)) < 400


def test_self_check_survives_a_failure_with_no_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path)
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout=b'', stderr=b'   \n'),
    )

    with pytest.raises(workload.WheelhouseError, match='failed its self-check'):
        workload.self_check(spec, 'v1')


@pytest.mark.parametrize('module', ['not-a-module', 'os; import antigravity', 'a..b'])
def test_self_check_rejects_a_module_name_that_is_not_an_identifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    module: str,
) -> None:
    spec = dataclasses.replace(_spec(tmp_path), import_name=module)

    def unexpected_run(cmd: list[str], **kwargs: object) -> typing.NoReturn:
        raise AssertionError('self_check must reject the specification before running anything')

    monkeypatch.setattr(workload, 'run', unexpected_run)

    with pytest.raises(workload.WheelhouseError, match='not a valid module name'):
        workload.self_check(spec, 'v1')


def _make_venv(spec: workload.Wheelhouse, version: str, *, mtime: float) -> None:
    """Create a fake version directory with a controlled modification time."""
    directory = spec.venvs_dir / version
    (directory / 'bin').mkdir(parents=True)
    (directory / 'bin' / 'python').touch()
    os.utime(directory, (mtime, mtime))


def test_prune_venvs_keeps_the_active_version_and_the_newest_other(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    _make_venv(spec, 'v1', mtime=1000)
    _make_venv(spec, 'v2', mtime=2000)
    _make_venv(spec, 'v3', mtime=3000)
    workload.flip_current(spec, 'v2')

    assert workload.prune_venvs(spec, keep=2) == ['v1']
    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['v2', 'v3']


def test_prune_venvs_never_removes_the_active_version_even_when_it_is_oldest(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    _make_venv(spec, 'old-active', mtime=1000)
    _make_venv(spec, 'newer', mtime=2000)
    _make_venv(spec, 'newest', mtime=3000)
    workload.flip_current(spec, 'old-active')

    assert workload.prune_venvs(spec, keep=2) == ['newer']
    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['newest', 'old-active']
    assert (spec.current_link / 'bin' / 'python').exists()


def test_prune_venvs_tolerates_an_absent_venvs_directory_and_rejects_keep_zero(tmp_path: pathlib.Path) -> None:
    spec = _spec(tmp_path)
    assert workload.prune_venvs(spec) == []
    with pytest.raises(ValueError, match='at least 1'):
        workload.prune_venvs(spec, keep=0)


def test_pip_install_wheelhouse_has_the_complete_offline_force_reinstall_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    spec = _spec(tmp_path, extras=('server', 'metrics'))
    calls: list[list[str]] = []
    monkeypatch.setattr(workload, 'run', lambda cmd, **kwargs: calls.append(cmd))

    workload.pip_install_wheelhouse(spec, 'v1')

    assert calls == [
        [
            str(spec.venv_pip('v1')),
            '--isolated',
            'install',
            '--no-index',
            '--find-links',
            str(spec.wheelhouse_dir),
            '--force-reinstall',
            'example-worker[server,metrics]',
        ]
    ]


def test_stamps_are_secure_readable_and_rewritten(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    written: list[tuple[pathlib.Path, int, bool]] = []

    @contextlib.contextmanager
    def fake_open_file_secure(
        path: pathlib.Path,
        *,
        mode: int = 0o600,
        create_parents: bool = False,
    ) -> collections.abc.Iterator[typing.TextIO]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as file:
            yield file
        os.chmod(path, mode)
        written.append((path, mode, create_parents))

    monkeypatch.setattr(utils, 'open_file_secure', fake_open_file_secure)
    path = tmp_path / 'nested' / 'installed-version'

    assert workload.read_stamp(path) is None
    workload.write_stamp(path, 'v1')
    assert workload.read_stamp(path) == 'v1'
    workload.write_stamp(path, 'v2')
    assert workload.read_stamp(path) == 'v2'
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert written == [(path, 0o644, True), (path, 0o644, True)]


def test_systemd_helpers_use_absolute_systemctl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(workload, 'run', fake_run)
    workload.service_stop('agent')
    assert workload.service_running('agent') is True

    assert [cmd for cmd, _ in calls] == [
        ['/usr/bin/systemctl', 'stop', 'agent'],
        ['/usr/bin/systemctl', 'is-active', '--quiet', 'agent'],
    ]
    assert calls[-1][1] == {'check': False, 'capture': True}


def test_service_running_is_false_for_an_inactive_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        workload,
        'run',
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 3, stdout=b'', stderr=b''),
    )
    assert workload.service_running('agent') is False
