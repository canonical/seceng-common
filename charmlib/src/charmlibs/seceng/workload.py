# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Install a Python wheelhouse without depending on the Juju runtime.

This module performs machine-level operations for a wheelhouse-only workload.
It has no development or source-install path: no git, SSH, compiler toolchains,
or pip installs from a source repository.

The module imports no ops, so the install path can be unit tested without a
charm harness. Subprocess environments keep the charm's proxy variables but
drop its virtual environment, so pip and Python resolve only the workload's
own. The GitHub token reaches curl on stdin rather than argv; see
``_auth_config``.

``unpack_wheelhouse`` removes its input tarball only after successful validation
and replacement. GitHub, tar, and checksum failures raise ``WheelhouseError``;
``create_venv``, ``pip_install_wheelhouse``, and systemctl helpers expose raw
``subprocess.CalledProcessError``.

Each version has its own ``venvs/<version>`` virtual environment, with
``current`` symlinked to the active one. Each venv is created at its final
path. A systemd unit must invoke the interpreter through ``current`` rather
than a resolved version path, or flipping the symlink has no effect.

Versions share ``wheelhouse/`` safely because reverting is a symlink flip, so a
retained previous version does not need its wheels. No automatic post-restart
rollback is implemented: most start failures are configuration faults rather
than version faults, and the previous version remains on disk for manual revert.
"""

import collections.abc
import copy
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import typing

from . import utils


# A version string becomes a directory name under venvs/ as well as part of a
# release URL, so restrict it to characters that are inert in both.
_VERSION_PATTERN = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]*\Z')
# Keep a status message readable when a self-check failure is reported through it.
_SELF_CHECK_REASON_LIMIT = 200

# Bound connection setup so an unreachable GitHub endpoint cannot wedge a hook.
_CURL_CONNECT_TIMEOUT_SECONDS = 30
# Cap the small release-metadata request so a stalled API or proxy fails promptly.
_CURL_API_MAX_TIME_SECONDS = 300
# Give curl time to report its own timeout before Python enforces the outer bound.
_CURL_API_SUBPROCESS_TIMEOUT_SECONDS = _CURL_API_MAX_TIME_SECONDS + 5.0
# Allow a large wheelhouse to cross a slow link without imposing a short transfer cap.
_CURL_DOWNLOAD_MAX_TIME_SECONDS = 3600
# Detect a nearly wedged transfer while permitting downloads that make slow progress.
_CURL_DOWNLOAD_SPEED_LIMIT_BYTES_PER_SECOND = 1024
# Require the low transfer rate to persist before treating the download as stalled.
_CURL_DOWNLOAD_SPEED_TIME_SECONDS = 120
# Apply the same allowance to the download subprocess.
_CURL_DOWNLOAD_SUBPROCESS_TIMEOUT_SECONDS = _CURL_DOWNLOAD_MAX_TIME_SECONDS + 5.0


class WheelhouseError(Exception):
    """Report a wheelhouse retrieval, verification, or installation failure."""


def validate_version(version: str) -> str:
    """Return ``version`` unchanged if it is safe to use, else raise.

    A configured version is interpolated into a release URL and used verbatim as
    a directory name under ``venvs/``, so it is restricted to alphanumerics, dot,
    underscore, and hyphen, and must begin with an alphanumeric. That rejects
    path traversal, a leading hyphen that a later command could read as an
    option, and shell or URL metacharacters, without needing every caller to
    remember to sanitise.
    """
    if not version:
        raise WheelhouseError('version must not be empty.')
    if not _VERSION_PATTERN.match(version):
        raise WheelhouseError(
            f'version {version!r} is not a valid release tag: use only letters, digits, dot, underscore, '
            'and hyphen, starting with a letter or digit.'
        )
    return version


@dataclasses.dataclass(kw_only=True, frozen=True)
class Wheelhouse:
    """Describe one Python distribution installed from a wheelhouse.

    The consumer charm declares the Debian packages an install needs, including
    ``python3-venv``, ``python3-pip``, ``curl``, and ``tar``, through
    ``SecEngCharmBase.package_install_list``. The base installs them before any
    wheelhouse.
    """

    name: str
    repo: str
    extras: tuple[str, ...] = ()
    import_name: str | None = None
    install_root: pathlib.Path | None = None
    service_name: str | None = None
    version_config_key: str = 'worker-version'
    source_secret_key: str = 'source-credentials'
    token_key: str = 'github-token'
    asset_template: str = 'worker-bundle-{version}-cp312-linux-x86_64.tar.gz'

    def __post_init__(self) -> None:
        """Reject an install root that would be interpreted relative to a hook's cwd."""
        if self.install_root is not None and not self.install_root.is_absolute():
            raise ValueError('install_root must be an absolute path.')

    @property
    def resolved_install_root(self) -> pathlib.Path:
        """Return the configured install root or ``/opt/{name}``."""
        return self.install_root or pathlib.Path('/opt') / self.name

    @property
    def venvs_dir(self) -> pathlib.Path:
        return self.resolved_install_root / 'venvs'

    @property
    def current_link(self) -> pathlib.Path:
        return self.resolved_install_root / 'current'

    def venv_dir(self, version: str) -> pathlib.Path:
        return self.venvs_dir / validate_version(version)

    def venv_python(self, version: str) -> pathlib.Path:
        return self.venv_dir(version) / 'bin' / 'python'

    def venv_pip(self, version: str) -> pathlib.Path:
        return self.venv_dir(version) / 'bin' / 'pip'

    @property
    def wheelhouse_dir(self) -> pathlib.Path:
        return self.resolved_install_root / 'wheelhouse'

    @property
    def version_stamp(self) -> pathlib.Path:
        """Return the path recording the installed version."""
        return self.resolved_install_root / 'installed-version'

    @property
    def source_stamp(self) -> pathlib.Path:
        """Return the path recording the installed source repository."""
        return self.resolved_install_root / 'installed-source'

    @property
    def resolved_service_name(self) -> str:
        return self.service_name or self.name

    @property
    def resolved_import_name(self) -> str:
        """Return the module the self-check imports to prove the venv works."""
        return self.import_name or self.name.replace('-', '_')

    @property
    def requirement_string(self) -> str:
        if not self.extras:
            return self.name
        return f"{self.name}[{','.join(self.extras)}]"

    def asset_name(self, version: str) -> str:
        return self.asset_template.format(version=version)


def clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return a sanitised subprocess environment.

    Only the system path, root home, locale, and proxy variables from the
    current process are inherited. ``VIRTUAL_ENV`` and ``PYTHONPATH`` are
    always removed, including when supplied through ``extra``.
    """
    env: dict[str, str] = {
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': '/root',
        'LANG': 'C.UTF-8',
    }
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
        if variable in os.environ:
            env[variable] = os.environ[variable]
    if extra is not None:
        env.update(extra)
    env.pop('VIRTUAL_ENV', None)
    env.pop('PYTHONPATH', None)
    return env


def run(
    cmd: collections.abc.Sequence[str],
    *,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
    capture: bool = False,
    timeout: float | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command with the sanitised environment and optional text input."""
    env = clean_env(extra_env)
    if input_text is None:
        return subprocess.run(cmd, check=check, env=env, capture_output=capture, timeout=timeout)
    return subprocess.run(
        cmd,
        check=check,
        env=env,
        capture_output=capture,
        timeout=timeout,
        input=input_text.encode('utf-8'),
    )


def _auth_config(token: str) -> str:
    """Return curl's stdin configuration carrying the bearer credential.

    The credential uses ``--config -`` rather than ``-H`` so it never appears in
    the process command line, which local users can read with ``ps``. Curl's
    parser terminates a quoted value on an unescaped double quote and honours
    backslash escapes, so both are rejected; other whitespace and control
    characters are invalid credential content.
    """
    if not token:
        raise WheelhouseError('GitHub token must not be empty.')
    if '"' in token or '\\' in token:
        raise WheelhouseError('GitHub token must not contain a double quote or a backslash.')
    if any(not '\x21' <= character <= '\x7e' for character in token):
        raise WheelhouseError('GitHub token must not contain whitespace, newlines, or non-ASCII characters.')
    return f'header = "Authorization: Bearer {token}"\n'


def _release_api_url(repo: str, tag: str) -> str:
    """Return the GitHub release lookup URL."""
    return f'https://api.github.com/repos/{repo}/releases/tags/{tag}'


def _response_body_and_status(output: bytes) -> tuple[str, int | None]:
    """Separate curl's response body from its optional trailing HTTP status."""
    text = output.decode('utf-8', errors='replace')
    body, separator, status_text = text.rpartition('\n')
    if separator and len(status_text) == 3 and status_text.isdigit():
        return body, int(status_text)
    return text, None


def _github_error(repo: str, tag: str, asset_name: str, status: int | None) -> WheelhouseError:
    """Build an actionable error for a failed GitHub release lookup.

    Deliberately excludes curl's stderr: its configuration-parse diagnostics can
    quote the offending line, and that line carries the credential. These
    messages reach juju status.
    """
    if status == 401:
        return WheelhouseError(
            'GitHub returned 401 for the release lookup: the github-token was rejected as invalid or expired, '
            'or it lacks read access to the repository contents. Rotate the configured release credentials secret.'
        )
    if status == 404:
        return WheelhouseError(
            f'GitHub returned 404 for release tag {tag!r} in {repo!r}: the tag or asset {asset_name!r} '
            'is missing. Verify the tag and release asset name.'
        )
    if status is None:
        return WheelhouseError(
            f'GitHub release lookup for tag {tag!r} in {repo!r} failed without an HTTP status. '
            'Check network and proxy configuration.'
        )
    return WheelhouseError(
        f'GitHub returned HTTP {status} while looking up tag {tag!r} in {repo!r}. Check the repository and credentials.'
    )


def _release_assets(repo: str, tag: str, requested_asset: str, token: str) -> list[dict[str, object]]:
    """Fetch and validate the asset list for one GitHub release."""
    url = _release_api_url(repo, tag)
    result = run(
        [
            '/usr/bin/curl',
            '-q',
            '-sSL',
            '--connect-timeout',
            str(_CURL_CONNECT_TIMEOUT_SECONDS),
            '--max-time',
            str(_CURL_API_MAX_TIME_SECONDS),
            '--config',
            '-',
            '-H',
            'Accept: application/vnd.github+json',
            '--write-out',
            '\n%{http_code}',
            url,
        ],
        check=False,
        capture=True,
        timeout=_CURL_API_SUBPROCESS_TIMEOUT_SECONDS,
        input_text=_auth_config(token),
    )
    body, status = _response_body_and_status(result.stdout or b'')
    if result.returncode != 0 or (status is not None and status >= 400):
        raise _github_error(repo, tag, requested_asset, status)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise WheelhouseError(f'GitHub returned invalid JSON for release tag {tag!r} in {repo!r}.') from error
    if not isinstance(payload, dict):
        raise WheelhouseError(f'GitHub returned an invalid release response for tag {tag!r} in {repo!r}.')
    raw_assets = payload.get('assets')
    if not isinstance(raw_assets, list):
        raise WheelhouseError(f'GitHub release tag {tag!r} in {repo!r} has no valid asset list.')
    return [typing.cast(dict[str, object], asset) for asset in raw_assets if isinstance(asset, dict)]


def _asset_api_url(asset: dict[str, object], repo: str, tag: str, name: str) -> str:
    """Return an asset API URL from a validated GitHub asset object."""
    url = asset.get('url')
    if not isinstance(url, str):
        raise WheelhouseError(f'GitHub asset {name!r} for tag {tag!r} in {repo!r} has no API url.')
    return url


def resolve_asset_url(repo: str, tag: str, asset_name: str, token: str) -> str:
    """Return the exact GitHub API URL for a release asset.

    The asset API URL is the only one that serves a private repository's asset;
    the browser-facing download URL returns 404 whatever credential is
    presented.
    """
    assets = _release_assets(repo, tag, asset_name, token)
    asset = next((entry for entry in assets if entry.get('name') == asset_name), None)
    if asset is None:
        raise _github_error(repo, tag, asset_name, 404)
    return _asset_api_url(asset, repo, tag, asset_name)


def download_asset(asset_url: str, dest: pathlib.Path, token: str) -> None:
    """Download a GitHub release asset and remove any partial file on failure.

    The octet-stream Accept header is required: the asset endpoint returns JSON
    metadata rather than the asset bytes without it.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = run(
            [
                '/usr/bin/curl',
                '-q',
                '-fsSL',
                '--connect-timeout',
                str(_CURL_CONNECT_TIMEOUT_SECONDS),
                '--max-time',
                str(_CURL_DOWNLOAD_MAX_TIME_SECONDS),
                '--speed-limit',
                str(_CURL_DOWNLOAD_SPEED_LIMIT_BYTES_PER_SECOND),
                '--speed-time',
                str(_CURL_DOWNLOAD_SPEED_TIME_SECONDS),
                '-H',
                'Accept: application/octet-stream',
                '--config',
                '-',
                '-o',
                str(dest),
                asset_url,
            ],
            check=False,
            timeout=_CURL_DOWNLOAD_SUBPROCESS_TIMEOUT_SECONDS,
            input_text=_auth_config(token),
        )
        if result.returncode != 0 or not dest.exists():
            raise WheelhouseError('failed to download the wheelhouse asset')
    except Exception as error:
        dest.unlink(missing_ok=True)
        if isinstance(error, WheelhouseError):
            raise
        raise WheelhouseError('failed to download the wheelhouse asset') from error


def fetch_checksum(repo: str, tag: str, asset_name: str, token: str) -> str | None:
    """Download a sibling checksum asset and return its first token if present."""
    checksum_name = f'{asset_name}.sha256'
    assets = _release_assets(repo, tag, checksum_name, token)
    asset = next((entry for entry in assets if entry.get('name') == checksum_name), None)
    if asset is None:
        return None
    checksum_url = _asset_api_url(asset, repo, tag, checksum_name)
    with tempfile.TemporaryDirectory() as directory:
        checksum_path = pathlib.Path(directory) / 'checksum'
        download_asset(checksum_url, checksum_path, token)
        tokens = checksum_path.read_text(encoding='utf-8').split()
    if not tokens:
        raise WheelhouseError(f'GitHub checksum asset {checksum_name!r} is empty.')
    return tokens[0]


def verify_sha256(path: pathlib.Path, expected: str) -> None:
    """Verify a file's SHA-256 digest using bounded-size reads."""
    digest = hashlib.sha256()
    with path.open('rb') as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected.lower():
        raise WheelhouseError(f'SHA-256 mismatch for {path.name}: expected {expected}, got {actual}.')


def _stripped_member(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    """Copy a tar member after removing its one archive-root component."""
    path = pathlib.PurePosixPath(member.name)
    if path.is_absolute() or '..' in path.parts:
        raise WheelhouseError(f'wheelhouse archive contains unsafe member {member.name!r}.')
    if len(path.parts) < 2:
        return None
    stripped = '/'.join(path.parts[1:])
    if not stripped:
        return None
    copied = copy.copy(member)
    copied.name = stripped
    return copied


def _remove_path(path: pathlib.Path) -> None:
    """Remove a file, symlink, or directory without following a symlink."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _clean_swap_artifacts(dest: pathlib.Path) -> None:
    """Remove temporary swap directories left by an earlier interrupted run."""
    prefix = f'.{dest.name}.'
    for candidate in dest.parent.iterdir():
        if candidate.name.startswith(prefix):
            _remove_path(candidate)


def unpack_wheelhouse(tarball: pathlib.Path, dest: pathlib.Path) -> None:
    """Safely replace ``dest`` with a tarball stripped of one leading component.

    The input tarball is removed only after validation and replacement succeed.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    _clean_swap_artifacts(dest)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=f'.{dest.name}.', dir=str(dest.parent)))
    backup_directory = pathlib.Path(tempfile.mkdtemp(prefix=f'.{dest.name}.old.', dir=str(dest.parent)))
    backup_directory.rmdir()
    moved_old = False
    succeeded = False
    restore_failed = False
    try:
        try:
            with tarfile.open(tarball, mode='r:*') as archive:
                roots: set[str] = set()
                members: list[tarfile.TarInfo] = []
                for member in archive.getmembers():
                    stripped = _stripped_member(member)
                    path = pathlib.PurePosixPath(member.name)
                    if path.parts:
                        roots.add(path.parts[0])
                    if stripped is not None:
                        members.append(stripped)
                if len(roots) > 1:
                    raise WheelhouseError('wheelhouse archive members do not share one top-level component.')
                if roots != {'wheelhouse'}:
                    raise WheelhouseError(f'wheelhouse is missing wheelhouse/ in archive {tarball.name!r}.')
                archive.extractall(temporary, members=members, filter='data')
        except WheelhouseError:
            raise
        except (OSError, tarfile.TarError, EOFError) as error:
            raise WheelhouseError(f'failed to safely unpack wheelhouse {tarball.name!r}: {error}.') from error

        if not any(path.is_file() for path in temporary.rglob('*.whl')):
            raise WheelhouseError(f'wheelhouse archive {tarball.name!r} contains no .whl files.')

        if dest.is_symlink() or dest.exists():
            os.replace(dest, backup_directory)
            moved_old = True
        os.replace(temporary, dest)
        temporary = pathlib.Path()
        if moved_old:
            _remove_path(backup_directory)
            moved_old = False
        succeeded = True
    except Exception:
        if moved_old and not dest.exists() and not dest.is_symlink() and backup_directory.exists():
            try:
                os.replace(backup_directory, dest)
            except Exception:
                restore_failed = True
            else:
                moved_old = False
        raise
    finally:
        if temporary.name:
            _remove_path(temporary)
        if moved_old and not restore_failed:
            _remove_path(backup_directory)
        if succeeded:
            tarball.unlink(missing_ok=True)


def is_venv_created(spec: Wheelhouse, version: str) -> bool:
    """Return whether one version's virtual environment Python exists."""
    return spec.venv_python(version).exists()


def create_venv(spec: Wheelhouse, version: str) -> None:
    """Create one version's virtual environment at its final path.

    A virtual environment records absolute paths in ``pyvenv.cfg`` and in every
    console-script shebang, so it must be built where it will be used rather
    than built elsewhere and moved.
    """
    spec.venvs_dir.mkdir(parents=True, exist_ok=True)
    run(['/usr/bin/python3', '-m', 'venv', str(spec.venv_dir(version))])


def remove_venv(spec: Wheelhouse, version: str) -> None:
    """Remove one version's virtual environment.

    Callers must not pass the version that ``current`` points at: removing it
    would delete the interpreter the systemd unit resolves through.
    """
    shutil.rmtree(spec.venv_dir(version), ignore_errors=True)


def current_version(spec: Wheelhouse) -> str | None:
    """Return the version the ``current`` symlink names, if any.

    Reports the symlink's own target rather than a resolved path, so a version
    whose directory has been removed is still reported: the caller decides
    whether the target has to exist. Returns ``None`` when the link is absent,
    is not a symlink, or points outside ``venvs/``.
    """
    try:
        target = os.readlink(spec.current_link)
    except OSError:
        return None
    path = pathlib.PurePosixPath(target)
    if path.parent != pathlib.PurePosixPath('venvs'):
        return None
    return path.name


def flip_current(spec: Wheelhouse, version: str) -> None:
    """Point ``current`` at one version's virtual environment atomically.

    The new link is created under a temporary name and renamed over the old one,
    because unlinking first would leave a window in which the service has no
    interpreter at all. The target is stored relative to the install root so the
    tree can be relocated or bind-mounted whole.
    """
    version = validate_version(version)
    link = spec.current_link
    if link.exists(follow_symlinks=False) and not link.is_symlink():
        raise WheelhouseError(f'{link} exists and is not a symlink; refusing to replace it.')
    link.parent.mkdir(parents=True, exist_ok=True)
    temporary = link.with_name(f'.{link.name}.new')
    _remove_path(temporary)
    os.symlink(pathlib.Path('venvs') / version, temporary)
    try:
        os.replace(temporary, link)
    except OSError as error:
        _remove_path(temporary)
        raise WheelhouseError(f'failed to activate {spec.name} {version}: {error}.') from error


def self_check(spec: Wheelhouse, version: str) -> None:
    """Prove one version's virtual environment can import the workload.

    pip can exit 0 while a wheel or native dependency still leaves the
    environment unable to import the workload, so this check runs before
    ``current`` is flipped.

    The module name comes from the static specification, but it is checked
    against Python identifier rules before it is passed to ``python -c``.
    """
    module = spec.resolved_import_name
    if not all(part.isidentifier() for part in module.split('.')):
        raise WheelhouseError(f'self-check module {module!r} is not a valid module name.')
    result = run([str(spec.venv_python(version)), '-c', f'import {module}'], check=False, capture=True)
    if result.returncode == 0:
        return
    detail = ''
    for line in reversed((result.stderr or b'').decode('utf-8', errors='replace').splitlines()):
        if line.strip():
            detail = line.strip()[:_SELF_CHECK_REASON_LIMIT]
            break
    message = f'{spec.name} {version} failed its self-check: {module} could not be imported'
    if detail:
        message = f'{message} ({detail})'
    raise WheelhouseError(f'{message}.')


def prune_venvs(spec: Wheelhouse, *, keep: int = 2) -> list[str]:
    """Remove all but the newest ``keep`` virtual environments and return the removed names.

    The active version is always retained regardless of its modification time,
    so pruning can never delete what ``current`` points at. Ordering is by
    modification time because a version directory carries no other record of
    when it was installed.
    """
    if keep < 1:
        raise ValueError('keep must be at least 1.')
    try:
        entries = [entry for entry in spec.venvs_dir.iterdir() if entry.is_dir() and not entry.is_symlink()]
    except FileNotFoundError:
        return []
    active = current_version(spec)
    retained: list[str] = [active] if active is not None else []
    for entry in sorted(entries, key=lambda entry: entry.stat().st_mtime, reverse=True):
        if len(retained) >= keep:
            break
        if entry.name not in retained:
            retained.append(entry.name)
    removed: list[str] = []
    for entry in entries:
        if entry.name not in retained:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return sorted(removed)


def pip_install_wheelhouse(spec: Wheelhouse, version: str) -> None:
    """Install the distribution strictly offline from the extracted wheelhouse."""
    run(
        [
            str(spec.venv_pip(version)),
            '--isolated',
            'install',
            '--no-index',
            '--find-links',
            str(spec.wheelhouse_dir),
            '--force-reinstall',
            spec.requirement_string,
        ]
    )


def read_stamp(path: pathlib.Path) -> str | None:
    """Read a stamp value, returning ``None`` when the stamp is absent."""
    try:
        return path.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        return None


def write_stamp(path: pathlib.Path, value: str) -> None:
    """Securely write a stamp readable by operators as mode 0644."""
    with utils.open_file_secure(path, mode=0o644, create_parents=True) as stamp:
        stamp.write(f'{value}\n')


def service_stop(name: str) -> None:
    """Stop a systemd service."""
    run(['/usr/bin/systemctl', 'stop', name])


def service_running(name: str) -> bool:
    """Return whether systemd reports a service as active."""
    result = run(['/usr/bin/systemctl', 'is-active', '--quiet', name], check=False, capture=True)
    return result.returncode == 0
