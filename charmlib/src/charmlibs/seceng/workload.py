# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Versioned deployment of a Python workload from an offline wheelhouse.

A deployment is a tree the caller owns: ``<install_root>/venvs`` holds one
virtualenv per release tag and ``<install_root>/current`` is a symlink to the
one in service. Neither directory is ever created here, because their ownership
and permissions belong to the charm that laid the tree out. Release artifacts
are acquired by charmlibs.seceng.github and the unit that runs a deployed
workload is managed by charmlibs.seceng.systemd.

Every virtualenv is built at the path it will be served from and is linked into
service only once it has been proven to import the workload, so a failed build
is deleted and the deployment in service is never written into. Each
check-then-act sequence -- replacing the symlink, pruning old versions -- holds
an O_DIRECTORY descriptor on the parent directory and acts through *at()
syscalls, so the directory cannot be swapped for another between the check and
the act.
"""

from __future__ import annotations

__all__ = [
    'ArtifactExtractionError',
    'Version',
    'Wheelhouse',
    'WorkloadError',
    'WorkloadInstallError',
    'unpack_archive',
]

import collections.abc
import contextlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

from . import utils

_VERSION_PATTERN = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]*\Z')
_VENVS_DIR_NAME = 'venvs'
_CURRENT_LINK_NAME = 'current'
_REQUIREMENT_STAMP_NAME = '.wheelhouse-requirement'
_SYSTEM_PYTHON = '/usr/bin/python3'
# Bound for every local subprocess (virtualenv creation, pip, the import
# self-check); without it a hung child blocks the hook until Juju kills the
# whole dispatch.
_SUBPROCESS_TIMEOUT_SECONDS = 300


class WorkloadError(Exception):
    """Base error for workload operations, safe for Juju status messages."""


class ArtifactExtractionError(WorkloadError):
    """Archive extraction failed or the archive contained unsafe paths."""


class WorkloadInstallError(WorkloadError):
    """Virtual environment creation, pip install, or the self-check failed."""


class Version(str):
    """A release tag that is safe to use as a single path component.

    Admits an alphanumeric first character followed by alphanumerics, dots,
    underscores, and hyphens. That is what allows a version to be interpolated
    into a path or a symlink target with no further checking: it can be neither
    empty, nor '.' or '..', nor carry a separator.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> Version:
        """Validate value and return it as a Version, or raise ValueError."""
        if not _VERSION_PATTERN.match(value):
            raise ValueError(
                f'version {value!r} must start with a letter or digit and contain only letters, digits, and '
                "the characters '._-'"
            )
        return super().__new__(cls, value)


def unpack_archive(archive_path: pathlib.Path, dest_dir: pathlib.Path) -> None:
    """Extract a tar archive into dest_dir, which must not yet exist.

    The destination is claimed with mkdir(exist_ok=False), so extraction only
    ever populates a directory this call created and never writes into a tree a
    workload may be reading. dest_dir.parent must already exist: creating it
    would mean inventing the ownership and permissions that belong to the
    caller.

    Device nodes, links whose targets escape the extraction root, and member
    paths that are absolute, empty, or contain '..' are all refused. The
    archive's own layout is preserved. dest_dir is removed again if anything
    fails, so a partial extraction never outlives the failure.

    Raises ArtifactExtractionError.
    """
    if not archive_path.is_file():
        raise ArtifactExtractionError(f'archive file not found: {archive_path}')

    try:
        dest_dir.mkdir(exist_ok=False)
    except OSError as err:
        raise ArtifactExtractionError(f'failed to claim extraction directory {dest_dir}: {err}') from err

    with contextlib.ExitStack() as on_failure:
        on_failure.callback(shutil.rmtree, dest_dir, ignore_errors=True)
        try:
            with tarfile.open(archive_path, mode='r:*') as archive:
                members = archive.getmembers()
                for member in members:
                    member_path = pathlib.PurePosixPath(member.name)
                    if not member_path.parts or member_path.is_absolute() or '..' in member_path.parts:
                        raise ArtifactExtractionError(f'archive contains unsafe member path: {member.name!r}')
                archive.extractall(dest_dir, members=members, filter='data')
        except (OSError, tarfile.TarError, EOFError) as err:
            raise ArtifactExtractionError(f'failed to extract archive {archive_path.name!r}: {err}') from err
        on_failure.pop_all()


def _run(argv: collections.abc.Sequence[str], step: str) -> None:
    """Run argv to completion, or raise WorkloadInstallError naming step.

    The environment is the ambient one minus the charm's own interpreter
    context, so a build cannot pick up the charm's virtualenv, and the call is
    bounded so a hung child cannot hold the hook.
    """
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            env=utils.clean_env(),
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as err:
        raise WorkloadInstallError(f'{step} did not finish within {_SUBPROCESS_TIMEOUT_SECONDS} seconds') from err
    except OSError as err:
        raise WorkloadInstallError(f'failed to start {step}: {err}') from err
    if result.returncode != 0:
        raise WorkloadInstallError(
            f'{step} failed with exit status {result.returncode}{utils.stderr_detail(result.stderr)}'
        )


@contextlib.contextmanager
def _directory_fd(path: pathlib.Path) -> collections.abc.Iterator[int]:
    """Hold path open as the descriptor that *at() syscalls resolve against.

    Raises OSError if path is not an existing directory.
    """
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


def _replace_symlink(parent_fd: int, link_name: str, target: str) -> None:
    """Point link_name at target inside the directory held open as parent_fd.

    The link is staged under a temporary name and renamed over link_name, so a
    reader following it sees either the old target or the new one; both syscalls
    resolve against parent_fd. Replaces anything but a directory, which rename
    refuses. Raises OSError.
    """
    staged = f'.{link_name}.tmp'
    try:
        os.symlink(target, staged, dir_fd=parent_fd)
    except FileExistsError:
        # Left behind by a run interrupted between the symlink and the rename.
        os.unlink(staged, dir_fd=parent_fd)
        os.symlink(target, staged, dir_fd=parent_fd)
    try:
        os.rename(staged, link_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(staged, dir_fd=parent_fd)
        raise


class Wheelhouse:
    """The versioned virtualenv deployment rooted at one install directory."""

    def __init__(self, install_root: pathlib.Path, import_name: str):
        """Bind to the deployment at install_root that serves import_name.

        install_root and its 'venvs' subdirectory must already exist, with the
        ownership and permissions the caller intends. Raises ValueError if
        import_name is not a Python module path.
        """
        if not all(part.isidentifier() for part in import_name.split('.')):
            raise ValueError(f'import name {import_name!r} is not a python module path')
        self.install_root = install_root
        self.import_name = import_name
        self.venvs_dir = install_root / _VENVS_DIR_NAME
        self.current_link = install_root / _CURRENT_LINK_NAME

    def get_active_version(self) -> str | None:
        """Return the version 'current' names, or None if it names nothing.

        Reports what is recorded as being in service, not whether it still
        works: a dangling link still names its version. None means the link is
        absent or is not a symlink.
        """
        try:
            target = os.readlink(self.current_link)
        except OSError:
            return None
        return pathlib.PurePosixPath(target).name

    def is_active_version(self, version: str, requirement: str) -> bool:
        """Return whether version is in service and can still run the workload.

        True requires that 'current' names version, that its virtualenv was
        built for this exact requirement, and that its interpreter imports the
        workload module. Anything else is False, including a version that is
        installed but has not been activated.

        Raises ValueError for a malformed version.
        """
        version = Version(version)
        return self.get_active_version() == version and self._is_working(self.venvs_dir / version, requirement)

    def install(self, wheelhouse_tar: pathlib.Path, version: str, requirement: str) -> None:
        """Build the virtualenv for version from an offline wheelhouse archive.

        The virtualenv is created at venvs/<version>, the path it will be served
        from, and is populated from the wheels in wheelhouse_tar alone -- pip is
        given no index. It survives only once its interpreter has imported the
        workload module: a failure at any step removes it again, and the version
        in service is untouched either way. Nothing is put into service here;
        call activate() for that.

        Returns without doing anything if venvs/<version> is already a working
        install of requirement, which is what lets a charm call this on every
        hook. Refuses if it exists and is anything else: that tree may be the
        one the workload is running from, and it is not overwritten in place.

        The archive is extracted below the directory TMPDIR names.

        Raises ValueError for a malformed version, and ArtifactExtractionError
        or WorkloadInstallError on failure.
        """
        version = Version(version)
        venv_dir = self.venvs_dir / version
        if self._is_working(venv_dir, requirement):
            return

        try:
            venv_dir.mkdir(exist_ok=False)
        except FileExistsError as err:
            raise WorkloadInstallError(
                f'{venv_dir} already exists and is not a working install of {requirement!r}'
            ) from err
        except OSError as err:
            raise WorkloadInstallError(f'failed to create {venv_dir}: {err}') from err

        with contextlib.ExitStack() as on_failure:
            on_failure.callback(shutil.rmtree, venv_dir, ignore_errors=True)
            with tempfile.TemporaryDirectory() as scratch:
                wheels = pathlib.Path(scratch) / 'wheelhouse'
                unpack_archive(wheelhouse_tar, wheels)
                _run([_SYSTEM_PYTHON, '-m', 'venv', str(venv_dir)], f'virtualenv creation for {version}')
                _run(
                    [
                        str(venv_dir / 'bin' / 'pip'),
                        'install',
                        '--isolated',
                        '--no-index',
                        '--find-links',
                        str(wheels),
                        '--force-reinstall',
                        requirement,
                    ],
                    f'pip install of {requirement!r} for {version}',
                )
            failure = self._import_failure(venv_dir)
            if failure is not None:
                raise WorkloadInstallError(f'self-check of {version} failed: {failure}')
            try:
                with utils.open_file_secure(
                    venv_dir / _REQUIREMENT_STAMP_NAME,
                    mode=0o644,
                    create_parents=False,
                ) as stamp:
                    stamp.write(f'{requirement}\n')
            except OSError as err:
                raise WorkloadInstallError(f'failed to write the requirement stamp for {version}: {err}') from err
            on_failure.pop_all()

    def activate(self, version: str) -> None:
        """Put version into service by pointing 'current' at its virtualenv.

        Whatever 'current' was -- a link to another version, or a stray regular
        file -- is replaced atomically. The workload keeps running from the
        files it has already opened until the caller restarts it.

        Raises ValueError for a malformed version, and WorkloadError if the
        version is not installed or the link cannot be replaced.
        """
        version = Version(version)
        venv_dir = self.venvs_dir / version
        if not venv_dir.is_dir():
            raise WorkloadError(f'cannot activate {version}: {venv_dir} is not a directory')
        try:
            with _directory_fd(self.install_root) as root_fd:
                _replace_symlink(root_fd, _CURRENT_LINK_NAME, f'{_VENVS_DIR_NAME}/{version}')
        except OSError as err:
            raise WorkloadError(f'failed to point {self.current_link} at {version}: {err}') from err

    def prune(self, keep: int = 2) -> list[str]:
        """Delete all but the newest virtualenvs, returning the versions removed.

        Retains the version in service and, up to keep directories in total,
        the most recently built of the rest, because a rollback needs the
        previous one. The version 'current' names is retained whether or not it
        is among the newest, so pruning cannot delete the deployment the
        workload is running from.

        Raises ValueError if keep is less than one, and WorkloadError if the
        venvs directory cannot be read or an entry cannot be deleted.
        """
        if keep < 1:
            raise ValueError('keep must be at least 1')

        active = self.get_active_version()
        removed: list[str] = []
        try:
            with _directory_fd(self.venvs_dir) as venvs_fd:
                # Only directories are versions to count or delete, and a
                # symlink is never followed to decide that.
                dated: list[tuple[float, str]] = []
                for name in os.listdir(venvs_fd):
                    entry = os.stat(name, dir_fd=venvs_fd, follow_symlinks=False)
                    if stat.S_ISDIR(entry.st_mode):
                        dated.append((entry.st_mtime, name))
                versions = [name for _, name in sorted(dated, reverse=True)]

                retained: set[str] = set()
                if active is not None and active in versions:
                    retained.add(active)
                for version in versions:
                    if len(retained) >= keep:
                        break
                    retained.add(version)
                removed = [version for version in versions if version not in retained]
                for version in removed:
                    shutil.rmtree(version, dir_fd=venvs_fd)
        except OSError as err:
            raise WorkloadError(f'failed to prune {self.venvs_dir}: {err}') from err
        return sorted(removed)

    def _is_working(self, venv_dir: pathlib.Path, requirement: str) -> bool:
        """Return whether venv_dir is a complete install of requirement."""
        try:
            stamped = (venv_dir / _REQUIREMENT_STAMP_NAME).read_text(encoding='utf-8')
        except OSError:
            return False
        return stamped.strip() == requirement.strip() and self._import_failure(venv_dir) is None

    def _import_failure(self, venv_dir: pathlib.Path) -> str | None:
        """Return why venv_dir cannot import the workload module, or None.

        A missing interpreter, a non-zero exit, and a hang all answer the one
        question this asks -- can this virtualenv run the workload -- so each is
        reported as a reason rather than raised. A caller that must fail loudly
        turns the reason into an error.
        """
        python_bin = venv_dir / 'bin' / 'python3'
        if not python_bin.is_file():
            return f'no interpreter at {python_bin}'
        try:
            result = subprocess.run(
                [str(python_bin), '-c', f'import {self.import_name}'],
                check=False,
                capture_output=True,
                env=utils.clean_env(),
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return f'import of {self.import_name} did not finish within {_SUBPROCESS_TIMEOUT_SECONDS} seconds'
        except OSError as err:
            return f'failed to run {python_bin}: {err}'
        if result.returncode != 0:
            return f'{self.import_name} could not be imported{utils.stderr_detail(result.stderr)}'
        return None
