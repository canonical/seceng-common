# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Unit tests for archive extraction and the versioned wheelhouse deployment."""

from __future__ import annotations

import collections.abc
import io
import os
import pathlib
import stat
import subprocess
import tarfile
import typing

import pytest
from conftest import FakeSubprocess, Responder

from charmlibs.seceng import utils
from charmlibs.seceng.workload import (
    ArtifactExtractionError,
    Version,
    Wheelhouse,
    WorkloadError,
    WorkloadInstallError,
    unpack_archive,
)

_IMPORT_NAME = 'my_pkg'
_REQUIREMENT = 'my-pkg==1.0.0'
_WHEEL = 'wheelhouse/my_pkg-1.0.0-py3-none-any.whl'


def _create_tar(path: pathlib.Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 1000
            tar.addfile(info, io.BytesIO(data))


# ============================================================================
# Release tags
# ============================================================================


@pytest.mark.parametrize('tag', ['1.0.0', 'v1.2.3_rc1-beta', '0.1.0', '1', 'a.b-c_d'])
def test_version_accepts_a_release_tag(tag: str) -> None:
    assert Version(tag) == tag


@pytest.mark.parametrize(
    'invalid',
    [
        '',
        '.',
        '..',
        '-1.0.0',
        '_1.0.0',
        '../1.0.0',
        '1.0.0/../../etc',
        '1.0;rm -rf /',
        '1.0?foo=bar',
        '1.0#frag',
        '1.0 2.0',
        '1.0\n2.0',
        '1.0\x00',
        'ünicode',
    ],
)
def test_version_rejects_anything_that_is_not_a_single_path_component(invalid: str) -> None:
    with pytest.raises(ValueError, match='version'):
        Version(invalid)


# ============================================================================
# Archive extraction
# ============================================================================


def test_unpack_archive_preserves_the_archive_layout(tmp_path: pathlib.Path) -> None:
    """A top-level directory in the archive is part of the artifact, not noise."""
    archive = tmp_path / 'bundle.tar.gz'
    _create_tar(
        archive,
        {
            'bundle/file1.txt': b'hello',
            'bundle/subdir/file2.txt': b'world',
        },
    )
    dest = tmp_path / 'output'
    unpack_archive(archive, dest)

    assert (dest / 'bundle' / 'file1.txt').read_bytes() == b'hello'
    assert (dest / 'bundle' / 'subdir' / 'file2.txt').read_bytes() == b'world'


def test_unpack_archive_extracts_members_without_a_common_root(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / 'multi.tar.gz'
    _create_tar(
        archive,
        {
            'file1.txt': b'hello',
            'file2.txt': b'world',
        },
    )
    dest = tmp_path / 'output'
    unpack_archive(archive, dest)

    assert (dest / 'file1.txt').read_bytes() == b'hello'
    assert (dest / 'file2.txt').read_bytes() == b'world'


def test_unpack_archive_is_non_destructive_to_input_archive(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / 'keep.tar.gz'
    _create_tar(archive, {_WHEEL: b'fake-wheel'})
    initial_bytes = archive.read_bytes()

    dest = tmp_path / 'dest'
    unpack_archive(archive, dest)

    assert archive.exists()
    assert archive.read_bytes() == initial_bytes


def test_unpack_archive_refuses_an_existing_destination(tmp_path: pathlib.Path) -> None:
    """Extracting over a live tree would corrupt whatever is reading from it."""
    dest = tmp_path / 'dest'
    dest.mkdir()
    (dest / 'old.txt').write_text('old content')

    archive = tmp_path / 'new.tar.gz'
    _create_tar(archive, {'new.txt': b'new content'})

    with pytest.raises(ArtifactExtractionError, match='failed to claim extraction directory'):
        unpack_archive(archive, dest)

    assert (dest / 'old.txt').read_text() == 'old content'
    assert not (dest / 'new.txt').exists()


def test_unpack_archive_refuses_to_create_the_parent_directory(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / 'bundle.tar.gz'
    _create_tar(archive, {'file.txt': b'hello'})

    with pytest.raises(ArtifactExtractionError, match='failed to claim extraction directory'):
        unpack_archive(archive, tmp_path / 'absent' / 'dest')

    assert not (tmp_path / 'absent').exists()


def test_unpack_archive_reports_a_missing_archive(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ArtifactExtractionError, match='archive file not found'):
        unpack_archive(tmp_path / 'nothing.tar.gz', tmp_path / 'dest')

    assert not (tmp_path / 'dest').exists()


@pytest.mark.parametrize('member', ['bundle/../../evil.txt', '/etc/cron.d/evil', '..', ''])
def test_unpack_archive_rejects_an_unsafe_member_path(tmp_path: pathlib.Path, member: str) -> None:
    archive = tmp_path / 'evil.tar.gz'
    _create_tar(archive, {member: b'bad'})
    dest = tmp_path / 'dest'

    with pytest.raises(ArtifactExtractionError, match='unsafe member path'):
        unpack_archive(archive, dest)

    # No member of a rejected archive is left behind.
    assert not dest.exists()


def test_unpack_archive_rejects_symlink_with_filter_data(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / 'symlink.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        info = tarfile.TarInfo(name='bundle/link')
        info.type = tarfile.SYMTYPE
        info.linkname = '/etc/passwd'
        tar.addfile(info)

    dest = tmp_path / 'dest'
    with pytest.raises(ArtifactExtractionError, match='failed to extract archive'):
        unpack_archive(archive, dest)

    assert not dest.exists()


def test_unpack_archive_removes_the_destination_when_extraction_fails(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / 'truncated.tar.gz'
    _create_tar(archive, {_WHEEL: b'x' * 4096})
    archive.write_bytes(archive.read_bytes()[: len(archive.read_bytes()) // 2])
    dest = tmp_path / 'dest'

    with pytest.raises(ArtifactExtractionError, match='failed to extract archive'):
        unpack_archive(archive, dest)

    assert not dest.exists()


# ============================================================================
# Wheelhouse fixtures
# ============================================================================


def _venv_steps(
    *,
    venv: int | Exception = 0,
    pip: int | Exception = 0,
    self_check: int | Exception = 0,
    observe: collections.abc.Callable[[list[str]], None] | None = None,
) -> Responder:
    """Answer for the three steps install() runs, dispatching on argv shape.

    A successful venv step materialises bin/python3 and bin/pip, which is what
    the real one leaves behind for the steps that follow. observe sees each argv
    before the call returns, which is how a test inspects the filesystem the
    subprocess would have seen.
    """

    def respond(argv: list[str]) -> int | Exception:
        if argv[1:3] == ['-m', 'venv']:
            outcome = venv
            if venv == 0:
                bin_dir = pathlib.Path(argv[3]) / 'bin'
                bin_dir.mkdir(parents=True, exist_ok=True)
                (bin_dir / 'python3').touch()
                (bin_dir / 'pip').touch()
        elif 'install' in argv:
            outcome = pip
        else:
            outcome = self_check
        if observe is not None:
            observe(argv)
        return outcome

    return respond


@pytest.fixture
def install_root(tmp_path: pathlib.Path) -> pathlib.Path:
    """Lay out the deployment tree a charm is expected to have created."""
    root = tmp_path / 'srv' / 'workload'
    (root / 'venvs').mkdir(parents=True)
    return root


@pytest.fixture
def wheelhouse(install_root: pathlib.Path, writable_root: None) -> Wheelhouse:
    return Wheelhouse(install_root, _IMPORT_NAME)


@pytest.fixture
def wheelhouse_tar(tmp_path: pathlib.Path) -> pathlib.Path:
    archive = tmp_path / 'wheelhouse.tar.gz'
    _create_tar(archive, {_WHEEL: b'fake wheel'})
    return archive


# ============================================================================
# Building a version
# ============================================================================


@pytest.mark.parametrize('invalid', ['', 'my-pkg', 'pkg.', '.pkg', 'pkg..sub', '1pkg', 'pkg sub'])
def test_wheelhouse_rejects_an_import_name_that_is_not_a_module_path(install_root: pathlib.Path, invalid: str) -> None:
    with pytest.raises(ValueError, match='import name'):
        Wheelhouse(install_root, invalid)


def test_install_builds_the_virtualenv_where_it_will_be_served_from(
    fake_subprocess: FakeSubprocess,
    wheelhouse: Wheelhouse,
    wheelhouse_tar: pathlib.Path,
    install_root: pathlib.Path,
) -> None:
    """Built at its final path, so no shebang or activation script has to be rewritten."""
    recorded = fake_subprocess(_venv_steps())

    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    venv_dir = install_root / 'venvs' / '1.0.0'
    stamp = venv_dir / '.wheelhouse-requirement'
    assert (venv_dir / 'bin' / 'python3').is_file()
    assert stamp.read_text(encoding='utf-8') == f'{_REQUIREMENT}\n'
    assert stat.S_IMODE(stamp.stat().st_mode) == 0o644
    # Building a version does not put it into service.
    assert wheelhouse.get_active_version() is None
    assert not (install_root / 'current').exists(follow_symlinks=False)

    venv_call, pip_call, check_call = (call.argv for call in recorded)
    assert venv_call == ['/usr/bin/python3', '-m', 'venv', str(venv_dir)]
    assert pip_call[0] == str(venv_dir / 'bin' / 'pip')
    assert pip_call[1:5] == ['install', '--isolated', '--no-index', '--find-links']
    assert pip_call[6:] == ['--force-reinstall', _REQUIREMENT]
    assert check_call == [str(venv_dir / 'bin' / 'python3'), '-c', f'import {_IMPORT_NAME}']


def test_install_feeds_pip_the_extracted_wheels_and_then_discards_them(
    fake_subprocess: FakeSubprocess,
    wheelhouse: Wheelhouse,
    wheelhouse_tar: pathlib.Path,
    install_root: pathlib.Path,
) -> None:
    seen_by_pip: list[list[str]] = []

    def observe(argv: list[str]) -> None:
        if 'install' not in argv:
            return
        wheels = pathlib.Path(argv[argv.index('--find-links') + 1])
        seen_by_pip.append(sorted(str(path.relative_to(wheels)) for path in wheels.rglob('*')))

    recorded = fake_subprocess(_venv_steps(observe=observe))

    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    assert seen_by_pip == [['wheelhouse', _WHEEL]]
    pip_call = recorded[1].argv
    wheels = pathlib.Path(pip_call[pip_call.index('--find-links') + 1])
    # The wheels are scratch space, outside the deployment tree and gone again.
    assert not wheels.exists()
    assert install_root not in wheels.parents


def test_install_subprocesses_are_bounded_and_free_of_the_charm_virtualenv(
    monkeypatch: pytest.MonkeyPatch,
    fake_subprocess: FakeSubprocess,
    wheelhouse: Wheelhouse,
    wheelhouse_tar: pathlib.Path,
) -> None:
    monkeypatch.setenv('VIRTUAL_ENV', '/var/lib/juju/agents/unit-x/charm/venv')
    monkeypatch.setenv('PYTHONPATH', '/var/lib/juju/agents/unit-x/charm/lib')
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy:3128')
    recorded = fake_subprocess(_venv_steps())

    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    for call in recorded:
        assert 'VIRTUAL_ENV' not in call.env
        assert 'PYTHONPATH' not in call.env
        assert call.env['HTTPS_PROXY'] == 'http://proxy:3128'
        assert call.timeout == 300


def test_install_is_a_no_op_when_the_version_is_already_installed(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path
) -> None:
    """A charm reconciling on every hook must not rebuild what is already there."""
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    recorded = fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    # Only the import check that established the existing build still works.
    assert [call.argv[1:] for call in recorded] == [['-c', f'import {_IMPORT_NAME}']]


def test_install_refuses_a_version_directory_it_did_not_build(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    """The tree may be what the workload is running from; it is not overwritten."""
    venv_dir = install_root / 'venvs' / '1.0.0'
    venv_dir.mkdir()
    (venv_dir / 'left-behind').write_text('previous contents')
    recorded = fake_subprocess(_venv_steps())

    with pytest.raises(WorkloadInstallError, match='already exists and is not a working install'):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    assert (venv_dir / 'left-behind').read_text() == 'previous contents'
    assert recorded == []


def test_install_refuses_to_create_the_venvs_directory(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    (install_root / 'venvs').rmdir()
    fake_subprocess(_venv_steps())

    with pytest.raises(WorkloadInstallError, match='failed to create'):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    assert not (install_root / 'venvs').exists()


@pytest.mark.parametrize(
    ('failure', 'message'),
    [
        ({'venv': 1}, 'virtualenv creation for 1.0.0 failed with exit status 1'),
        ({'venv': FileNotFoundError('/usr/bin/python3')}, 'failed to start virtualenv creation for 1.0.0'),
        ({'pip': 2}, "pip install of 'my-pkg==1.0.0' for 1.0.0 failed with exit status 2"),
        ({'pip': subprocess.TimeoutExpired(['pip'], 300)}, 'pip install .* did not finish within 300 seconds'),
        ({'self_check': 1}, 'self-check of 1.0.0 failed: my_pkg could not be imported'),
        ({'self_check': subprocess.TimeoutExpired(['python3'], 300)}, 'import of my_pkg did not finish within 300'),
    ],
)
def test_install_removes_the_virtualenv_when_a_step_fails(
    fake_subprocess: FakeSubprocess,
    wheelhouse: Wheelhouse,
    wheelhouse_tar: pathlib.Path,
    install_root: pathlib.Path,
    failure: dict[str, int | Exception],
    message: str,
) -> None:
    fake_subprocess(_venv_steps(**failure))  # type: ignore[arg-type]  # the parametrised keyword names one step

    with pytest.raises(WorkloadInstallError, match=message):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    # An incomplete virtualenv must not outlive the attempt that built it.
    assert not (install_root / 'venvs' / '1.0.0').exists()
    assert list((install_root / 'venvs').iterdir()) == []


def test_install_reports_pips_diagnosis(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path
) -> None:
    fake_subprocess(
        _venv_steps(pip=1),
        stderr=b'ERROR: No matching distribution found for my-pkg==1.0.0\n',
    )

    with pytest.raises(WorkloadInstallError, match='ERROR: No matching distribution found'):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)


def test_install_removes_the_virtualenv_when_the_requirement_stamp_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch,
    fake_subprocess: FakeSubprocess,
    wheelhouse: Wheelhouse,
    wheelhouse_tar: pathlib.Path,
    install_root: pathlib.Path,
) -> None:
    """A virtualenv with no stamp would be reinstalled forever; it is not kept."""
    fake_subprocess(_venv_steps())
    write_file = utils.open_file_secure

    def fail_on_the_stamp(path: pathlib.Path, **kwargs: object) -> typing.Any:
        if path.name == '.wheelhouse-requirement':
            raise OSError('No space left on device')
        return write_file(path, **kwargs)  # type: ignore[call-overload]  # the fake forwards the caller's keywords

    monkeypatch.setattr(utils, 'open_file_secure', fail_on_the_stamp)

    with pytest.raises(WorkloadInstallError, match='failed to write the requirement stamp'):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    assert not (install_root / 'venvs' / '1.0.0').exists()


def test_install_leaves_the_deployment_in_service_untouched_when_it_fails(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '0.9.0', _REQUIREMENT)
    wheelhouse.activate('0.9.0')

    fake_subprocess(_venv_steps(pip=1))
    with pytest.raises(WorkloadInstallError, match='pip install'):
        wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)

    assert wheelhouse.get_active_version() == '0.9.0'
    assert wheelhouse.is_active_version('0.9.0', _REQUIREMENT)
    assert not (install_root / 'venvs' / '1.0.0').exists()


def test_install_reports_an_archive_it_cannot_extract(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, install_root: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    recorded = fake_subprocess(_venv_steps())

    with pytest.raises(ArtifactExtractionError, match='archive file not found'):
        wheelhouse.install(tmp_path / 'absent.tar.gz', '1.0.0', _REQUIREMENT)

    assert not (install_root / 'venvs' / '1.0.0').exists()
    assert recorded == []


def test_install_rejects_a_malformed_version(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())

    with pytest.raises(ValueError, match='version'):
        wheelhouse.install(wheelhouse_tar, '../escape', _REQUIREMENT)

    assert list((install_root / 'venvs').iterdir()) == []


# ============================================================================
# Putting a version into service
# ============================================================================


def test_activate_points_current_at_the_version(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)
    wheelhouse.install(wheelhouse_tar, '2.0.0', _REQUIREMENT)

    wheelhouse.activate('1.0.0')
    # Relative, so the tree can be moved or bind-mounted elsewhere.
    assert os.readlink(install_root / 'current') == 'venvs/1.0.0'

    wheelhouse.activate('2.0.0')
    assert os.readlink(install_root / 'current') == 'venvs/2.0.0'
    assert wheelhouse.get_active_version() == '2.0.0'


def test_activate_replaces_a_stray_file_standing_where_current_belongs(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    """Repairing an errant regular file is valid; refusing to would need a racy check."""
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)
    (install_root / 'current').write_text('not a symlink')

    wheelhouse.activate('1.0.0')

    assert os.readlink(install_root / 'current') == 'venvs/1.0.0'


def test_activate_reuses_the_staged_name_left_by_an_interrupted_run(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)
    os.symlink('venvs/0.0.0', install_root / '.current.tmp')

    wheelhouse.activate('1.0.0')

    assert os.readlink(install_root / 'current') == 'venvs/1.0.0'
    assert not (install_root / '.current.tmp').exists(follow_symlinks=False)


def test_activate_refuses_a_version_that_is_not_installed(wheelhouse: Wheelhouse, install_root: pathlib.Path) -> None:
    with pytest.raises(WorkloadError, match='cannot activate 1.0.0'):
        wheelhouse.activate('1.0.0')

    assert not (install_root / 'current').exists(follow_symlinks=False)


def test_activate_reports_a_current_it_cannot_replace(
    fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path, install_root: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)
    (install_root / 'current').mkdir()

    with pytest.raises(WorkloadError, match='failed to point'):
        wheelhouse.activate('1.0.0')

    # The staged link is not left behind for the next run to trip over.
    assert not (install_root / '.current.tmp').exists(follow_symlinks=False)


@pytest.mark.parametrize('target', ['venvs/1.2.3', 'venvs/1.2.3/'])
def test_get_active_version_reads_the_link(install_root: pathlib.Path, target: str) -> None:
    os.symlink(target, install_root / 'current')

    assert Wheelhouse(install_root, _IMPORT_NAME).get_active_version() == '1.2.3'


def test_get_active_version_reports_nothing_without_a_link(install_root: pathlib.Path) -> None:
    wheelhouse = Wheelhouse(install_root, _IMPORT_NAME)
    assert wheelhouse.get_active_version() is None

    (install_root / 'current').write_text('not a symlink')
    assert wheelhouse.get_active_version() is None


# ============================================================================
# Deciding whether a deployment still works
# ============================================================================


@pytest.fixture
def active(fake_subprocess: FakeSubprocess, wheelhouse: Wheelhouse, wheelhouse_tar: pathlib.Path) -> Wheelhouse:
    """Return a wheelhouse with 1.0.0 built and in service."""
    fake_subprocess(_venv_steps())
    wheelhouse.install(wheelhouse_tar, '1.0.0', _REQUIREMENT)
    wheelhouse.activate('1.0.0')
    return wheelhouse


def test_is_active_version_accepts_a_working_deployment(fake_subprocess: FakeSubprocess, active: Wheelhouse) -> None:
    fake_subprocess(_venv_steps())

    assert active.is_active_version('1.0.0', _REQUIREMENT)


def test_is_active_version_rejects_a_version_that_was_never_activated(
    fake_subprocess: FakeSubprocess, active: Wheelhouse, wheelhouse_tar: pathlib.Path
) -> None:
    fake_subprocess(_venv_steps())
    active.install(wheelhouse_tar, '2.0.0', _REQUIREMENT)

    assert not active.is_active_version('2.0.0', _REQUIREMENT)


def test_is_active_version_rejects_a_changed_requirement(fake_subprocess: FakeSubprocess, active: Wheelhouse) -> None:
    """The tag says nothing about the extras or pins the venv was built with."""
    fake_subprocess(_venv_steps())

    assert not active.is_active_version('1.0.0', 'my-pkg[extra]==1.0.0')


def test_is_active_version_rejects_a_venv_that_cannot_import_the_workload(
    fake_subprocess: FakeSubprocess, active: Wheelhouse
) -> None:
    fake_subprocess(_venv_steps(self_check=1))

    assert not active.is_active_version('1.0.0', _REQUIREMENT)


def test_is_active_version_rejects_a_venv_whose_import_hangs(
    fake_subprocess: FakeSubprocess, active: Wheelhouse
) -> None:
    fake_subprocess(_venv_steps(self_check=subprocess.TimeoutExpired(['python3'], 300)))

    assert not active.is_active_version('1.0.0', _REQUIREMENT)


def test_is_active_version_rejects_a_venv_without_an_interpreter(
    active: Wheelhouse, install_root: pathlib.Path
) -> None:
    (install_root / 'venvs' / '1.0.0' / 'bin' / 'python3').unlink()

    assert not active.is_active_version('1.0.0', _REQUIREMENT)


def test_is_active_version_rejects_a_venv_whose_interpreter_cannot_be_run(
    fake_subprocess: FakeSubprocess, active: Wheelhouse
) -> None:
    fake_subprocess(_venv_steps(self_check=PermissionError('Permission denied')))

    assert not active.is_active_version('1.0.0', _REQUIREMENT)


# ============================================================================
# Pruning old versions
# ============================================================================


def _make_versions(venvs_dir: pathlib.Path, ages: dict[str, int]) -> None:
    """Create version directories with distinct modification times."""
    for version, mtime in ages.items():
        (venvs_dir / version).mkdir()
        os.utime(venvs_dir / version, (mtime, mtime))


def test_prune_keeps_the_version_in_service_and_the_newest_others(install_root: pathlib.Path) -> None:
    _make_versions(install_root / 'venvs', {'1.0.0': 100, '2.0.0': 200, '3.0.0': 300, '4.0.0': 400})
    os.symlink('venvs/3.0.0', install_root / 'current')

    assert Wheelhouse(install_root, _IMPORT_NAME).prune() == ['1.0.0', '2.0.0']
    assert sorted(path.name for path in (install_root / 'venvs').iterdir()) == ['3.0.0', '4.0.0']


def test_prune_keeps_the_version_in_service_even_when_it_is_the_oldest(install_root: pathlib.Path) -> None:
    """Pruning must never delete the tree the workload is running from."""
    _make_versions(install_root / 'venvs', {'1.0.0': 100, '2.0.0': 200, '3.0.0': 300, '4.0.0': 400})
    os.symlink('venvs/1.0.0', install_root / 'current')

    assert Wheelhouse(install_root, _IMPORT_NAME).prune() == ['2.0.0', '3.0.0']
    assert sorted(path.name for path in (install_root / 'venvs').iterdir()) == ['1.0.0', '4.0.0']


def test_prune_can_be_asked_to_keep_only_what_is_in_service(install_root: pathlib.Path) -> None:
    _make_versions(install_root / 'venvs', {'1.0.0': 100, '2.0.0': 200})
    os.symlink('venvs/1.0.0', install_root / 'current')

    assert Wheelhouse(install_root, _IMPORT_NAME).prune(keep=1) == ['2.0.0']
    assert [path.name for path in (install_root / 'venvs').iterdir()] == ['1.0.0']


def test_prune_keeps_the_newest_when_nothing_is_in_service(install_root: pathlib.Path) -> None:
    _make_versions(install_root / 'venvs', {'1.0.0': 100, '2.0.0': 200, '3.0.0': 300})

    assert Wheelhouse(install_root, _IMPORT_NAME).prune() == ['1.0.0']
    assert sorted(path.name for path in (install_root / 'venvs').iterdir()) == ['2.0.0', '3.0.0']


def test_prune_protects_nothing_extra_when_current_dangles(install_root: pathlib.Path) -> None:
    """A 'current' naming a version that is gone reserves no retention slot."""
    _make_versions(install_root / 'venvs', {'1.0.0': 100, '2.0.0': 200, '3.0.0': 300})
    os.symlink('venvs/9.9.9', install_root / 'current')

    assert Wheelhouse(install_root, _IMPORT_NAME).prune() == ['1.0.0']
    assert sorted(path.name for path in (install_root / 'venvs').iterdir()) == ['2.0.0', '3.0.0']


def test_prune_leaves_alone_what_is_not_a_version_directory(install_root: pathlib.Path) -> None:
    venvs = install_root / 'venvs'
    _make_versions(venvs, {'1.0.0': 100})
    (venvs / 'notes.txt').write_text('not a deployment')
    os.symlink('1.0.0', venvs / 'previous')

    assert Wheelhouse(install_root, _IMPORT_NAME).prune(keep=1) == []
    assert sorted(path.name for path in venvs.iterdir()) == ['1.0.0', 'notes.txt', 'previous']


def test_prune_rejects_a_retention_that_would_empty_the_tree(install_root: pathlib.Path) -> None:
    with pytest.raises(ValueError, match='keep must be at least 1'):
        Wheelhouse(install_root, _IMPORT_NAME).prune(keep=0)


def test_prune_reports_a_missing_venvs_directory(install_root: pathlib.Path) -> None:
    (install_root / 'venvs').rmdir()

    with pytest.raises(WorkloadError, match='failed to prune'):
        Wheelhouse(install_root, _IMPORT_NAME).prune()
