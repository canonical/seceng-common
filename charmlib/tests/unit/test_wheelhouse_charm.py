# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Unit tests for wheelhouse installation in the SecEng charm base.

The filesystem operations that decide correctness, including the ``current``
symlink, stamps, per-version virtual environment detection, and pruning, run for
real against a temporary tree. Only operations that would reach the network,
apt, pip, or systemd are replaced, so the ordering and rollback properties under
test are the ones the charm actually has.
"""

import collections.abc
import contextlib
import dataclasses
import os
import pathlib
import subprocess
import typing

import ops
import pytest
from ops import testing

from charmlibs.seceng import template
from charmlibs.seceng import utils
from charmlibs.seceng import workload
from charmlibs.seceng.base import SecEngCharmBase


ASSET_URL = 'https://api.github.com/repos/canonical/agent/releases/assets/42'
CHECKSUM = 'a' * 64
TOKEN = 'ghp_test_token'


@pytest.fixture
def writable_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the secure writer create files under a test directory.

    ``utils.open_file_secure`` refuses to traverse a directory owned by a
    non-root user, which every pytest temporary directory is, so the stamp
    writer needs its file primitive replaced even though the stamp logic itself
    is exercised for real.
    """

    @contextlib.contextmanager
    def fake_open_file_secure(
        path: pathlib.Path,
        *,
        user: str | None = None,
        group: str | None = None,
        mode: int = 0o600,
        create_parents: bool = False,
        text: bool = True,
    ) -> collections.abc.Iterator[typing.TextIO]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as file:
            yield file
        os.chmod(path, mode)

    monkeypatch.setattr(utils, 'open_file_secure', fake_open_file_secure)


@dataclasses.dataclass
class Journal:
    """Record what the charm did, in order."""

    steps: list[str] = dataclasses.field(default_factory=list)
    rendered: list[dict[str, str] | None] = dataclasses.field(default_factory=list)
    service_running: bool = True

    def record(self, step: str) -> None:
        self.steps.append(step)


def _spec(tmp_path: pathlib.Path, **overrides: object) -> workload.Wheelhouse:
    """Return a wheelhouse specification rooted in a temporary directory."""
    fields: dict[str, object] = {
        'name': 'example-worker',
        'repo': 'canonical/example-worker',
        'install_root': tmp_path / 'opt' / 'example-worker',
    }
    fields.update(overrides)
    return workload.Wheelhouse(**fields)  # type: ignore[arg-type]  # heterogeneous test overrides


def _charm_class(spec: workload.Wheelhouse, journal: Journal) -> type[SecEngCharmBase]:
    """Return a charm class installing one wheelhouse and recording its steps."""

    class WheelhouseCharm(SecEngCharmBase):
        wheelhouse_install_list = [spec]

        def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
            journal.record('secrets')

    return WheelhouseCharm


def _patch_workload(
    monkeypatch: pytest.MonkeyPatch,
    journal: Journal,
    *,
    checksum: str | None = CHECKSUM,
    fail_at: str | None = None,
    failure: Exception | None = None,
    self_check_fails: bool = False,
) -> None:
    """Replace the network, pip, and systemd operations with recorders."""

    def step(name: str) -> None:
        journal.record(name)
        if name == fail_at:
            raise failure or workload.WheelhouseError(f'{name} failed')

    def fake_resolve_asset_url(repo: str, tag: str, asset_name: str, token: str) -> str:
        assert token == TOKEN
        step('resolve')
        return ASSET_URL

    def fake_download_asset(url: str, dest: pathlib.Path, token: str) -> None:
        assert token == TOKEN
        step('download')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b'tarball')

    def fake_fetch_checksum(repo: str, tag: str, asset_name: str, token: str) -> str | None:
        step('checksum')
        return checksum

    def fake_verify_sha256(path: pathlib.Path, expected: str) -> None:
        step('verify')

    def fake_unpack(tarball: pathlib.Path, dest: pathlib.Path) -> None:
        step('unpack')
        dest.mkdir(parents=True, exist_ok=True)
        (dest / 'agent-0.1.0-py3-none-any.whl').touch()
        tarball.unlink(missing_ok=True)

    def fake_create_venv(spec: workload.Wheelhouse, version: str) -> None:
        step('create-venv')
        python = spec.venv_python(version)
        python.parent.mkdir(parents=True, exist_ok=True)
        python.touch()

    def fake_pip_install(spec: workload.Wheelhouse, version: str) -> None:
        step('pip-install')

    def fake_self_check(spec: workload.Wheelhouse, version: str) -> None:
        step('self-check')
        if self_check_fails:
            raise workload.WheelhouseError(f'{spec.name} {version} failed its self-check: cannot import.')

    def fake_flip_current(spec: workload.Wheelhouse, version: str) -> None:
        step('flip')
        _real_flip_current(spec, version)

    def fake_service_running(name: str) -> bool:
        return journal.service_running

    _real_flip_current = workload.flip_current

    monkeypatch.setattr(workload, 'resolve_asset_url', fake_resolve_asset_url)
    monkeypatch.setattr(workload, 'download_asset', fake_download_asset)
    monkeypatch.setattr(workload, 'fetch_checksum', fake_fetch_checksum)
    monkeypatch.setattr(workload, 'verify_sha256', fake_verify_sha256)
    monkeypatch.setattr(workload, 'unpack_wheelhouse', fake_unpack)
    monkeypatch.setattr(workload, 'create_venv', fake_create_venv)
    monkeypatch.setattr(workload, 'pip_install_wheelhouse', fake_pip_install)
    monkeypatch.setattr(workload, 'self_check', fake_self_check)
    monkeypatch.setattr(workload, 'flip_current', fake_flip_current)
    monkeypatch.setattr(workload, 'service_running', fake_service_running)

    def fake_process(
        engine: template.TemplateEngine,
        *filepaths: pathlib.Path,
        dirty_secrets: set[str] = set(),
        installed: collections.abc.Mapping[str, str] | None = None,
    ) -> None:
        journal.record('templates')
        journal.rendered.append(None if installed is None else dict(installed))

    monkeypatch.setattr(template.TemplateEngine, 'process', fake_process)


def _context(
    spec: workload.Wheelhouse,
    journal: Journal,
) -> testing.Context[SecEngCharmBase]:
    """Return a scenario context for a charm installing one wheelhouse."""
    return testing.Context(
        _charm_class(spec, journal),
        config={
            'options': {
                'deployment': {'type': 'string'},
                'worker-version': {'type': 'string'},
                'source-credentials': {'type': 'secret'},
            },
        },
        meta={'name': 'wheelhouse-charm'},
    )


def _custom_acquire_context(
    spec: workload.Wheelhouse,
    journal: Journal,
) -> testing.Context[SecEngCharmBase]:
    """Return a scenario context for a charm overriding wheelhouse acquisition."""

    class CustomWheelhouseCharm(SecEngCharmBase):
        wheelhouse_install_list = [spec]

        def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
            journal.record('secrets')

        def _acquire_wheelhouse(self, spec: workload.Wheelhouse, version: str) -> str:
            journal.record('acquire')
            return 'custom-source'

    return testing.Context(
        CustomWheelhouseCharm,
        config={
            'options': {
                'deployment': {'type': 'string'},
                'worker-version': {'type': 'string'},
                'source-credentials': {'type': 'secret'},
            },
        },
        meta={'name': 'wheelhouse-charm'},
    )


def _state(
    context: testing.Context[SecEngCharmBase],
    *,
    version: str = 'v1',
    secret_content: dict[str, str] | None = None,
    include_secret: bool = True,
    stored: dict[str, object] | None = None,
) -> tuple[testing.State, testing.Secret | None]:
    """Return an input state with the worker version and credential configured."""
    secret = testing.Secret(secret_content if secret_content is not None else {'github-token': TOKEN})
    config: dict[str, str] = {'deployment': 'test'}
    if version:
        config['worker-version'] = version
    if include_secret:
        config['source-credentials'] = secret.id
    return (
        testing.State.from_context(
            context,
            leader=True,
            config=config,
            secrets={secret} if include_secret else set(),
        ),
        secret if include_secret else None,
    )


def _installed(spec: workload.Wheelhouse) -> tuple[str | None, str | None]:
    """Return the active version and the stamped version, from disk."""
    return workload.current_version(spec), workload.read_stamp(spec.version_stamp)


def test_install_activates_the_version_only_after_it_is_proven(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    state_out = context.run(context.on.config_changed(), state_in)

    # The flip is the last thing before the stamp, and templates render after
    # the install so the unit file and environment exist for the restart.
    assert journal.steps == [
        'resolve',
        'download',
        'checksum',
        'verify',
        'unpack',
        'create-venv',
        'pip-install',
        'self-check',
        'flip',
        'secrets',
        'templates',
    ]
    assert _installed(spec) == ('v1', 'v1')
    assert workload.read_stamp(spec.source_stamp) == ASSET_URL
    assert state_out.unit_status == testing.ActiveStatus('worker v1')


def test_templates_receive_the_active_version_as_the_digest(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    context.run(context.on.config_changed(), state_in)

    assert journal.rendered == [{'example-worker': 'v1'}]


def test_the_installed_tarball_is_not_left_behind(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal, fail_at='verify')
    context = _context(spec, journal)
    state_in, _ = _state(context)

    context.run(context.on.config_changed(), state_in)

    assert not list(spec.resolved_install_root.glob('*.tar.gz'))


def test_a_second_hook_with_the_same_version_reinstalls_nothing(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    state_mid = context.run(context.on.config_changed(), state_in)
    journal.steps.clear()
    context.run(context.on.config_changed(), state_mid)

    # The self-check still runs on the skip path, so a venv broken by hand is
    # noticed rather than assumed good.
    assert journal.steps == ['self-check', 'secrets', 'templates']


def test_a_broken_active_venv_is_reinstalled(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)

    journal.steps.clear()
    _patch_workload(monkeypatch, journal, self_check_fails=True)
    state_out = context.run(context.on.config_changed(), state_mid)

    assert journal.steps.count('pip-install') == 1
    assert 'flip' not in journal.steps
    assert spec.venv_python('v1').exists()
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert 'self-check' in state_out.unit_status.message


def test_upgrading_the_version_installs_it_and_keeps_the_previous_venv(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, secret = _state(context, version='v1')
    state_mid = context.run(context.on.config_changed(), state_in)

    state_out = context.run(
        context.on.config_changed(),
        dataclasses.replace(state_mid, config={**state_mid.config, 'worker-version': 'v2'}),
    )

    assert _installed(spec) == ('v2', 'v2')
    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['v1', 'v2']
    assert journal.rendered[-1] == {'example-worker': 'v2'}
    assert state_out.unit_status == testing.ActiveStatus('worker v2')


def test_a_third_version_prunes_the_oldest_but_keeps_the_rollback_target(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state, _ = _state(context, version='v1')
    for version in ('v1', 'v2', 'v3'):
        state = context.run(
            context.on.config_changed(),
            dataclasses.replace(state, config={**state.config, 'worker-version': version}),
        )
        os.utime(spec.venvs_dir / version, (1000 + int(version[1:]), 1000 + int(version[1:])))

    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['v2', 'v3']
    assert workload.current_version(spec) == 'v3'


@pytest.mark.parametrize(
    ('failure', 'expected'),
    [
        (
            workload.WheelhouseError('the wheelhouse archive contains no .whl files'),
            'the wheelhouse archive contains no .whl files',
        ),
        (
            subprocess.CalledProcessError(1, ['/opt/agent/venvs/v2/bin/pip', 'install']),
            'pip exited with status 1',
        ),
    ],
)
def test_a_failed_upgrade_leaves_the_previous_version_serving(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
    failure: Exception,
    expected: str,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='v1')
    state_mid = context.run(context.on.config_changed(), state_in)

    _patch_workload(monkeypatch, journal, fail_at='pip-install', failure=failure)
    state_out = context.run(
        context.on.config_changed(),
        dataclasses.replace(state_mid, config={**state_mid.config, 'worker-version': 'v2'}),
    )

    # current, both stamps, and therefore the template digest are untouched, so
    # the templated restart does not fire and the old worker keeps running.
    assert _installed(spec) == ('v1', 'v1')
    assert journal.rendered[-1] == {'example-worker': 'v1'}
    # The half-built venv is discarded: left behind, pruning would count it as a
    # retained version and evict the real rollback target.
    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['v1']
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert state_out.unit_status.message == f'worker install failed: {expected}'


def test_a_failed_self_check_does_not_activate_the_new_version(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='v1')
    state_mid = context.run(context.on.config_changed(), state_in)

    _patch_workload(monkeypatch, journal, self_check_fails=True)
    state_out = context.run(
        context.on.config_changed(),
        dataclasses.replace(state_mid, config={**state_mid.config, 'worker-version': 'v2'}),
    )

    assert _installed(spec) == ('v1', 'v1')
    assert spec.venv_python('v1').exists()
    assert not spec.venv_dir('v2').exists()
    assert isinstance(state_out.unit_status, testing.BlockedStatus)


def test_the_first_install_failing_leaves_nothing_active(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal, fail_at='resolve')
    context = _context(spec, journal)
    state_in, _ = _state(context)

    state_out = context.run(context.on.config_changed(), state_in)

    assert _installed(spec) == (None, None)
    assert journal.rendered == [{}]
    assert isinstance(state_out.unit_status, testing.BlockedStatus)


def test_an_absent_checksum_asset_fails_closed(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal, checksum=None)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    state_out = context.run(context.on.config_changed(), state_in)

    assert 'unpack' not in journal.steps
    assert _installed(spec) == (None, None)
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert 'sha256' in state_out.unit_status.message


def test_an_unset_version_blocks_before_any_retrieval(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='')

    state_out = context.run(context.on.config_changed(), state_in)

    assert journal.steps == ['secrets', 'templates']
    assert state_out.unit_status == testing.BlockedStatus('Set worker-version')


def test_a_version_that_would_escape_the_venv_directory_blocks(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='../../etc')

    state_out = context.run(context.on.config_changed(), state_in)

    assert 'resolve' not in journal.steps
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert 'not a valid release tag' in state_out.unit_status.message


@pytest.mark.parametrize(
    ('secret_content', 'include_secret', 'expected'),
    [
        (None, False, 'Set the source-credentials secret'),
        ({'unrelated': 'x'}, True, 'source-credentials secret has no github-token'),
    ],
)
def test_a_missing_or_wrong_credential_blocks_with_a_specific_message(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
    secret_content: dict[str, str] | None,
    include_secret: bool,
    expected: str,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, secret_content=secret_content, include_secret=include_secret)

    state_out = context.run(context.on.config_changed(), state_in)

    assert 'resolve' not in journal.steps
    assert state_out.unit_status == testing.BlockedStatus(expected)


def test_a_failed_venv_creation_leaves_nothing_for_pruning_to_mistake_for_a_rollback_target(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state, _ = _state(context, version='v1')
    for version in ('v1', 'v2'):
        state = context.run(
            context.on.config_changed(),
            dataclasses.replace(state, config={**state.config, 'worker-version': version}),
        )
        os.utime(spec.venvs_dir / version, (1000 + int(version[1:]), 1000 + int(version[1:])))

    # python3 -m venv can fail after creating the directory: a disk filling up
    # during ensurepip, a partially upgraded python3-venv, an OOM kill.
    def half_built_venv(spec: workload.Wheelhouse, version: str) -> typing.NoReturn:
        journal.record('create-venv')
        (spec.venv_dir(version) / 'bin').mkdir(parents=True)
        (spec.venv_dir(version) / 'pyvenv.cfg').touch()
        raise subprocess.CalledProcessError(1, ['/usr/bin/python3', '-m', 'venv'])

    monkeypatch.setattr(workload, 'create_venv', half_built_venv)
    state = context.run(
        context.on.config_changed(),
        dataclasses.replace(state, config={**state.config, 'worker-version': 'v3'}),
    )

    assert not spec.venv_dir('v3').exists()
    assert _installed(spec) == ('v2', 'v2')

    # Left behind, the half-built v3 would be the newest directory in venvs/, so
    # this next successful install would retain it as the "one previous" version
    # and delete v2, leaving a rollback target with no interpreter in it.
    _patch_workload(monkeypatch, journal)
    context.run(
        context.on.config_changed(),
        dataclasses.replace(state, config={**state.config, 'worker-version': 'v4'}),
    )

    assert sorted(entry.name for entry in spec.venvs_dir.iterdir()) == ['v2', 'v4']
    assert spec.venv_python('v2').exists()


def test_a_secret_that_exists_but_is_not_granted_blocks_instead_of_erroring_the_hook(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    # ops narrows to SecretNotFoundError only when Juju's stderr says "not
    # found"; a secret that was never granted to this application arrives as the
    # base ModelError, and letting that escape would error the hook and have
    # Juju retry a missing grant forever.
    def denied(model: ops.Model, **kwargs: object) -> typing.NoReturn:
        raise ops.ModelError('ERROR permission denied')

    monkeypatch.setattr(ops.Model, 'get_secret', denied)
    state_out = context.run(context.on.config_changed(), state_in)

    assert 'resolve' not in journal.steps
    assert state_out.unit_status == testing.BlockedStatus(
        'source-credentials secret cannot be read: check it exists and is granted to this application'
    )


def test_rotating_the_credential_reinstalls_the_worker(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    # The first install fails on an expired token, which is what rotation fixes.
    _patch_workload(monkeypatch, journal, fail_at='resolve')
    context = _context(spec, journal)
    state_in, secret = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)
    assert secret is not None

    journal.steps.clear()
    _patch_workload(monkeypatch, journal)
    state_out = context.run(context.on.secret_changed(secret), state_mid)

    assert journal.steps[:1] == ['resolve']
    assert _installed(spec) == ('v1', 'v1')
    assert state_out.unit_status == testing.ActiveStatus('worker v1')


def test_an_unrelated_secret_change_does_not_touch_the_worker(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)

    other = testing.Secret({'unrelated': 'value'})
    journal.steps.clear()
    context.run(
        context.on.secret_changed(other),
        dataclasses.replace(state_mid, secrets=state_mid.secrets | {other}),
    )

    assert journal.steps == ['secrets', 'templates']


def test_upgrade_charm_reinstalls_nothing_when_the_version_is_unchanged(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)

    journal.steps.clear()
    context.run(context.on.upgrade_charm(), state_mid)

    assert journal.steps == ['self-check', 'templates']
    assert _installed(spec) == ('v1', 'v1')


def test_status_reports_a_configured_version_that_is_not_installed(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='v1')
    state_mid = context.run(context.on.config_changed(), state_in)

    # Collect status without an intervening install, as a bare status hook does.
    state_out = context.run(
        context.on.update_status(),
        dataclasses.replace(state_mid, config={**state_mid.config, 'worker-version': 'v2'}),
    )

    assert state_out.unit_status == testing.BlockedStatus('worker v2 requested but v1 installed -- reinstall needed')


def test_status_reports_an_installed_worker_whose_service_is_down(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)

    journal.service_running = False
    state_out = context.run(context.on.update_status(), state_mid)

    assert state_out.unit_status == testing.BlockedStatus('worker v1 installed but example-worker is not running')


def test_status_prefers_a_recorded_failure_over_the_version_gap(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='v1')
    state_mid = context.run(context.on.config_changed(), state_in)

    _patch_workload(monkeypatch, journal, fail_at='download')
    state_out = context.run(
        context.on.config_changed(),
        dataclasses.replace(state_mid, config={**state_mid.config, 'worker-version': 'v2'}),
    )

    # A recorded cause explains the gap; "reinstall needed" would not.
    assert state_out.unit_status == testing.BlockedStatus('worker install failed: download failed')


def test_a_recovered_install_clears_the_recorded_failure(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal, fail_at='download')
    context = _context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)
    assert isinstance(state_mid.unit_status, testing.BlockedStatus)

    _patch_workload(monkeypatch, journal)
    state_out = context.run(context.on.config_changed(), state_mid)

    assert state_out.unit_status == testing.ActiveStatus('worker v1')


def test_a_charm_without_wheelhouses_contributes_no_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Contributing a status would take over from every imperative status the
    # existing consumers of this base class set.
    journal = Journal()
    context = testing.Context(
        SecEngCharmBase,
        config={'options': {'deployment': {'type': 'string'}}},
        meta={'name': 'plain-charm'},
    )
    monkeypatch.setattr(
        template.TemplateEngine,
        'process',
        lambda self, *paths, dirty_secrets=set(), installed=None: journal.record('templates'),
    )
    state_in = testing.State.from_context(context, leader=True, config={'deployment': 'test'})

    state_out = context.run(context.on.update_status(), state_in)

    assert isinstance(state_out.unit_status, testing.UnknownStatus)


def test_installed_worker_version_reads_the_stamp(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context)

    with context(context.on.config_changed(), state_in) as manager:
        manager.run()
        charm = typing.cast(SecEngCharmBase, manager.charm)
        assert charm.installed_worker_version(spec) == 'v1'


def test_an_overridden_acquire_wheelhouse_supplies_the_wheels(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _custom_acquire_context(spec, journal)
    state_in, _ = _state(context)

    state_out = context.run(context.on.config_changed(), state_in)

    for omitted in ('resolve', 'download', 'checksum', 'verify', 'unpack'):
        assert omitted not in journal.steps

    assert journal.steps == [
        'acquire',
        'create-venv',
        'pip-install',
        'self-check',
        'flip',
        'secrets',
        'templates',
    ]
    assert _installed(spec) == ('v1', 'v1')
    assert workload.read_stamp(spec.source_stamp) == 'custom-source'
    assert state_out.unit_status == testing.ActiveStatus('worker v1')


def test_an_overridden_acquire_wheelhouse_is_not_reached_for_an_active_version(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _custom_acquire_context(spec, journal)
    state_in, _ = _state(context)
    state_mid = context.run(context.on.config_changed(), state_in)

    journal.steps.clear()
    context.run(context.on.config_changed(), state_mid)

    assert 'acquire' not in journal.steps
    assert journal.steps == ['self-check', 'secrets', 'templates']


def test_an_active_version_does_not_block_when_credentials_are_unset(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    writable_root: None,
) -> None:
    # The release credential is read during acquisition, so a version that is
    # already active and healthy is never blocked by a credential that was
    # revoked or never set.
    spec = _spec(tmp_path)
    journal = Journal()
    _patch_workload(monkeypatch, journal)
    context = _context(spec, journal)
    state_in, _ = _state(context, version='v1', include_secret=True)
    state_mid = context.run(context.on.config_changed(), state_in)

    state_no_secret = dataclasses.replace(
        state_mid,
        config={'deployment': 'test', 'worker-version': 'v1'},
        secrets=frozenset[testing.Secret](),
    )
    state_out = context.run(context.on.config_changed(), state_no_secret)

    assert state_out.unit_status == testing.ActiveStatus('worker v1')
