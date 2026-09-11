# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Unit tests for the systemd service unit manager."""

from __future__ import annotations

import pathlib
import stat
import subprocess

import pytest
from conftest import FakeSubprocess

from charmlibs.seceng.systemd import SystemDError, SystemDService

_NAME = 'workload'
_DEFINITION = '[Unit]\nDescription=Test workload\n\n[Service]\nExecStart=/usr/bin/true\n'


@pytest.fixture
def unit_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Redirect /etc/systemd/system into the test's temporary tree."""
    directory = tmp_path / 'etc' / 'systemd' / 'system'
    directory.mkdir(parents=True)
    monkeypatch.setattr('charmlibs.seceng.systemd._UNIT_DIR', directory)
    return directory


# ============================================================================
# Unit naming
# ============================================================================


@pytest.mark.parametrize('name', ['workload', 'workload@1', 'a.b-c_d:e', '9lives'])
def test_service_accepts_a_systemd_unit_name(name: str) -> None:
    assert SystemDService(name).name == name


@pytest.mark.parametrize(
    'invalid',
    [
        '',
        '.',
        '..',
        '/',
        '../evil',
        'etc/workload',
        'workload/../../evil',
        'has space',
        'trailing ',
        'with\ttab',
        'with\nnewline',
        'workload;rm -rf /',
        'workload$(id)',
        'nul\x00byte',
        'ünit',
    ],
)
def test_service_rejects_a_name_that_is_not_a_single_unit(invalid: str) -> None:
    """The name reaches both an argv entry and a path component unescaped."""
    with pytest.raises(ValueError, match='service name'):
        SystemDService(invalid)


# ============================================================================
# Unit actions
# ============================================================================


@pytest.mark.parametrize(
    ('action', 'expected'),
    [
        ('enable', ['/usr/bin/systemctl', 'enable', _NAME]),
        ('restart', ['/usr/bin/systemctl', 'restart', _NAME]),
        ('daemon_reload', ['/usr/bin/systemctl', 'daemon-reload']),
    ],
)
def test_action_invokes_systemctl(fake_subprocess: FakeSubprocess, action: str, expected: list[str]) -> None:
    recorded = fake_subprocess(lambda _argv: 0)

    getattr(SystemDService(_NAME), action)()

    assert [call.argv for call in recorded] == [expected]


@pytest.mark.parametrize(('returncode', 'active'), [(0, True), (3, False), (4, False)])
def test_is_active_reports_what_systemd_says(fake_subprocess: FakeSubprocess, returncode: int, active: bool) -> None:
    recorded = fake_subprocess(lambda _argv: returncode)

    assert SystemDService(_NAME).is_active() is active
    assert [call.argv for call in recorded] == [['/usr/bin/systemctl', 'is-active', '--quiet', _NAME]]


def test_systemctl_is_bounded_and_free_of_the_charm_virtualenv(
    monkeypatch: pytest.MonkeyPatch, fake_subprocess: FakeSubprocess
) -> None:
    monkeypatch.setenv('VIRTUAL_ENV', '/var/lib/juju/agents/unit-x/charm/venv')
    monkeypatch.setenv('PYTHONPATH', '/var/lib/juju/agents/unit-x/charm/lib')
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy:3128')
    recorded = fake_subprocess(lambda _argv: 0)

    SystemDService(_NAME).restart()

    call = recorded[0]
    assert 'VIRTUAL_ENV' not in call.env
    assert 'PYTHONPATH' not in call.env
    assert call.env['HTTPS_PROXY'] == 'http://proxy:3128'
    assert call.timeout == 300


# ============================================================================
# Failure translation
# ============================================================================


def test_a_failed_action_reports_systemctls_diagnosis(fake_subprocess: FakeSubprocess) -> None:
    fake_subprocess(lambda _argv: 1, stderr=b'Failed to enable unit: Unit workload.service does not exist\n')

    with pytest.raises(SystemDError, match='systemctl enable workload failed with exit status 1: Failed to enable'):
        SystemDService(_NAME).enable()


def test_a_failed_action_without_output_reports_the_exit_status(fake_subprocess: FakeSubprocess) -> None:
    fake_subprocess(lambda _argv: 5)

    with pytest.raises(SystemDError, match='failed with exit status 5$'):
        SystemDService(_NAME).restart()


@pytest.mark.parametrize(
    ('outcome', 'message'),
    [
        (FileNotFoundError('/usr/bin/systemctl'), 'failed to run systemctl is-active'),
        (subprocess.TimeoutExpired(['/usr/bin/systemctl'], 300), 'did not finish within 300 seconds'),
    ],
)
def test_a_systemctl_that_never_answers_is_not_a_stopped_unit(
    fake_subprocess: FakeSubprocess, outcome: Exception, message: str
) -> None:
    """is_active must not report a broken host as an inactive service."""
    fake_subprocess(lambda _argv: outcome)

    with pytest.raises(SystemDError, match=message):
        SystemDService(_NAME).is_active()


# ============================================================================
# Unit definition authoring
# ============================================================================


def test_open_service_definition_writes_the_unit_then_reloads(
    fake_subprocess: FakeSubprocess, writable_root: None, unit_dir: pathlib.Path
) -> None:
    definition_path = unit_dir / f'{_NAME}.service'
    seen_at_reload: list[str] = []

    def observe_the_definition(_argv: list[str]) -> int:
        seen_at_reload.append(definition_path.read_text(encoding='utf-8'))
        return 0

    recorded = fake_subprocess(observe_the_definition)

    with SystemDService(_NAME).open_service_definition() as definition:
        definition.write(_DEFINITION)
        # Nothing is visible to systemd until the body completes.
        assert not definition_path.exists()

    assert definition_path.read_text(encoding='utf-8') == _DEFINITION
    assert stat.S_IMODE(definition_path.stat().st_mode) == 0o644
    assert [call.argv for call in recorded] == [['/usr/bin/systemctl', 'daemon-reload']]
    # The reload must come after the definition lands, or systemd reloads the
    # unit it already had.
    assert seen_at_reload == [_DEFINITION]


def test_open_service_definition_keeps_the_previous_unit_when_the_body_fails(
    fake_subprocess: FakeSubprocess, writable_root: None, unit_dir: pathlib.Path
) -> None:
    definition_path = unit_dir / f'{_NAME}.service'
    definition_path.write_text('[Service]\nExecStart=/usr/bin/previous\n', encoding='utf-8')
    recorded = fake_subprocess(lambda _argv: 0)

    with pytest.raises(RuntimeError, match='template rendering failed'):
        with SystemDService(_NAME).open_service_definition() as definition:
            definition.write('[Service]\nExecStart=/usr/bin/hal')
            raise RuntimeError('template rendering failed')

    assert definition_path.read_text(encoding='utf-8') == '[Service]\nExecStart=/usr/bin/previous\n'
    assert list(unit_dir.iterdir()) == [definition_path]
    assert recorded == []


def test_open_service_definition_refuses_to_create_the_unit_directory(
    monkeypatch: pytest.MonkeyPatch, fake_subprocess: FakeSubprocess, writable_root: None, tmp_path: pathlib.Path
) -> None:
    """A host without /etc/systemd/system is not one to invent a unit tree on."""
    monkeypatch.setattr('charmlibs.seceng.systemd._UNIT_DIR', tmp_path / 'etc' / 'systemd' / 'system')
    recorded = fake_subprocess(lambda _argv: 0)

    with pytest.raises(FileNotFoundError):
        with SystemDService(_NAME).open_service_definition() as definition:
            definition.write(_DEFINITION)

    assert not (tmp_path / 'etc').exists()
    assert recorded == []


def test_open_service_definition_reports_a_failed_reload(
    fake_subprocess: FakeSubprocess, writable_root: None, unit_dir: pathlib.Path
) -> None:
    fake_subprocess(lambda _argv: 1, stderr=b'Failed to reload daemon: Access denied\n')

    with pytest.raises(SystemDError, match='daemon-reload failed with exit status 1: Failed to reload'):
        with SystemDService(_NAME).open_service_definition() as definition:
            definition.write(_DEFINITION)

    # The definition itself landed; only systemd's view of it is stale.
    assert (unit_dir / f'{_NAME}.service').read_text(encoding='utf-8') == _DEFINITION
