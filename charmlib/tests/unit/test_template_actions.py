# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

"""Tests for the template engine's post-render actions.

An action is what a templated file does to the system once its content actually
changed. These tests cover parsing, identity, and the order in which the engine
merges the actions declared by successive entries and executes them; the
change-driven dispatch itself belongs to the engine and is covered through the
charm.
"""

import collections.abc
import os
import pathlib
import pwd
import subprocess
import tempfile
import typing

import pytest
import yaml
from ops import testing

from charmlibs.seceng.base import SecEngCharmBase
from charmlibs.seceng.template import (
    Action,
    DpkgReconfigureAction,
    SystemctlDaemonReloadAction,
    SystemctlEnableAction,
    SystemctlRestartAction,
)


def test_parse_daemon_reload() -> None:
    assert Action.parse('systemctl:daemon-reload') == SystemctlDaemonReloadAction()


def test_parse_restart_carries_the_service_name() -> None:
    action = Action.parse('systemctl:restart:example-worker')
    assert isinstance(action, SystemctlRestartAction)
    assert action.service == 'example-worker'


def test_parse_restart_preserves_colons_in_the_service_name() -> None:
    action = Action.parse('systemctl:restart:svc:a:b')
    assert isinstance(action, SystemctlRestartAction)
    assert action.service == 'svc:a:b'


def test_parse_dpkg_reconfigure() -> None:
    assert Action.parse('dpkg-reconfigure:postfix') == DpkgReconfigureAction('postfix')


def test_restart_does_not_collide_with_daemon_reload() -> None:
    """Both start 'systemctl:', so the parse order must keep them distinct."""
    assert Action.parse('systemctl:daemon-reload') != Action.parse('systemctl:restart:daemon-reload')
    assert isinstance(Action.parse('systemctl:restart:daemon-reload'), SystemctlRestartAction)


def test_parse_enable_carries_the_service_name() -> None:
    action = Action.parse('systemctl:enable:example-worker')
    assert isinstance(action, SystemctlEnableAction)
    assert action.service == 'example-worker'


def test_enable_and_restart_of_one_service_are_distinct_actions() -> None:
    """Both dedupe on the service name, so they must not collapse into each other."""
    assert SystemctlEnableAction('agent') != SystemctlRestartAction('agent')
    assert len({SystemctlEnableAction('agent'), SystemctlRestartAction('agent')}) == 2


def test_enable_execute_shells_out_to_systemctl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        'charmlibs.seceng.template.subprocess.check_call',
        lambda cmd, *a, **kw: typing.cast(int, calls.append(cmd)),
    )
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 0)

    SystemctlEnableAction('agent').execute()

    assert calls == [['systemctl', 'enable', 'agent']]


def test_enable_execute_is_skipped_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> int:
        raise AssertionError('must not shell out when not running as root')

    monkeypatch.setattr('charmlibs.seceng.template.subprocess.check_call', refuse)
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 1000)

    SystemctlEnableAction('agent').execute()  # must not raise


def test_enable_rejects_an_empty_service() -> None:
    with pytest.raises(ValueError, match='service must not be empty'):
        SystemctlEnableAction('')


@pytest.mark.parametrize(
    'action',
    [
        'systemctl:restart',
        'systemctl:reboot',
        'systemctl',
        'restart:agent',
        '',
        'systemctl:restart:',
        'systemctl:enable',
        'systemctl:enable:',
    ],
)
def test_unsupported_actions_are_rejected(action: str) -> None:
    with pytest.raises(ValueError):
        Action.parse(action)


def test_restart_actions_dedupe_by_service() -> None:
    """The engine collects actions into a set, so two files may name one service."""
    first = SystemctlRestartAction('agent')
    second = SystemctlRestartAction('agent')
    other = SystemctlRestartAction('other-agent')
    assert first == second
    assert first != other
    assert first != SystemctlDaemonReloadAction()
    assert len({first, second, other}) == 2


def test_restart_execute_shells_out_to_systemctl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        'charmlibs.seceng.template.subprocess.check_call',
        lambda cmd, *a, **kw: typing.cast(int, calls.append(cmd)),
    )
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 0)

    SystemctlRestartAction('agent').execute()

    assert calls == [['systemctl', 'restart', 'agent']]


def test_restart_execute_is_skipped_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> int:
        raise AssertionError('must not shell out when not running as root')

    monkeypatch.setattr('charmlibs.seceng.template.subprocess.check_call', refuse)
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 1000)

    SystemctlRestartAction('agent').execute()  # must not raise


def test_restart_rejects_an_empty_service() -> None:
    with pytest.raises(ValueError, match='service must not be empty'):
        SystemctlRestartAction('')


def test_restart_propagates_a_failed_systemctl(monkeypatch: pytest.MonkeyPatch) -> None:
    """A restart that fails must not be swallowed: the workload is down."""

    def fail(cmd: list[str], *args: object, **kwargs: object) -> int:
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr('charmlibs.seceng.template.subprocess.check_call', fail)
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 0)

    with pytest.raises(subprocess.CalledProcessError):
        SystemctlRestartAction('agent').execute()


@pytest.fixture
def context() -> collections.abc.Iterator[testing.Context[SecEngCharmBase]]:
    yield testing.Context(
        SecEngCharmBase,
        config={
            'options': {
                'deployment': {'type': 'string'},
            },
        },
        meta={
            'name': 'SecEngCharmBase',
        },
    )


@pytest.fixture
def tmpdir() -> collections.abc.Iterator[pathlib.Path]:
    with tempfile.TemporaryDirectory() as tmpdir_path:
        yield pathlib.Path(tmpdir_path)


def _record_check_call(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every argv the engine executes, patching the seam tests use."""
    calls: list[list[str]] = []

    def record(cmd: list[str], *args: object, **kwargs: object) -> int:
        calls.append(cmd)
        return 0

    monkeypatch.setattr('charmlibs.seceng.template.subprocess.check_call', record)
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 0)
    return calls


def _run_templates(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    entries: list[dict[str, typing.Any]],
) -> list[list[str]]:
    """Render ``entries`` through the engine and return the argv it executed.

    Each entry's file is written under ``tmpdir/directory``; the templates
    config is attached to the charm and a config-changed is run.
    """
    calls = _record_check_call(monkeypatch)
    rendered_entries = []
    for index, entry in enumerate(entries):
        rendered_entries.append(
            {
                'name': str(tmpdir / 'directory!mode=700,uid' / f'file{index}'),
                'user': pwd.getpwuid(os.getuid()).pw_name,
                'permission': '0o640',
                **entry,
            }
        )
    config_file_path = tmpdir / 'templates.yaml'
    with config_file_path.open('w') as config_file:
        config_file.write(yaml.dump({'files': rendered_entries}))  # type: ignore[no-untyped-call]
    monkeypatch.setattr(SecEngCharmBase, 'templates', [config_file_path])
    state_in = testing.State.from_context(
        context,
        leader=True,
        config={
            'deployment': 'test',
        },
    )
    context.run(context.on.config_changed(), state_in)
    return calls


def test_single_entry_actions_execute_in_declaration_order(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {
                'template': '[Unit]\nDescription=worker\n',
                'actions': [
                    'dpkg-reconfigure:first',
                    'systemctl:daemon-reload',
                    'dpkg-reconfigure:second',
                ],
            },
        ],
    )

    assert calls == [
        ['dpkg-reconfigure', '-fnoninteractive', 'first'],
        ['systemctl', 'daemon-reload'],
        ['dpkg-reconfigure', '-fnoninteractive', 'second'],
    ]


def test_duplicate_actions_across_entries_are_collapsed(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {'template': 'one\n', 'actions': ['systemctl:daemon-reload', 'dpkg-reconfigure:worker']},
            {'template': 'two\n', 'actions': ['systemctl:daemon-reload', 'dpkg-reconfigure:worker']},
        ],
    )

    assert calls == [
        ['systemctl', 'daemon-reload'],
        ['dpkg-reconfigure', '-fnoninteractive', 'worker'],
    ]


def test_unchanged_file_entry_does_not_repeat_actions(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_check_call(monkeypatch)
    source = tmpdir / 'source'
    source.write_text('unit\n')
    rendered = tmpdir / 'directory' / 'unit'
    config_file_path = tmpdir / 'templates.yaml'
    with config_file_path.open('w') as config_file:
        config_file.write(
            yaml.dump(
                {
                    'files': [
                        {
                            'name': str(tmpdir / 'directory!mode=700,uid' / 'unit'),
                            'user': pwd.getpwuid(os.getuid()).pw_name,
                            'permission': '0o640',
                            'file': str(source),
                            'actions': ['systemctl:daemon-reload'],
                        },
                    ],
                }
            )  # type: ignore[no-untyped-call]
        )
    monkeypatch.setattr(SecEngCharmBase, 'templates', [config_file_path])
    state_in = testing.State.from_context(
        context,
        leader=True,
        config={
            'deployment': 'test',
        },
    )

    state_out = context.run(context.on.config_changed(), state_in)
    assert calls == [['systemctl', 'daemon-reload']]

    calls.clear()
    context.run(context.on.config_changed(), state_out)

    assert calls == []
    assert rendered.read_text() == 'unit\n'


def test_documented_merge_example_ordering(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin the merge contract described by the comment in ``update_actions``.

    The comment specifies: actions A, B, C, A merged with new_actions C, B, A
    gives A, B, C, B, A. Reached through the engine with a first entry
    declaring A, B, C, A, which leaves the collected actions holding exactly
    A, B, C, A, followed by a second entry declaring C, B, A. A is a
    dpkg-reconfigure, B an enable, C a restart.
    """
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {
                'template': 'one\n',
                'actions': [
                    'dpkg-reconfigure:pkg',
                    'systemctl:enable:svc',
                    'systemctl:restart:svc',
                    'dpkg-reconfigure:pkg',
                ],
            },
            {
                'template': 'two\n',
                'actions': ['systemctl:restart:svc', 'systemctl:enable:svc', 'dpkg-reconfigure:pkg'],
            },
        ],
    )

    assert calls == [
        ['dpkg-reconfigure', '-fnoninteractive', 'pkg'],
        ['systemctl', 'enable', 'svc'],
        ['systemctl', 'restart', 'svc'],
        ['systemctl', 'enable', 'svc'],
        ['dpkg-reconfigure', '-fnoninteractive', 'pkg'],
    ]


def test_empty_actions_merge_preserves_declared_order(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Merging into an empty actions deque must preserve the declared order.

    Regression test: the merge left search_index pointing at the position it
    had just filled, so every later insert landed before its predecessor and
    an initially empty deque came out completely reversed.
    """
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {
                'template': 'one\n',
                'actions': [
                    'systemctl:enable:first',
                    'systemctl:enable:second',
                    'systemctl:enable:third',
                ],
            },
        ],
    )

    assert calls == [
        ['systemctl', 'enable', 'first'],
        ['systemctl', 'enable', 'second'],
        ['systemctl', 'enable', 'third'],
    ]


def test_restart_declared_again_is_not_duplicated(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entries redeclaring restart must dedupe, not stack extra restarts."""
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {'template': 'one\n', 'actions': ['systemctl:restart:agent']},
            {'template': 'two\n', 'actions': ['systemctl:restart:agent']},
            {'template': 'three\n', 'actions': ['systemctl:restart:agent']},
        ],
    )

    assert calls == [['systemctl', 'restart', 'agent']]


def test_consumer_unit_file_actions_execute_in_declared_order(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The consumer case: daemon-reload, enable, restart, exactly that order.

    A unit-file entry declares the three actions in that order. Reversed, the
    service is restarted from systemd's cached view of the unit file, so a unit
    change takes effect only at some later restart, and on first install enable
    runs before the unit definitions are reloaded.
    """
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {
                'template': '[Unit]\nDescription=example-worker\n',
                'actions': [
                    'systemctl:daemon-reload',
                    'systemctl:enable:example-worker',
                    'systemctl:restart:example-worker',
                ],
            },
        ],
    )

    assert calls == [
        ['systemctl', 'daemon-reload'],
        ['systemctl', 'enable', 'example-worker'],
        ['systemctl', 'restart', 'example-worker'],
    ]


def test_multi_entry_restart_only_entries_execute_exactly_three_actions(
    context: testing.Context[SecEngCharmBase],
    tmpdir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trio entry followed by restart-only entries: exactly three actions.

    The restart-only entries dedupe against the trio's restart, so the run
    must execute exactly three actions, in the trio's declared order.
    """
    calls = _run_templates(
        context,
        tmpdir,
        monkeypatch,
        [
            {
                'template': 'one\n',
                'actions': [
                    'systemctl:daemon-reload',
                    'systemctl:enable:agent',
                    'systemctl:restart:agent',
                ],
            },
            {'template': 'two\n', 'actions': ['systemctl:restart:agent']},
            {'template': 'three\n', 'actions': ['systemctl:restart:agent']},
        ],
    )

    assert len(calls) == 3
    assert calls == [
        ['systemctl', 'daemon-reload'],
        ['systemctl', 'enable', 'agent'],
        ['systemctl', 'restart', 'agent'],
    ]
