# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

"""Tests for the template engine's action collection and dirty checks."""

import collections.abc
import os
import pathlib
import pwd
import tempfile

import pytest
import yaml
from ops import testing

from charmlibs.seceng.base import SecEngCharmBase


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
    entries: list[dict[str, object]],
) -> list[list[str]]:
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
