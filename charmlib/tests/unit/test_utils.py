# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Tests for the subprocess helpers."""

from __future__ import annotations

import os

import pytest

from charmlibs.seceng import utils


def test_clean_env_inherits_ambient_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HTTP_PROXY', 'http://proxy:3128')
    monkeypatch.setenv('JUJU_UNIT_NAME', 'my-charm/0')

    env = utils.clean_env()

    assert env['HTTP_PROXY'] == 'http://proxy:3128'
    assert env['JUJU_UNIT_NAME'] == 'my-charm/0'
    assert env['PATH'] == os.environ['PATH']


def test_clean_env_strips_interpreter_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('VIRTUAL_ENV', '/home/user/venv')
    monkeypatch.setenv('PYTHONPATH', '/home/user/lib')

    env = utils.clean_env()

    assert 'VIRTUAL_ENV' not in env
    assert 'PYTHONPATH' not in env


def test_clean_env_does_not_mutate_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('VIRTUAL_ENV', '/home/user/venv')

    utils.clean_env()

    assert os.environ['VIRTUAL_ENV'] == '/home/user/venv'


@pytest.mark.parametrize(
    ('stderr', 'expected'),
    [
        (
            b'Warning: unit changed on disk\nFailed to enable unit: no such unit\n',
            ': Failed to enable unit: no such unit',
        ),
        (b'  ERROR: no matching distribution  \n\n', ': ERROR: no matching distribution'),
        (b'\n   \n', ''),
        (b'', ''),
        (b'\xff invalid utf-8', ': \ufffd invalid utf-8'),
    ],
)
def test_stderr_detail_reports_the_last_meaningful_line(stderr: bytes, expected: str) -> None:
    assert utils.stderr_detail(stderr) == expected


def test_stderr_detail_truncates_a_line_too_long_for_a_status_message() -> None:
    assert utils.stderr_detail(b'x' * 500) == ': ' + 'x' * 200
