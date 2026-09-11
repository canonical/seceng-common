# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Fixtures shared across the unit suites."""

import collections.abc
import contextlib
import errno
import os
import pathlib
import subprocess
import typing

import pytest

from charmlibs.seceng import utils

Responder = collections.abc.Callable[[list[str]], int | Exception]


class Call(typing.NamedTuple):
    """One recorded subprocess invocation."""

    argv: list[str]
    env: dict[str, str]
    timeout: float | None


class FakeSubprocess(typing.Protocol):
    """Installer for the ``subprocess.run`` stand-in, as returned by the fixture."""

    def __call__(self, respond: Responder, *, stderr: bytes = b'') -> list[Call]: ...


@pytest.fixture
def fake_subprocess(monkeypatch: pytest.MonkeyPatch) -> FakeSubprocess:
    """Return an installer that replaces ``subprocess.run`` with a recording stand-in.

    The installer takes a responder, called with each argv, that returns the
    exit status to report or an exception to raise from the call. The responder
    runs once the invocation has been recorded, so it may also stand in for the
    side effects of the real command, or observe the filesystem that command
    would have seen. The installer returns the list recording the invocations.
    """

    def install(respond: Responder, *, stderr: bytes = b'') -> list[Call]:
        recorded: list[Call] = []

        def fake_run(
            argv: collections.abc.Sequence[str],
            *,
            check: bool = False,
            capture_output: bool = False,
            env: dict[str, str] | None = None,
            timeout: float | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            command = list(argv)
            recorded.append(Call(command, env or {}, timeout))
            outcome = respond(command)
            if isinstance(outcome, Exception):
                raise outcome
            return subprocess.CompletedProcess(command, returncode=outcome, stdout=b'', stderr=stderr)

        monkeypatch.setattr(subprocess, 'run', fake_run)
        return recorded

    return install


@pytest.fixture
def writable_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the secure writer create files under a test directory.

    ``utils.open_file_secure`` refuses to traverse a directory owned by a
    non-root user, which every pytest temporary directory is, so callers that
    write through it need the primitive replaced even though their own logic is
    exercised for real. The replacement keeps the two guarantees those callers
    depend on: the file appears only once the body completes, and the parent
    directory is not created unless ``create_parents`` asks for it.
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
    ) -> collections.abc.Iterator[typing.TextIO | typing.BinaryIO]:
        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        elif not path.parent.is_dir():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path.parent))
        pending = path.with_name(f'.{path.name}.pending')
        file: typing.TextIO | typing.BinaryIO
        if text:
            file = pending.open('w', encoding='utf-8')
        else:
            file = pending.open('wb')
        try:
            with file:
                yield file
        except BaseException:
            pending.unlink(missing_ok=True)
            raise
        os.chmod(pending, mode)
        os.replace(pending, path)

    monkeypatch.setattr(utils, 'open_file_secure', fake_open_file_secure)
