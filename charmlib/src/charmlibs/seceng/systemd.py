# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Management of a single systemd service unit.

A unit is named without its ``.service`` suffix, and the name is validated on
construction: that is what lets it be interpolated into both a systemctl
argument and a path under /etc/systemd/system with no further checking. No
directory is created here, because /etc/systemd/system belongs to the
distribution and a host missing it is not one to guess ownership on.
"""

from __future__ import annotations

__all__ = [
    'SystemDError',
    'SystemDService',
]

import collections.abc
import contextlib
import pathlib
import re
import subprocess
import typing

from . import utils

_SYSTEMCTL = '/usr/bin/systemctl'
_UNIT_DIR = pathlib.Path('/etc/systemd/system')
# systemd's unit name charset without the separators and metacharacters it
# would accept but a shell-free argument and a single path component must not
# carry. Requiring an alphanumeric first character also rules out '.' and '..'.
_NAME_PATTERN = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9:_.@-]*\Z')
# Bound for every systemctl call; without it a unit whose start job hangs would
# block the hook until Juju kills the whole dispatch.
_TIMEOUT_SECONDS = 300


class SystemDError(Exception):
    """Base error for systemd operations, safe for Juju status messages."""


class SystemDService:
    """A systemd service unit, named without its '.service' suffix."""

    def __init__(self, name: str):
        """Bind to the unit called name, or raise ValueError if it cannot be one."""
        if not _NAME_PATTERN.match(name):
            raise ValueError(
                f'service name {name!r} must start with a letter or digit and contain only letters, digits, and '
                "the characters ':_.@-'"
            )
        self.name = name
        self._unit_path = _UNIT_DIR / f'{name}.service'

    def is_active(self) -> bool:
        """Return whether systemd reports the unit as active.

        Inactive, failed, and unknown are all False. Failing to get an answer
        is not: SystemDError is raised when systemctl cannot be run or does not
        finish in time, so a broken host is never reported as a stopped
        service.
        """
        return self._systemctl('is-active', '--quiet', self.name, check=False) == 0

    def enable(self) -> None:
        """Enable the unit so systemd starts it at boot. Raises SystemDError."""
        self._systemctl('enable', self.name)

    def restart(self) -> None:
        """Restart the unit, starting it if it is not running. Raises SystemDError."""
        self._systemctl('restart', self.name)

    def daemon_reload(self) -> None:
        """Make systemd re-read every unit definition from disk.

        Not scoped to this unit: systemd offers no way to reload one. Raises
        SystemDError.
        """
        self._systemctl('daemon-reload')

    @contextlib.contextmanager
    def open_service_definition(self) -> collections.abc.Iterator[typing.TextIO]:
        """Yield a handle for writing this unit's definition, reloading systemd after.

        The definition is renamed into place at mode 0644 once the body
        completes, so systemd never reads a half-written unit and a body that
        raises leaves the previous definition untouched. The reload runs on
        clean exit, so a restart() that follows acts on what was just written.

        Raises OSError if the definition cannot be written, including
        FileNotFoundError when /etc/systemd/system does not exist, and
        SystemDError if the reload fails.
        """
        with utils.open_file_secure(self._unit_path, mode=0o644, create_parents=False, text=True) as definition:
            yield definition
        self.daemon_reload()

    def _systemctl(self, *arguments: str, check: bool = True) -> int:
        """Run systemctl with arguments and return its exit status.

        Raises SystemDError if systemctl cannot be executed or outlives its
        timeout, and, unless check is unset, if it exits non-zero.
        """
        command = ' '.join(arguments)
        try:
            result = subprocess.run(
                [_SYSTEMCTL, *arguments],
                check=False,
                capture_output=True,
                env=utils.clean_env(),
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as err:
            raise SystemDError(f'systemctl {command} did not finish within {_TIMEOUT_SECONDS} seconds') from err
        except OSError as err:
            raise SystemDError(f'failed to run systemctl {command}: {err}') from err
        if check and result.returncode != 0:
            raise SystemDError(
                f'systemctl {command} failed with exit status {result.returncode}{utils.stderr_detail(result.stderr)}'
            )
        return result.returncode
