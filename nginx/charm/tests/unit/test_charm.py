# Copyright 2026 Luci Stanescu
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://documentation.ubuntu.com/ops/latest/explanation/testing/

import collections.abc
import contextlib
import functools
import os
import pathlib
import pwd
import tempfile

import pytest
from ops import testing

from charm import SecEngNginxCharm
from charmlibs.seceng import utils


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch) -> collections.abc.Iterator[testing.Context[SecEngNginxCharm]]:
    user = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(utils, 'open_file_secure', functools.partial(utils.open_file_secure, user=user))

    with contextlib.ExitStack() as exit_stack:
        SecEngNginxCharm.package_install_list = []
        SecEngNginxCharm.templates = []

        tmpdir = exit_stack.enter_context(tempfile.TemporaryDirectory())
        relative_config_dir = SecEngNginxCharm.nginx_config_dir
        relative_config_dir = relative_config_dir.relative_to(relative_config_dir.anchor)
        SecEngNginxCharm.nginx_config_dir = pathlib.Path(tmpdir / relative_config_dir)

        os.makedirs(SecEngNginxCharm.nginx_config_dir / 'sites-enabled', exist_ok=True)

        yield testing.Context(SecEngNginxCharm)


def test_start(context: testing.Context[SecEngNginxCharm]) -> None:
    # Arrange:
    state_in = testing.State.from_context(context, leader=True)
    state_in.config['deployment'] = 'test'
    state_in.config['default-server-config'] = 'FIXME'

    # Act:
    state_out = context.run(context.on.config_changed(), state_in)

    # Assert:
    assert state_out.unit_status == testing.BlockedStatus('no server')
