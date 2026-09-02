# Copyright 2026 Luci Stanescu
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://documentation.ubuntu.com/ops/latest/explanation/testing/

import collections.abc
import contextlib
import functools
import os
import pwd

import pytest
from ops import testing

from charm import SecEngServerCharm
from charmlibs.seceng import utils


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch) -> collections.abc.Iterator[testing.Context[SecEngServerCharm]]:
    user = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(utils, 'open_file_secure', functools.partial(utils.open_file_secure, user=user))

    with contextlib.ExitStack():
        SecEngServerCharm.templates = []
        yield testing.Context(SecEngServerCharm)


def test_start(context: testing.Context[SecEngServerCharm]) -> None:
    # Arrange:
    state_in = testing.State.from_context(context, leader=True)
    state_in.config['deployment'] = 'test'

    # Act:
    state_out = context.run(context.on.config_changed(), state_in)

    # Assert:
    assert state_out.unit_status == testing.ActiveStatus('ready')
