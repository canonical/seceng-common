# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import collections.abc

import pytest
from ops import testing

from charmlibs.seceng.base import SecEngCharmBase


@pytest.fixture
def context() -> collections.abc.Iterator[testing.Context[SecEngCharmBase]]:
    yield testing.Context(SecEngCharmBase, meta={'name': 'SecEngCharmBase'})


def test_config_changed_state(context: testing.Context[SecEngCharmBase]) -> None:
    # Arrange:
    state_in = testing.State.from_context(context, leader=True)

    # Act:
    state_out = context.run(context.on.config_changed(), state_in)

    # Assert:
    assert state_out.unit_status == testing.ActiveStatus('ready')
