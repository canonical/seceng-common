# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import binascii
import collections.abc
import contextlib
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import tempfile

import pytest
import yaml
from ops import testing

from charmlibs.seceng.base import DebconfConfig, FileConfig, SecEngCharmBase, SecretConfig, SecretsRoot


@pytest.fixture
def context() -> collections.abc.Iterator[testing.Context[SecEngCharmBase]]:
    yield testing.Context(
        SecEngCharmBase,
        config={
            'options': {
                'deployment': {'type': 'string'},
                'test1': {'type': 'secret'},
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


def test_config_changed_state(context: testing.Context[SecEngCharmBase]) -> None:
    # Arrange:
    state_in = testing.State.from_context(
        context,
        leader=True,
        config={
            'deployment': 'test',
        },
    )

    # Act:
    state_out = context.run(context.on.config_changed(), state_in)

    # Assert:
    assert state_out.unit_status == testing.ActiveStatus('ready')


def test_install_secrets_file(context: testing.Context[SecEngCharmBase], tmpdir: pathlib.Path) -> None:
    with contextlib.ExitStack() as exit_stack:
        # Arrange:
        secret_test1_value_foo = binascii.hexlify(os.urandom(16)).decode('ascii')
        secret_test1 = testing.Secret(
            {
                'foo': secret_test1_value_foo,
            }
        )
        secret_test2_value_bar = binascii.hexlify(os.urandom(16)).decode('ascii')
        secret_test2 = testing.Secret(
            {
                'bar': secret_test2_value_bar,
            }
        )
        secrets_config = SecretsRoot(
            {
                'test1': SecretConfig(
                    user=pwd.getpwuid(os.getuid()).pw_name,
                    files=[
                        FileConfig(
                            name=str(tmpdir / 'directory!mode=700,uid' / 'test1-secret-file'),
                            permission='0o640',
                            template="Secret is {foo}",
                        )
                    ],
                )
            }
        )
        config_file_path = str(tmpdir / 'test-install-secrets.yaml')
        config_file = exit_stack.enter_context(open(config_file_path, 'w'))
        config_file.write(yaml.dump(secrets_config.model_dump()))  # type: ignore[no-untyped-call]
        config_file.close()
        SecEngCharmBase.secrets_config = config_file_path
        state_in = testing.State.from_context(
            context,
            leader=True,
            config={
                'test1': f'{secret_test1.id}',
                'deployment': 'test',
            },
            secrets={
                secret_test1,
                secret_test2,
            },
        )

        # Act:
        state_out = context.run(context.on.config_changed(), state_in)

        # Assert:
        test1_secret_file = exit_stack.enter_context(open(str(tmpdir / 'directory' / 'test1-secret-file'), 'r'))
        assert test1_secret_file.read() == f"Secret is {secret_test1_value_foo}"
        assert stat.S_IMODE(os.stat(test1_secret_file.fileno()).st_mode) == 0o640
        assert state_out.unit_status == testing.ActiveStatus('ready')


def test_install_secrets_debconf(context: testing.Context[SecEngCharmBase], tmpdir: pathlib.Path) -> None:
    with contextlib.ExitStack() as exit_stack:
        # Arrange:
        secret_test1_value_foo = binascii.hexlify(os.urandom(16)).decode('ascii')
        secret_test1 = testing.Secret(
            {
                'foo': secret_test1_value_foo,
            }
        )
        secret_test2_value_bar = binascii.hexlify(os.urandom(16)).decode('ascii')
        secret_test2 = testing.Secret(
            {
                'bar': secret_test2_value_bar,
            }
        )
        secrets_config = SecretsRoot(
            {
                'test1': SecretConfig(
                    debconf=[
                        DebconfConfig(
                            name='namespace/secret-option',
                            package='some-package',
                            template="Secret is {foo}\nmultiline test",
                        )
                    ],
                )
            }
        )
        config_file_path = str(tmpdir / 'test-install-secrets.yaml')
        config_file = exit_stack.enter_context(open(config_file_path, 'w'))
        config_file.write(yaml.dump(secrets_config.model_dump()))  # type: ignore[no-untyped-call]
        config_file.close()
        SecEngCharmBase.secrets_config = config_file_path
        state_in = testing.State.from_context(
            context,
            leader=True,
            config={
                'test1': f'{secret_test1.id}',
                'deployment': 'test',
            },
            secrets={
                secret_test1,
                secret_test2,
            },
        )

        debconf_db_path = str(tmpdir / 'debconf.dat')
        os.environ['DEBCONF_DB_REPLACE'] = f'File{{filename:{debconf_db_path} backup:no}}'
        exit_stack.callback(os.environ.pop, 'DEBCONF_DB_REPLACE')

        # Act:
        state_out = context.run(context.on.config_changed(), state_in)

        # Assert:
        debconf_output = subprocess.check_output(
            ['debconf-communicate'],
            input='GET namespace/secret-option',
            text=True,
            encoding=sys.stdin.encoding,
        ).splitlines()
        assert len(debconf_output) == 1
        code, rest = debconf_output[0].split(' ', 1)
        assert code == '0'
        debconf_secret = subprocess.check_output(
            ['debconf-escape', '-u'],
            input=rest,
            text=True,
            encoding=sys.stdin.encoding,
        )
        assert debconf_secret == f"Secret is {secret_test1_value_foo}"
        assert state_out.unit_status == testing.ActiveStatus('ready')
