# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

"""Tests for secret reads while building a template context."""

import logging
import os
import pathlib
import pwd
import typing

import ops
import pytest
import yaml
from ops import testing

from charmlibs.seceng.base import SecEngCharmBase
from charmlibs.seceng.template import TemplateError


class SecretTemplateCharm(SecEngCharmBase):
    """Charm fixture for testing template secret reads."""

    def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
        pass

    def _install_templates(self, *, dirty_secrets: set[str] = set()) -> None:
        self.template_engine.process(*self.templates, dirty_secrets=dirty_secrets)


@pytest.fixture
def context() -> testing.Context[SecretTemplateCharm]:
    return testing.Context(
        SecretTemplateCharm,
        config={
            'options': {
                'deployment': {'type': 'string'},
                'source-credentials': {'type': 'secret'},
            },
        },
        meta={'name': 'secret-template-charm'},
    )


def _state(
    context: testing.Context[SecretTemplateCharm],
    secret: testing.Secret | None = None,
) -> testing.State:
    config = {'deployment': 'test'}
    secrets: set[testing.Secret] = set()
    if secret is not None:
        config['source-credentials'] = secret.id
        secrets.add(secret)
    return testing.State.from_context(context, leader=True, config=config, secrets=secrets)


def _attach_template(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    *,
    silentfail: bool | None,
    expression: str,
) -> pathlib.Path:
    rendered = tmp_path / 'directory!mode=700,uid' / 'rendered'
    entry: dict[str, object] = {
        'name': str(rendered),
        'user': pwd.getpwuid(os.getuid()).pw_name,
        'permission': '0o640',
        'template': expression,
    }
    if silentfail is not None:
        entry['silentfail'] = silentfail
    config_file = tmp_path / 'templates.yaml'
    config_file.write_text(
        yaml.dump({'files': [entry]})  # type: ignore[no-untyped-call]
    )
    monkeypatch.setattr(SecretTemplateCharm, 'templates', [config_file])
    return tmp_path / 'directory' / 'rendered'


def _deny_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(model: ops.Model, **kwargs: object) -> typing.NoReturn:
        raise ops.ModelError('ERROR permission denied')

    monkeypatch.setattr(ops.Model, 'get_secret', denied)


def test_unreadable_secret_skips_a_silentfail_entry(
    context: testing.Context[SecretTemplateCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    secret = testing.Secret({'token': 'unused'})
    rendered = _attach_template(
        monkeypatch,
        tmp_path,
        silentfail=True,
        expression="VALUE={secret['source-credentials']}\n",
    )
    _deny_secret(monkeypatch)

    context.run(context.on.config_changed(), _state(context, secret))

    assert not rendered.exists(), 'an unreadable silentfail secret must not render a file'


def test_unreadable_secret_warning_names_the_option(
    context: testing.Context[SecretTemplateCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = testing.Secret({'token': 'unused'})
    _attach_template(
        monkeypatch,
        tmp_path,
        silentfail=True,
        expression="VALUE={secret['source-credentials']}\n",
    )
    _deny_secret(monkeypatch)

    caplog.set_level(logging.WARNING)
    context.run(context.on.config_changed(), _state(context, secret))

    assert any("'source-credentials'" in record.message for record in caplog.records), (
        'the warning must name the configuration option'
    )


def test_unreadable_secret_without_silentfail_still_raises_template_error(
    context: testing.Context[SecretTemplateCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    secret = testing.Secret({'token': 'unused'})
    _attach_template(
        monkeypatch,
        tmp_path,
        silentfail=None,
        expression="VALUE={secret['source-credentials']}\n",
    )
    _deny_secret(monkeypatch)
    monkeypatch.setenv('SCENARIO_BARE_CHARM_ERRORS', 'true')

    with pytest.raises(TemplateError):
        context.run(context.on.config_changed(), _state(context, secret))


def test_readable_secret_renders_the_secret_value(
    context: testing.Context[SecretTemplateCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    secret = testing.Secret({'token': 'readable-secret'})
    rendered = _attach_template(
        monkeypatch,
        tmp_path,
        silentfail=True,
        expression="TOKEN={secret['source-credentials']['token']}\n",
    )

    context.run(context.on.config_changed(), _state(context, secret))

    assert rendered.read_text() == 'TOKEN=readable-secret\n', 'a readable secret must be rendered to the entry'
