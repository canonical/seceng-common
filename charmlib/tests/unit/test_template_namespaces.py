# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

"""Tests for the template engine's ``installed`` and ``model_proxy`` namespaces.

Both namespaces reuse the engine's existing Namespace machinery. The same
missing-object skip and read-value dirty tracking as ``config`` and ``secret``
mean these tests pin the behaviours that follow from that reuse:
an entry referencing an absent object is skipped entirely, and an entry whose
read value changes between renders is re-rendered and fires its actions.
"""

import collections.abc
import os
import pathlib
import pwd
import tempfile

import pytest
import yaml
from ops import testing

from charmlibs.seceng.base import SecEngCharmBase

DIGEST = 'a' * 64
OTHER_DIGEST = 'b' * 64

PROXY_VARS = (
    'JUJU_CHARM_HTTP_PROXY',
    'JUJU_CHARM_HTTPS_PROXY',
    'JUJU_CHARM_NO_PROXY',
    # _setup_proxies copies the JUJU_CHARM_* values into these when the charm
    # initialises; registering them with monkeypatch keeps that write from
    # leaking into other tests.
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'no_proxy',
)


class NamespaceTestCharm(SecEngCharmBase):
    """A consumer charm passing its current installed map to the engine."""

    installed: collections.abc.Mapping[str, str] | None = None

    def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
        pass

    def _install_templates(self, *, dirty_secrets: set[str] = set()) -> None:
        if self.installed is None:
            self.template_engine.process(*self.templates, dirty_secrets=dirty_secrets)
        else:
            self.template_engine.process(
                *self.templates,
                dirty_secrets=dirty_secrets,
                installed=self.installed,
            )


@pytest.fixture
def context() -> testing.Context[NamespaceTestCharm]:
    return testing.Context(
        NamespaceTestCharm,
        config={
            'options': {
                'deployment': {'type': 'string'},
            },
        },
        meta={'name': 'namespace-test-charm'},
    )


@pytest.fixture
def tmpdir() -> collections.abc.Iterator[pathlib.Path]:
    with tempfile.TemporaryDirectory() as tmpdir_path:
        yield pathlib.Path(tmpdir_path)


@pytest.fixture
def contained_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in PROXY_VARS:
        monkeypatch.setenv(name, '')


def _attach_template(
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
    template: str,
) -> tuple[list[list[str]], pathlib.Path]:
    """Attach one silentfail file entry with a restart action to the charm.

    Returns the list the executed action argv is recorded into and the path the
    engine renders the file to.
    """
    calls: list[list[str]] = []

    def record_check_call(cmd: list[str], *args: object, **kwargs: object) -> int:
        calls.append(cmd)
        return 0

    monkeypatch.setattr('charmlibs.seceng.template.subprocess.check_call', record_check_call)
    monkeypatch.setattr('charmlibs.seceng.template.os.geteuid', lambda: 0)
    rendered = tmpdir / 'directory!mode=700,uid' / 'namespaced.env'
    config_file_path = tmpdir / 'templates.yaml'
    with config_file_path.open('w') as config_file:
        config_file.write(
            yaml.dump(
                {
                    'files': [
                        {
                            'name': str(rendered),
                            'user': pwd.getpwuid(os.getuid()).pw_name,
                            'permission': '0o640',
                            'silentfail': True,
                            'template': template,
                            'actions': ['systemctl:restart:test-agent'],
                        },
                    ],
                }
            )  # type: ignore[no-untyped-call]
        )
    monkeypatch.setattr(NamespaceTestCharm, 'templates', [config_file_path])
    return calls, tmpdir / 'directory' / 'namespaced.env'


def _state(context: testing.Context[NamespaceTestCharm]) -> testing.State:
    return testing.State.from_context(
        context,
        leader=True,
        config={'deployment': 'test'},
    )


def test_installed_entry_is_skipped_before_the_first_install(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    """Nothing is installed yet, so the entry has nothing to render and is skipped."""
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {})
    _action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    context.run(context.on.config_changed(), _state(context))

    assert not rendered.exists(), 'an entry referencing an uninstalled wheelhouse must be skipped entirely'


def test_installed_entry_renders_once_installed_and_fires_its_actions(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    context.run(context.on.config_changed(), _state(context))

    assert rendered.read_text() == f'DIGEST={DIGEST}\n'
    assert action_calls == [['systemctl', 'restart', 'test-agent']]


def test_installed_entry_rerenders_and_fires_actions_when_the_digest_changes(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    """A digest change is a real change of the running workload: re-render, restart."""
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    state_out = context.run(context.on.config_changed(), _state(context))
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': OTHER_DIGEST})
    context.run(context.on.config_changed(), state_out)

    assert rendered.read_text() == f'DIGEST={OTHER_DIGEST}\n', 'the rendered digest must be the installed one'
    assert action_calls == [
        ['systemctl', 'restart', 'test-agent'],
        ['systemctl', 'restart', 'test-agent'],
    ], 'the restart must follow the successful upgrade'


def test_installed_entry_does_not_rerender_when_nothing_changed(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    state_out = context.run(context.on.config_changed(), _state(context))
    context.run(context.on.config_changed(), state_out)

    assert rendered.read_text() == f'DIGEST={DIGEST}\n'
    assert action_calls.count(['systemctl', 'restart', 'test-agent']) == 1, 'an unchanged digest must not restart'


def test_installed_entry_reuses_persisted_mapping_when_mapping_is_omitted(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    """Omitting the map preserves the digest across the next identical render."""
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    state_out = context.run(context.on.config_changed(), _state(context))
    monkeypatch.setattr(NamespaceTestCharm, 'installed', None)
    state_out = context.run(context.on.config_changed(), state_out)
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    context.run(context.on.config_changed(), state_out)

    assert rendered.read_text() == f'DIGEST={DIGEST}\n'
    assert action_calls == [['systemctl', 'restart', 'test-agent']], 'render 3 must not restart again'


def test_explicit_empty_installed_mapping_clears_persisted_digest(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
) -> None:
    """An explicit empty map means that no wheelhouse is installed."""
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "DIGEST={installed['test-agent']}\n")

    state_out = context.run(context.on.config_changed(), _state(context))
    monkeypatch.setattr(NamespaceTestCharm, 'installed', {})
    state_out = context.run(context.on.config_changed(), state_out)
    assert action_calls == [['systemctl', 'restart', 'test-agent']]
    assert rendered.read_text() == f'DIGEST={DIGEST}\n', 'missing installed entries leave the file unchanged'

    monkeypatch.setattr(NamespaceTestCharm, 'installed', {'test-agent': DIGEST})
    context.run(context.on.config_changed(), state_out)

    assert action_calls == [
        ['systemctl', 'restart', 'test-agent'],
        ['systemctl', 'restart', 'test-agent'],
    ], 'the explicit empty map must not reuse the persisted digest'


def test_model_proxy_entry_is_skipped_when_no_proxy_is_configured(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
    contained_proxy_env: None,
) -> None:
    _action_calls, rendered = _attach_template(monkeypatch, tmpdir, "PROXY={model_proxy['https']}\n")

    context.run(context.on.config_changed(), _state(context))

    assert not rendered.exists(), 'an entry referencing a proxy on a proxy-less model must be skipped'


def test_model_proxy_entry_renders_when_a_proxy_is_configured(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
    contained_proxy_env: None,
) -> None:
    monkeypatch.setenv('JUJU_CHARM_HTTPS_PROXY', 'http://squid.internal:3128')
    _action_calls, rendered = _attach_template(monkeypatch, tmpdir, "PROXY={model_proxy['https']}\n")

    context.run(context.on.config_changed(), _state(context))

    assert rendered.read_text() == 'PROXY=http://squid.internal:3128\n'


def test_model_proxy_carries_each_key_from_its_own_variable(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
    contained_proxy_env: None,
) -> None:
    monkeypatch.setenv('JUJU_CHARM_HTTP_PROXY', 'http://squid.internal:3128')
    monkeypatch.setenv('JUJU_CHARM_NO_PROXY', '10.0.0.0/8,localhost')
    _action_calls, rendered = _attach_template(
        monkeypatch,
        tmpdir,
        "HTTP={model_proxy['http']} NO={model_proxy['no']}\n",
    )

    context.run(context.on.config_changed(), _state(context))

    assert rendered.read_text() == 'HTTP=http://squid.internal:3128 NO=10.0.0.0/8,localhost\n'


def test_model_proxy_entry_rerenders_and_fires_actions_when_proxy_changes(
    context: testing.Context[NamespaceTestCharm],
    monkeypatch: pytest.MonkeyPatch,
    tmpdir: pathlib.Path,
    contained_proxy_env: None,
) -> None:
    monkeypatch.setenv('JUJU_CHARM_HTTPS_PROXY', 'http://squid.internal:3128')
    action_calls, rendered = _attach_template(monkeypatch, tmpdir, "PROXY={model_proxy['https']}\n")

    state_out = context.run(context.on.config_changed(), _state(context))
    monkeypatch.setenv('JUJU_CHARM_HTTPS_PROXY', 'http://proxy2.internal:8080')
    context.run(context.on.config_changed(), state_out)

    assert rendered.read_text() == 'PROXY=http://proxy2.internal:8080\n'
    assert action_calls == [
        ['systemctl', 'restart', 'test-agent'],
        ['systemctl', 'restart', 'test-agent'],
    ], 'a changed proxy value must rerender and restart the dependent service'
