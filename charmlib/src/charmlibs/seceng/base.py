# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Base classes for SecEng charms.

Module providing base charm classes for common functionality used by the
Security Engineering team at Canonical.
"""

import collections.abc
import dataclasses
import importlib.resources
import logging
import os
import pathlib
import subprocess
import sys
import typing

import ops
import pydantic
import yaml
from ops.model import MaintenanceStatus

from . import utils
from .template import TemplateEngine


@dataclasses.dataclass(kw_only=True, frozen=True)
class Package:
    name: str
    ppa: str | None = 'ubuntu-security-infra'


@dataclasses.dataclass(kw_only=True, frozen=True)
class Snap:
    name: str
    channel: str = 'stable'


@dataclasses.dataclass(kw_only=True)
class DebconfConfig:
    name: str
    package: str
    template: str


@dataclasses.dataclass(kw_only=True)
class FileConfig:
    name: str
    permission: str | None = None
    template: str


class SecretConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

    user: str | None = None
    group: str | None = None
    debconf: list[DebconfConfig] = []
    files: list[FileConfig] = []


class SecretsRoot(pydantic.RootModel[dict[str, SecretConfig]]):
    def __len__(self) -> int:
        return len(self.root)

    def __iter__(self) -> collections.abc.Iterator[str]:  # type: ignore[override]
        return iter(self.root)

    def __getitem__(self, name: str) -> SecretConfig:
        return self.root[name]

    def __contains__(self, name: str) -> bool:
        return name in self.root

    def items(self) -> collections.abc.Iterable[tuple[str, SecretConfig]]:
        return self.root.items()


class SecEngCharmBase(ops.CharmBase):
    """Common base for SecEng charms.

    A base charm providing support for installing deb packages from PPAs and
    creating files from juju secrets.
    """

    package_install_list: list[Package] = []
    snap_install_list: list[Snap] = []

    secrets_config: str | None = None
    templates: list[pathlib.Path] = []

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)
        framework.observe(self.on.secret_changed, self._seceng_base_on_secret_changed)
        framework.observe(self.on.upgrade_charm, self._seceng_base_on_upgrage_charm)

        self.template_engine = TemplateEngine(self)
        self._stored.set_default(configured_ppas=[], installed_packages=[])

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_ppa_and_packages()
        self._install_snaps()
        self._install_secrets()
        self._install_templates()

    def _seceng_base_on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        if event.secret.id is not None:
            self._install_secrets(filter_secrets={event.secret.id})
            self._install_templates(dirty_secrets={event.secret.id})

    def _seceng_base_on_upgrage_charm(self, event: ops.UpgradeCharmEvent) -> None:
        self._install_templates()

    def _install_ppa_and_packages(self) -> None:
        previous_ppas = set(typing.cast(list[str], self._stored.configured_ppas))
        new_ppas = {
            f'ppa:{package.ppa}/{self.config["deployment"]}' for package in self.package_install_list if package.ppa
        }
        for old_ppa in previous_ppas - new_ppas:
            # FIXME: find a solution.
            # Do not do anything, because it could interfere with other charms.
            pass
        for new_ppa in new_ppas - previous_ppas:
            self.unit.status = MaintenanceStatus('Configuring PPA')
            subprocess.check_call(['add-apt-repository', '--no-update', '--ppa', new_ppa])
        if new_ppas != previous_ppas:
            subprocess.check_call(['apt-get', 'update'])
            self._stored.configured_ppa = list(new_ppas)
            self._stored.installed_packages = []  # Force reinstallation of packages when PPA changes.

        previous_packages = set(typing.cast(list[str], self._stored.installed_packages))
        new_packages = {package.name for package in self.package_install_list}
        for old_package in previous_packages - new_packages:
            # FIXME: might not be a real issue.
            # Do not do anything, because it could interfere with other charms.
            pass
        for new_package in new_packages - previous_packages:
            subprocess.check_call(['apt-mark', 'install', new_package])
        if new_packages != previous_packages:
            self.unit.status = MaintenanceStatus('Installing Debian packages')
            subprocess.check_call(['apt-get', 'dselect-upgrade', '-y'])
            self._stored.installed_packages = list(new_packages)

    def _install_snaps(self) -> None:
        for snap in self.snap_install_list:
            self.unit.status = MaintenanceStatus('Installing Snap: {snap.name} {snap.channel}')
            subprocess.check_call(["snap", "install", "--channel", snap.channel, snap.name])

    def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
        # This method should not be called on the install or upgrade hook,
        # because it may rely on package installation from
        self.unit.status = MaintenanceStatus('Installing Secrets')
        logging.warning("About to install secrets...")

        with importlib.resources.as_file(importlib.resources.files() / 'secrets.yaml') as filepath:
            self._install_secrets_file(filepath, filter_secrets=filter_secrets)

        if self.secrets_config is not None:
            self._install_secrets_file(self.charm_dir / self.secrets_config, filter_secrets=filter_secrets)

    def _install_secrets_file(self, filepath: pathlib.Path, *, filter_secrets: set[str] = set()) -> None:
        logging.debug("Parsing secrets file '{}'...".format(filepath))
        with open(filepath, 'r') as file:
            try:
                all_secrets = SecretsRoot.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]
            except pydantic.ValidationError:
                logging.error(f"Failed to load secrets configuration file '{filepath}.'")
                raise

        debconf_packages: set[str] = set()
        debconf_selections: list[str] = []

        for name, secret_id in self.config.items():
            option_type = self.meta.config.get(name)
            if not option_type or option_type.type != 'secret':
                continue
            if name not in all_secrets:
                continue
            if not isinstance(secret_id, str):
                logging.warning(
                    f"Unexpected type for charm configuration item '{name}'"
                    f" of type 'secret': {type(secret_id).__name__}."
                )
                continue
            if filter_secrets and secret_id not in filter_secrets:
                continue

            logging.warning(f"Processing secret '{name}'...")
            secret_entry = all_secrets[name]

            secret_object = self.model.get_secret(id=secret_id)
            secret_content = secret_object.get_content(refresh=True)

            for debconf_entry in secret_entry.debconf:
                value = debconf_entry.template.format(**secret_content)
                try:
                    value = subprocess.check_output(
                        ['debconf-escape', '-e'],
                        input=value,
                        text=True,
                        encoding=sys.stdin.encoding,
                    )
                except subprocess.CalledProcessError as e:
                    raise ValueError(f"failed to escape debconf value '{value}': exit code {e.returncode}")
                debconf_packages.add(debconf_entry.package)
                debconf_selections.append(f'{debconf_entry.package} {debconf_entry.name} password {value}')
                logging.info(f"Queueing debconf option '{debconf_entry.name}' for package '{debconf_entry.package}'.")

            for file_entry in secret_entry.files:
                with utils.open_file_secure(
                    pathlib.Path(file_entry.name),
                    user=secret_entry.user,
                    group=secret_entry.group,
                    mode=int(file_entry.permission, 0) if file_entry.permission is not None else 0o600,
                    create_parents=True,
                ) as f:
                    f.write(file_entry.template.format(**secret_content))
                logging.info(f"Created secrets file '{file_entry.name}'.")

        if debconf_selections:
            try:
                subprocess.run(
                    ['debconf-set-selections'],
                    input='\n'.join(debconf_selections),
                    text=True,
                    encoding=sys.stdin.encoding,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise ValueError(f"failed to run debconf-set-selections: exit code {e.returncode}")
            else:
                logging.info(f"Successfully set {len(debconf_selections)} debconf options.")
        else:
            logging.debug("No debconf options configured.")

        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if debconf_packages and os.geteuid() == 0:
            try:
                subprocess.check_call(['dpkg-reconfigure', '-fnoninteractive'] + list(debconf_packages))
            except subprocess.CalledProcessError as e:
                raise ValueError(f"failed to run dpkg-reconfigure: exit code {e.returncode}")
            else:
                logging.info("Successfully ran dpkg-reconfigure.")

    def _install_templates(self, *, dirty_secrets: set[str] = set()) -> None:
        # This method should not be called on the install hook, because it may
        # rely on package installation from the config changed hook.
        self.unit.status = MaintenanceStatus('Installing templates')
        logging.info("About to install templates...")

        with importlib.resources.as_file(importlib.resources.files() / 'templates.yaml') as filepath:
            self.template_engine.process(
                filepath,
                *(self.charm_dir / template for template in self.templates),
                dirty_secrets=dirty_secrets,
            )
