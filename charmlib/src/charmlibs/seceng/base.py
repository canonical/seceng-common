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
import pathlib
import subprocess
import sys
import typing

import ops
import pydantic
import yaml
from ops.model import ActiveStatus, MaintenanceStatus

from . import utils


@dataclasses.dataclass(kw_only=True)
class Package:
    name: str
    ppa: str = 'ubuntu-security-infra'


@dataclasses.dataclass(kw_only=True)
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

    package_install_ppa = 'ubuntu-security-infra'
    package_install_list: list[Package] = []
    snap_install_list: list[Snap] = []

    secrets_config: str | None = None

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)
        framework.observe(self.on.secret_changed, self._seceng_base_on_secret_changed)

        self._stored.set_default(configured_ppa='', installed_packages=set())

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_ppa_and_packages()
        self._install_snaps()
        self._install_secrets()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        if event.secret.id is not None:
            self._install_secrets(filter_secrets={event.secret.id})

    def _install_ppa_and_packages(self) -> None:
        for package in self.package_install_list:
            new_ppa = f'ppa:{package.ppa}/{self.config["deployment"]}'
            if new_ppa != typing.cast(str, self._stored.configured_ppa):
                self.unit.status = MaintenanceStatus('Configuring PPA')
                self._stored.configured_ppa = new_ppa
                subprocess.check_call(["add-apt-repository", new_ppa])
                subprocess.check_call(["apt-get", "update"])
                self._stored.installed_packages = set()  # Force reinstallation of packages when PPA changes.

            if set(self.package_install_list) != typing.cast(set[str], self._stored.installed_packages):
                self._stored.installed_packages = set(self.package_install_list)
                self.unit.status = MaintenanceStatus(f'Installing Debian Package: {package.name}')
                subprocess.check_call(["apt-get", "install", "-y", package.name])

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
