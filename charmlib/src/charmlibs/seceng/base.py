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
import shutil
import subprocess
from pathlib import Path

import ops
import pydantic
import yaml
from ops.model import ActiveStatus, MaintenanceStatus


@dataclasses.dataclass(kw_only=True)
class Package:
    name: str
    ppa: str = 'ubuntu-security-infra'


@dataclasses.dataclass(kw_only=True)
class Snap:
    name: str
    channel: str = 'stable'


@dataclasses.dataclass(kw_only=True)
class FileConfig:
    name: str
    permission: str | None = None
    variables: dict[str, str]
    template: str


class SecretConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

    user: str | None = None
    group: str | None = None
    files: list[FileConfig]


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

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.install, self._seceng_base_on_install)
        framework.observe(self.on.upgrade_charm, self._seceng_base_on_upgrade)
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)

    def _seceng_base_on_install(self, event: ops.InstallEvent) -> None:
        self._install_ppa_and_packages()
        self._install_snaps()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_upgrade(self, event: ops.UpgradeCharmEvent) -> None:
        self._install_ppa_and_packages()
        self._install_snaps()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_secrets()
        self.unit.status = ActiveStatus('ready')

    def _install_ppa_and_packages(self) -> None:
        for package in self.package_install_list:
            self.unit.status = MaintenanceStatus(f'Installing Debian Package: {package.name}')
            subprocess.check_call(["apt-get", "update"])
            subprocess.check_call(["add-apt-repository", f'ppa:{package.ppa}/{self.config["deployment"]}'])
            subprocess.check_call(["apt-get", "update"])
            subprocess.check_call(["apt-get", "install", "-y", package.name])

    def _install_snaps(self) -> None:
        for snap in self.snap_install_list:
            self.unit.status = MaintenanceStatus('Installing Snap: {snap.name} {snap.channel}')
            subprocess.check_call(["snap", "install", "--channel", snap.channel, snap.name])

    def _install_secrets(self) -> None:
        # This method should not be called on the install or upgrade hook,
        # because it may rely on package installation from
        self.unit.status = MaintenanceStatus('Installing Secrets')
        logging.warning("About to install secrets...")

        with importlib.resources.as_file(importlib.resources.files() / 'secrets.yaml') as filepath:
            self._install_secrets_file(filepath)

        if self.secrets_config is not None:
            self._install_secrets_file(self.charm_dir / self.secrets_config)

    def _install_secrets_file(self, filepath: pathlib.Path) -> None:
        with open(filepath, 'r') as file:
            try:
                all_secrets = SecretsRoot.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]
            except pydantic.ValidationError:
                logging.error(f"Failed to load secrets configuration file '{filepath}.'")
                raise

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

            logging.warning(f"Processing secret '{name}'...")
            secret_entry = all_secrets[name]

            secret_object = self.model.get_secret(id=secret_id)
            secret_content = secret_object.get_content(refresh=True)

            for file_entry in secret_entry.files:
                variables = {}
                for varname, varvalue in file_entry.variables.items():
                    variables[varname] = secret_content[varvalue]

                file_path = Path(file_entry.name)
                if not file_path.parent.exists():
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    if secret_entry.user and secret_entry.group:
                        shutil.chown(file_path.parent, secret_entry.user, secret_entry.group)

                with open(file_path, 'w') as f:
                    f.write(file_entry.template.format(**variables))
                if file_entry.permission:
                    file_path.chmod(int(file_entry.permission, 0))
                if secret_entry.user and secret_entry.group:
                    shutil.chown(file_path, secret_entry.user, secret_entry.group)
                logging.info(f"Created secrets file '{file_path}'.")
