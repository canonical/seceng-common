# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Base classes for SecEng charms.

Module providing base charm classes for common functionality used by the
Security Engineering team at Canonical.
"""

import importlib.resources
import logging
import pathlib
import shutil
import subprocess
from pathlib import Path

import ops
import yaml
from ops.model import ActiveStatus, MaintenanceStatus


class SecEngCharmBase(ops.CharmBase):
    """Common base for SecEng charms.

    A base charm providing support for installing deb packages from PPAs and
    creating files from juju secrets.
    """

    package_install_ppa = 'ubuntu-security-infra'
    package_install_list: list[str] = []

    secrets_config: str | None = None

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.install, self._seceng_base_on_install)
        framework.observe(self.on.upgrade_charm, self._seceng_base_on_upgrade)
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)

    def _seceng_base_on_install(self, event: ops.InstallEvent) -> None:
        self._install_ppa_and_packages()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_upgrade(self, event: ops.UpgradeCharmEvent) -> None:
        self._install_ppa_and_packages()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_secrets()
        self.unit.status = ActiveStatus('ready')

    def _install_ppa_and_packages(self) -> None:
        self.unit.status = MaintenanceStatus('Installing Debian Package')
        subprocess.check_call(["apt-get", "update"])
        subprocess.check_call(["add-apt-repository", f'ppa:{self.package_install_ppa}/{self.config["deployment"]}'])
        subprocess.check_call(["apt-get", "update"])
        if self.package_install_list:
            subprocess.check_call(["apt-get", "install", "-y"] + self.package_install_list)

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
            all_secrets = yaml.safe_load(file)  # type: ignore[no-untyped-call]

        for name, secret_id in self.config.items():
            assert isinstance(secret_id, str)
            option_type = self.meta.config.get(name)
            if not option_type or option_type.type != 'secret':
                continue
            if name not in all_secrets:
                continue
            logging.warning("Processing secret '{}'...".format(name))
            secret_entry = all_secrets[name]
            user = secret_entry['user'] if 'user' in secret_entry else None
            group = secret_entry['group'] if 'group' in secret_entry else None

            secret_object = self.model.get_secret(id=secret_id)
            secret_content = secret_object.get_content(refresh=True)

            for file in secret_entry['files']:
                variables = {}
                for variable in file['variables']:
                    variables[variable] = secret_content[file['variables'][variable]]

                file_path = Path(file['name'])
                if not file_path.parent.exists():
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    if user and group:
                        shutil.chown(file_path.parent, user, group)

                with open(file_path, 'w') as f:
                    f.write(file['template'].format(**variables))
                if 'permission' in file:
                    file_path.chmod(int(file['permission'], 0))
                if user and group:
                    shutil.chown(file_path, user, group)
                logging.info("Created secrets file '{}'.".format(file_path))
