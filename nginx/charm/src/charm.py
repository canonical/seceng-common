#!/usr/bin/env python3
# Copyright 2026 Luci Stanescu
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
import os
import pathlib
import subprocess

import ops

from charmlibs.seceng.base import Package, SecEngCharmBase

from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer, IngressPerAppReadyEvent, IngressPerAppRevokedEvent

from charmlibs.seceng.interfaces import (
    LocalProviderConnectedEvent,
    LocalProviderDataChangedEvent,
    LocalProviderDisconnectedEvent,
    LocalProviderReadyEvent,
)
from charmlibs.seceng.server import ServerRequirer, ServerProviderUnitData


class SecEngNginxCharm(SecEngCharmBase):
    """Charm the application."""

    package_install_list = [Package(name='nginx', ppa=None)]
    templates = [pathlib.Path('templates.yaml')]

    nginx_config_dir = pathlib.Path('/etc/nginx')

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.ingress = IngressPerAppRequirer(self, port=80)
        self.server = ServerRequirer(self)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.upgrade_charm, self._on_upgrade)
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.ingress.on.ready, self._on_ingress_ready)
        framework.observe(self.ingress.on.revoked, self._on_ingress_revoked)
        framework.observe(self.server.on.connected, self._on_server_connected)
        framework.observe(self.server.on.disconnected, self._on_server_disconnected)
        framework.observe(self.server.on.ready, self._on_server_ready)
        framework.observe(self.server.on.data_changed, self._on_server_data_changed)

        self._stored.set_default(default_server_config_hash=None)

    def _on_install(self, event: ops.InstallEvent) -> None:
        self.unit.open_port(protocol='tcp', port=80)
        self.unit.status = ops.ActiveStatus('ready')

    def _on_upgrade(self, event: ops.UpgradeCharmEvent) -> None:
        self.unit.open_port(protocol='tcp', port=80)
        self.unit.status = ops.ActiveStatus('ready')

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._setup_nginx()

    def _on_ingress_ready(self, event: IngressPerAppReadyEvent) -> None:
        logging.info("This app's ingress URL: %s.", event.url)

    def _on_ingress_revoked(self, event: IngressPerAppRevokedEvent) -> None:
        logging.info("This app no longer has ingress.")

    def _on_server_connected(self, event: LocalProviderConnectedEvent) -> None:
        logging.info(f"This unit is now connected to server {event.unit}.")

    def _on_server_disconnected(self, event: LocalProviderDisconnectedEvent) -> None:
        logging.info(f"This unit is now disconnected from server {event.unit}.")
        self._setup_nginx()

    def _on_server_ready(self, event: LocalProviderReadyEvent) -> None:
        logging.info(f"Server provider {event.unit} is now ready.")
        self._setup_nginx()

    def _on_server_data_changed(self, event: LocalProviderDataChangedEvent[ServerProviderUnitData]) -> None:
        logging.info(f"Server provider {event.unit} data has changed.")

    def _setup_nginx(self, dirty_secrets: set[str] = set()) -> None:
        self.unit.status = ops.MaintenanceStatus('reconfiguring nginx service...')

        if not self.server.provider_unit:
            logging.error("Not connected to a server provider.")
            self.unit.status = ops.BlockedStatus('no server')
            return
        if not self.server.ready:
            logging.error("Server provider not ready.")
            self.unit.status = ops.BlockedStatus('server not ready')
            return

        # Remove all symlinks from sites-enabled directory, apart from 'default'.
        try:
            dir_fd = os.open(self.nginx_config_dir / 'sites-enabled', os.O_RDONLY | os.O_DIRECTORY)
        except FileNotFoundError:
            logging.error("Nginx sites-enabled directory does not exist.")
            self.unit.status = ops.BlockedStatus('nginx not installed')
            return
        for name in os.listdir(dir_fd):
            if name == 'default':
                continue
            logging.info(f"Removing nginx site config '{name}'...")
            os.unlink(name, dir_fd=dir_fd)
        # Link available config file to sites-enabled.
        os.symlink(self.nginx_config_dir / 'sites-available/charm-default', '.default', dir_fd=dir_fd)
        os.rename('.default', 'default', src_dir_fd=dir_fd, dst_dir_fd=dir_fd)

        # Reload nginx.
        logging.info("Reloading nginx service...")
        try:
            subprocess.check_call(['systemctl', 'reload', 'nginx.service'])
        except subprocess.CalledProcessError:
            logging.warning("Failed to reload nginx service.")
        logging.info("Successfully configured nginx service.")
        self.unit.status = ops.ActiveStatus('ready')


if __name__ == "__main__":  # pragma: nocover
    ops.main(SecEngNginxCharm)
