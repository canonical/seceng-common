#!/usr/bin/env python3
# Copyright 2026 Luci Stanescu
# See LICENSE file for licensing details.

"""Charm the application."""

import contextlib
import logging
import pathlib

import ops

# from charmlibs.seceng.interfaces import ServerRelationProviderUnitData, ServerRelationRequirerUnitData
from charmlibs.seceng.template import TemplateEngine

from charmlibs.seceng.interfaces import (
    LocalRequirerConnectedEvent,
    LocalRequirerDataChangedEvent,
    LocalRequirerDisconnectedEvent,
)
from charmlibs.seceng.server import ServerProvider, ServerRequirerUnitData


class SecEngServerCharm(ops.CharmBase):
    """Charm the application."""

    templates = [pathlib.Path('templates.yaml')]

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.server = ServerProvider(self)
        framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.secret_changed, self._on_secret_changed)
        framework.observe(self.server.on.connected, self._on_requirer_connected)
        framework.observe(self.server.on.disconnected, self._on_requirer_disconnected)
        framework.observe(self.server.on.data_changed, self._on_requirer_data_changed)

        self.template_engine = TemplateEngine(self)

    def _on_upgrade_charm(self, event: ops.UpgradeCharmEvent) -> None:
        self._reconfigure()

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._reconfigure()

    def _on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        if event.secret.id is not None:
            self._reconfigure(dirty_secrets={event.secret.id})

    def _on_requirer_connected(self, event: LocalRequirerConnectedEvent) -> None:
        logging.info(f"This unit is now connected to server {event.unit}.")
        self._reconfigure()

    def _on_requirer_disconnected(self, event: LocalRequirerDisconnectedEvent) -> None:
        logging.info(f"This unit is now disconnected from server {event.unit}.")
        self._reconfigure()

    def _on_requirer_data_changed(self, event: LocalRequirerDataChangedEvent[ServerRequirerUnitData]) -> None:
        logging.info(f"Server requirer {event.unit} data has changed.")
        self._reconfigure()

    def _reconfigure(self, *, dirty_secrets: set[str] = set()) -> None:
        with contextlib.ExitStack() as exit_stack:
            self.unit.status = ops.MaintenanceStatus('Reconfiguring...')
            logging.info("Reconfiguring...")

            # Always set ready to False while reconfiguring and back to True
            # when done, even if we error out.
            self.server.begin_configure()
            exit_stack.callback(self.server.end_configure)

            self.unit.status = ops.MaintenanceStatus('Installing templates')
            logging.info("About to install templates...")
            if self.templates:
                self.template_engine.process(
                    *(self.charm_dir / template for template in self.templates),
                    dirty_secrets=dirty_secrets,
                )
            logging.info("Templates installed.")

            # No errors, so all requests from requirers handled.
            self.server.clear_pending_requirers()

            logging.info("Reconfigured")
            self.unit.status = ops.ActiveStatus('ready')


if __name__ == "__main__":  # pragma: nocover
    ops.main(SecEngServerCharm)
