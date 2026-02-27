# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Requirer interface implementation for server relation.

Module providing the implementation details for charms that are the requirer
side of the server relation and interact with the canonical-seceng-server
charm.
"""

__all__ = ['ServerRequirer']

import logging
import typing

import ops
import pydantic

from .interfaces import ServerRelationProviderUnitData, ServerRelationRequirerUnitData


class ServerRequirer(ops.Object):
    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    def __init__(self, charm: ops.CharmBase, /, *, relation_name: str = 'server'):
        super().__init__(charm, None)
        self.charm = charm

        self.framework.observe(charm.on[relation_name].relation_created, self._on_relation_created)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)
        self.framework.observe(charm.on[relation_name].relation_departed, self._on_relation_departed)

        self._stored.set_default(server_unit=None, server_data=None)

    @property
    def server_unit(self) -> str | None:
        return typing.cast(str | None, self._stored.server_unit)

    @server_unit.setter
    def server_unit(self, value: str | None) -> None:
        self._stored.server_unit = value

    @property
    def server_data(self) -> ServerRelationProviderUnitData | None:
        try:
            value = typing.cast(ServerRelationProviderUnitData | None, self.__dict__['server_data'])
        except KeyError:
            raw_data = self._stored.server_data
            if raw_data is not None:
                value = ServerRelationProviderUnitData.model_validate(raw_data)
            else:
                value = None
            self.__dict__['server_data'] = value
        return value

    @server_data.setter
    def server_data(self, value: ServerRelationProviderUnitData | None) -> None:
        self.__dict__['server_data'] = value
        self._stored.server_data = value.model_dump() if value is not None else None

    @property
    def ready(self) -> bool:
        server_data = self.server_data
        return server_data is not None and server_data.ready and self.charm.unit.name in server_data.requirers

    def _on_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        self._update_relation(event.relation)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return

        try:
            data = ServerRelationProviderUnitData.load_from_relation(event.relation, remote_unit)
        except pydantic.ValidationError as e:
            logging.warning(f"Server relation provider '{remote_unit.name}' provided invalid data: {e}.")
            return

        if not data.is_local:
            return

        if self.server_unit is None:
            logging.info(f"Server requirer connected to new server unit '{remote_unit.name}'.")
            # FIXME: emit connected
        elif self.server_unit != remote_unit.name:
            logging.error(
                f"Server requirer already connected to server unit '{self.server_unit}'"
                f" cannot also connect to '{remote_unit.name}'."
            )
            return  # FIXME

        previously_ready = self.ready
        self.server_unit = remote_unit.name
        self.server_data = data
        if self.ready and not previously_ready:
            # FIXME: emit ready
            logging.info(f"Server provider '{remote_unit.name}' ready.")
            pass
        else:
            logging.info(f"Server provider '{remote_unit.name}' not yet ready.")

    def _on_relation_departed(self, event: ops.RelationDepartedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return

        if self.server_unit is None or remote_unit.name != self.server_unit:
            return

        logging.info(f"Server requirer disconnected from server unit '{remote_unit.name}'.")
        # old_server_unit = self.server_unit
        # old_data = self.server_data
        self.server_unit = None
        self.server_data = None
        # FIXME: emit disconnected

    def _update_relation(self, relation: ops.Relation) -> None:
        if not relation.active:
            return
        # FIXME: these are due to mypy and pyright not supporting pydantic's
        # field alias functionality. Re-evaluate periodically because they
        # won't be reported once they're no longer necessary.
        # Last check (2026-02-26):
        #  mypy - 1.19
        #  pyright - 1.1.408
        data = ServerRelationRequirerUnitData(  # type: ignore [reportCallIssue, unused-ignore]
            machine_id=ServerRelationRequirerUnitData.get_machine_id(),  # type: ignore [reportCallIssue, call-arg, unused-ignore]
        )
        relation.save(data, self.charm.unit)
