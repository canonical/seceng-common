# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Interface definitions for SecEng charms.

Module providing common charm interface functionality used by the Security
Engineering team at Canonical.
"""

import collections.abc
import contextlib
import dataclasses
import functools
import importlib
import json
import logging
import traceback
import types
import typing
import uuid

import ops
import pydantic

from .types import JSONType


@contextlib.contextmanager
def safe_json_decoder() -> collections.abc.Iterator[collections.abc.Callable[[str], JSONType]]:
    """Decode Juju relation data which may contain auto-injected network data.

    This is a temporary workaround until the following works:
        ops.Relation.load(Model, src=...)

    For the time being, it is to be used as:
        with safe_json_decoder() as decoder:
            ops.Relation.load(Model, src=..., decoder=decoder)

    It will print a warning message, containing a backtrace, if it is not
    actually needed.

    See also BaseRelationData.load_from_relation() which uses this.
    """
    invoked = False
    had_errors = False

    def decoder(val: str) -> JSONType:
        nonlocal invoked
        invoked = True
        try:
            return typing.cast(JSONType, json.loads(val))
        except json.JSONDecodeError:
            # Catch and return the raw string for extra fields added by Juju,
            # e.g.: private-address, ingress-address, egress-subnets
            nonlocal had_errors
            had_errors = True
            return val

    stack_format = traceback.format_stack()
    try:
        yield decoder
    finally:
        if invoked and not had_errors:
            logging.warning("safe_json_decoder() Relation.load workaround no longer needed:")
            logging.warning("".join(stack_format))


class BaseRelationData(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(validate_by_name=True)

    @classmethod
    def load_from_relation(
        cls,
        relation: ops.Relation,
        src: ops.Application | ops.Unit,
        /,
        *args: typing.Any,
        **kw: typing.Any,
    ) -> typing.Self:
        with safe_json_decoder() as decoder:
            return relation.load(cls, src, *args, decoder=decoder, **kw)


#################################
# LocalRelation support classes #
#################################

#
# A LocalRelation is defined as a relation between two principal applications
# where data is exchange only between units deployed on the same machine. Unlike
# the subordinate-principal relation type, a LocalRelation can have more than
# one application on the requirer side. For example, a Server application can
# offer basic server setup facilities via a 'server' relation. Multiple
# applications can be deployed on the same machine and all of them can integrate
# with the Server application via the relation, for example, to request the
# installation of packages.
#
# The implementation makes use of the /etc/machine-id identifier. Since this is
# a normal relation, a full-mesh of relation data gets exchanged. However, these
# classes facilitate the exchange of data only between units which are deployed
# on machines with the same UUID.
#


class LocalRelationUnitData(BaseRelationData):
    """Base class for data exchanged between a local requirer and provider.

    A UUID is always included in data exchanged on LocalRelation relations. This
    class is subclassed to represent data sent by a requirer and data sent by a
    provider.
    """

    @staticmethod
    def get_machine_id() -> uuid.UUID:
        """Return the machine UUID."""
        try:
            machine_id = open('/etc/machine-id').read().strip()
        except OSError as e:
            raise RuntimeError(f"cannot read '/etc/machine-id' file: {e.strerror}") from None
        try:
            return uuid.UUID(machine_id)
        except ValueError:
            raise RuntimeError(f"file '/etc/machine-id' does not contain a 32-hex-digit string: {machine_id}")

    # Note: must not define this with a default factory, because otherwise a
    # network-received representation would validate via model_validate() and
    # the value would default to the local machine, which is incorrect.
    machine_id: uuid.UUID = pydantic.Field(alias='machine-id', default_factory=get_machine_id)

    @property
    def is_local(self) -> bool:
        """Return whether this data was sent by the local machine."""
        return self.machine_id == self.get_machine_id()

    @classmethod
    def from_network(cls, obj: typing.Any) -> typing.Self:
        """Parse a dictionary received from the network.

        Enforces the presence of a machine-id field.
        """
        if not isinstance(obj, collections.abc.Mapping):
            raise TypeError("expected a mapping type")
        if 'machine_id' not in obj and 'machine-id' not in obj:
            raise ValueError("'machine-id' key missing")
        return cls.model_validate(obj)

    def to_network(self) -> collections.abc.Mapping[str, typing.Any]:
        """Generate a dictionary ready for network transmission."""
        return self.model_dump(mode='json')

    @classmethod
    def load_from_relation(
        cls,
        relation: ops.Relation,
        src: ops.Application | ops.Unit,
        /,
        *args: typing.Any,
        **kw: typing.Any,
    ) -> typing.Self:
        """Parse relation data and return an instance.

        Enforces the presence of a machine-id field.
        """
        obj = relation.data[src]
        if 'machine_id' not in obj and 'machine-id' not in obj:
            raise ValueError("'machine-id' key missing")
        return super().load_from_relation(relation, src, *args, **kw)


class LocalRelationProviderUnitData(LocalRelationUnitData):
    """Base class for UnitData sent by a provider of a LocalRelation."""

    ready: bool = False
    requirers: set[str] = pydantic.Field(default_factory=set)


class LocalRelationRequirerUnitData(LocalRelationUnitData):
    """Base class for UnitData sent by a requirer of a LocalRelation."""


@dataclasses.dataclass
class LocalEventBase(ops.EventBase):
    """Base class for events generated for LocalRelations.

    Implements snapshot() and restore functionality.
    """

    handle: dataclasses.InitVar[ops.Handle]

    relation: ops.Relation
    unit: ops.Unit

    def __post_init__(self, handle: ops.Handle) -> None:
        ops.EventBase.__init__(self, handle)

    def snapshot(self) -> dict[str, typing.Any]:
        """Serialize event data so that it can be reconstructed."""
        return {
            'relation-id': self.relation.id,
            'relation-name': self.relation.name,
            'unit-name': self.unit.name,
        }

    def restore(self, snapshot: dict[str, typing.Any]) -> None:
        """Deserialize event data generated by snapshot()."""
        relation = self.framework.model.get_relation(snapshot['relation-name'], snapshot['relation-id'])
        if relation is None:
            raise ValueError(
                f"Unable to restore {self}: relation {snapshot['relation-name']}"
                f" (id={snapshot['relation-id']}) not found"
            )
        self.relation = relation
        self.unit = self.framework.model.get_unit(snapshot['unit-name'])


@dataclasses.dataclass
class LocalProviderConnectedEvent(LocalEventBase):
    """Event sent to a requirer when a provider for a LocalRelation connects."""


@dataclasses.dataclass
class LocalProviderDisconnectedEvent(LocalEventBase):
    """Event sent to a requirer when a provider for a LocalRelation disconnects."""


@dataclasses.dataclass
class LocalProviderDataChangedEvent[PT: LocalRelationProviderUnitData](LocalEventBase):
    """Event sent to a requirer when the LocalRelation provider data changes."""

    data: PT

    def snapshot(self) -> dict[str, typing.Any]:
        """Serialize event data so that it can be reconstructed."""
        snapshot = super().snapshot()
        snapshot['data'] = self.data.to_network()
        snapshot['data-type-name'] = type(self.data).__qualname__
        snapshot['data-type-module'] = type(self.data).__module__
        return snapshot

    def restore(self, snapshot: dict[str, typing.Any]) -> None:
        """Deserialize event data generated by snapshot()."""
        super().restore(snapshot)
        obj = importlib.import_module(snapshot['data-type-module'])
        for part in snapshot['data-type-name'].split('.'):
            obj = getattr(obj, part)
        assert isinstance(obj, type) and issubclass(obj, LocalRelationProviderUnitData)
        self.data = typing.cast(PT, obj.from_network(snapshot['data']))


@dataclasses.dataclass
class LocalProviderReadyEvent(LocalEventBase):
    """Event sent to a requirer when the connected LocalRelation provider is ready."""


class LocalRequirerEvents[PT: LocalRelationProviderUnitData](ops.ObjectEvents):
    """Set of events sent to a requirer of a LocalRelation."""

    connected = ops.EventSource(LocalProviderConnectedEvent)
    disconnected = ops.EventSource(LocalProviderDisconnectedEvent)
    data_changed = ops.EventSource(LocalProviderDataChangedEvent)
    ready = ops.EventSource(LocalProviderReadyEvent)


@dataclasses.dataclass
class LocalRequirerConnectedEvent(LocalEventBase):
    """Event sent to a provider when a LocalRelation requirer connects."""


@dataclasses.dataclass
class LocalRequirerDisconnectedEvent(LocalEventBase):
    """Event sent to a provider when a LocalRelation requirer disconnects."""


@dataclasses.dataclass
class LocalRequirerDataChangedEvent[RT: LocalRelationRequirerUnitData](LocalEventBase):
    """Event sent to a provider when the LocalRelation requirer data changes."""

    data: RT

    def snapshot(self) -> dict[str, typing.Any]:
        """Serialize event data so that it can be reconstructed."""
        snapshot = super().snapshot()
        snapshot['data'] = self.data.to_network()
        snapshot['data-type-name'] = type(self.data).__qualname__
        snapshot['data-type-module'] = type(self.data).__module__
        return snapshot

    def restore(self, snapshot: dict[str, typing.Any]) -> None:
        """Deserialize event data generated by snapshot()."""
        super().restore(snapshot)
        obj = importlib.import_module(snapshot['data-type-module'])
        for part in snapshot['data-type-name'].split('.'):
            obj = getattr(obj, part)
        assert isinstance(obj, type) and issubclass(obj, LocalRelationRequirerUnitData)
        self.data = typing.cast(RT, obj.from_network(snapshot['data']))


class LocalProviderEvents[RT: LocalRelationRequirerUnitData](ops.ObjectEvents):
    """Set of events sent to a provider of a LocalRelation."""

    connected = ops.EventSource(LocalRequirerConnectedEvent)
    disconnected = ops.EventSource(LocalRequirerDisconnectedEvent)
    data_changed = ops.EventSource(LocalRequirerDataChangedEvent)


class _LocalProvider[
    PT: LocalRelationProviderUnitData,
    RT: LocalRelationRequirerUnitData,
    **PP,
    **RP,
](ops.Object):
    """Base class for provider of a LocalRelation.

    This class is subclassed by concrete implementations of a LocalRelation,
    which are also meant to bind the type variables to concrete implementations
    of the relation unit data. See the non-underscore helper factory function,
    which binds the type variables to the callables used to instantiate the
    relation unit data.
    """

    on = LocalProviderEvents[RT]()  # type: ignore[unused-ignore, reportIncompatibleMethodOverride]

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    relation_name: typing.ClassVar[str]
    provider_data_type: typing.ClassVar[type[PT]]  # type: ignore[unused-ignore, reportGeneralTypeIssues]
    requirer_data_type: typing.ClassVar[type[RT]]  # type: ignore[unused-ignore, reportGeneralTypeIssues]

    def __init__(self, charm: ops.CharmBase, /, *args: PP.args, **kwargs: PP.kwargs):
        # FIXME: once it's possible to subtract arguments from ParamSpec,
        # remove machine_id, ready, and requirers.
        super().__init__(charm, None)
        self.charm = charm
        self.provider_data_factory = functools.partial(self.provider_data_type, *args, **kwargs)  # type: ignore[arg-type]

        relation_name = type(self).relation_name
        self.framework.observe(charm.on[relation_name].relation_created, self._on_relation_created)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)
        self.framework.observe(charm.on[relation_name].relation_departed, self._on_relation_departed)

        self._stored.set_default(requirer_data={}, pending_requirers=set())
        raw_requirer_data = typing.cast(
            collections.abc.MutableMapping[tuple[int, str], typing.Any],
            self._stored.requirer_data,
        )
        self._requirer_data = {
            (relation_id, unit_name): self.requirer_data_type.from_network(unit_data)
            for (relation_id, unit_name), unit_data in raw_requirer_data.items()
        }
        raw_pending_requirers = typing.cast(collections.abc.MutableSet[tuple[int, str]], self._stored.pending_requirers)
        self._pending_requirers = set(raw_pending_requirers)

    def _update_stored_data(self) -> None:
        self._stored.requirer_data = {
            (relation_id, unit_name): unit_data.to_network()
            for (relation_id, unit_name), unit_data in self._requirer_data.items()
        }
        self._stored.pending_requirers = self._pending_requirers

    def _on_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        self._update_relation(event.relation, ready=True)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return

        try:
            data = self.requirer_data_type.load_from_relation(event.relation, remote_unit)
        except pydantic.ValidationError as e:
            logging.warning(f"Local service relation requirer '{remote_unit.name}' provided invalid data: {e}.")
            return

        if data.is_local:
            if (event.relation.id, remote_unit.name) not in self._requirer_data:
                self.on.connected.emit(
                    relation=event.relation,
                    unit=remote_unit,
                )
            self._requirer_data[(event.relation.id, remote_unit.name)] = data
            self._pending_requirers.add((event.relation.id, remote_unit.name))
            self._update_stored_data()
            self.on.data_changed.emit(
                relation=event.relation,
                unit=remote_unit,
                data=data,
            )

    def _on_relation_departed(self, event: ops.RelationDepartedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return

        self._pending_requirers.discard((event.relation.id, remote_unit.name))
        data = self._requirer_data.pop((event.relation.id, remote_unit.name), None)
        self._update_stored_data()
        if data is not None:
            assert data.is_local
            self.on.disconnected.emit(
                relation=event.relation,
                unit=remote_unit,
            )

    def _update_relation(self, relation: ops.Relation, *, ready: bool) -> None:
        if not relation.active:
            return
        # FIXME: these are due to mypy and pyright not supporting pydantic's
        # field alias functionality. Re-evaluate periodically because they
        # won't be reported once they're no longer necessary.
        # Last check (2026-02-26):
        #  mypy - 1.19
        #  pyright - 1.1.408
        requirers = {unit_name for relation_id, unit_name in self._requirer_data if relation_id == relation.id}
        if ready:
            pending_requirers = {
                unit_name for relation_id, unit_name in self._pending_requirers if relation_id == relation.id
            }
        else:
            pending_requirers = set()
        data = self.provider_data_factory(
            ready=ready,
            requirers=requirers - pending_requirers,
        )
        try:
            relation.save(data, self.charm.unit)
        except ops.ModelError as e:
            logging.exception(f"Failed to update relation {relation.name}/{relation.id} data: {e}.")

    def clear_pending_requirers(self) -> None:
        """Mark all work for requirers done."""
        self._pending_requirers.clear()
        self._update_stored_data()

    def begin_configure(self) -> None:
        """Signal to the requirers that configuration reconciliation work has begun."""
        for relation in self.model.relations[type(self).relation_name]:
            self._update_relation(relation, ready=False)

    def end_configure(self, *args: PP.args, **kwargs: PP.kwargs) -> None:
        """Signal to the requirers that configuration reconciliation work has finished."""
        self.provider_data_factory = functools.partial(self.provider_data_type, *args, **kwargs)  # type: ignore[arg-type]
        for relation in self.model.relations[type(self).relation_name]:
            self._update_relation(relation, ready=True)


def LocalProvider[  # noqa: N802
    PT: LocalRelationProviderUnitData,
    RT: LocalRelationRequirerUnitData,
    **PP,
    **RP,
](
    *,
    relation_name: str,
    provider_data_type: collections.abc.Callable[PP, PT],
    requirer_data_type: collections.abc.Callable[RP, RT],
) -> type[_LocalProvider[PT, RT, PP, RP]]:
    """Subclass _LocalProvider via this helper function.

    The passed data types for the unit data bind both the arguments for
    instantiating the unit data and unit data type itself.
    """
    cls: type[_LocalProvider[PT, RT, PP, RP]] = types.new_class('LocalProvider', (_LocalProvider[PT, RT, PP, RP],))
    cls.relation_name = relation_name
    cls.provider_data_type = provider_data_type  # type: ignore[assignment, misc, unused-ignore, reportAttributeAccessIssue]
    cls.requirer_data_type = requirer_data_type  # type: ignore[assignment, misc, unused-ignore, reportAttributeAccessIssue]

    return cls


class _LocalRequirer[
    PT: LocalRelationProviderUnitData,
    RT: LocalRelationRequirerUnitData,
    **PP,
    **RP,
](ops.Object):
    """Base class for requirer of a LocalRelation.

    This class is subclassed by concrete implementations of a LocalRelation,
    which are also meant to bind the type variables to concrete implementations
    of the relation unit data. See the non-underscore helper factory function,
    which binds the type variables to the callables used to instantiate the
    relation unit data.
    """

    on = LocalRequirerEvents[PT]()  # type: ignore[unused-ignore, reportIncompatibleMethodOverride]

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    relation_name: typing.ClassVar[str]
    provider_data_type: typing.ClassVar[type[PT]]  # type: ignore[unused-ignore, reportGeneralTypeIssues]
    requirer_data_type: typing.ClassVar[type[RT]]  # type: ignore[unused-ignore, reportGeneralTypeIssues]

    def __init__(self, charm: ops.CharmBase, /, *args: RP.args, **kwargs: RP.kwargs):
        super().__init__(charm, None)
        self.charm = charm
        self.requirer_data_factory = functools.partial(self.requirer_data_type, *args, **kwargs)  # type: ignore[arg-type]

        relation_name = type(self).relation_name
        self.framework.observe(charm.on[relation_name].relation_created, self._on_relation_created)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)
        self.framework.observe(charm.on[relation_name].relation_departed, self._on_relation_departed)

        self._stored.set_default(provider_unit=None, provider_data=None)

    @property
    def provider_unit(self) -> str | None:
        """The name of the unit that provides the relation.

        Returns None if a provider is not connected.
        """
        return typing.cast(str | None, self._stored.provider_unit)

    @provider_unit.setter
    def provider_unit(self, value: str | None) -> None:
        self._stored.provider_unit = value

    @property
    def provider_data(self) -> PT | None:
        """The data from the provider of the relation.

        Returns None if a provider is not connected.
        """
        try:
            value = typing.cast(PT | None, self.__dict__['provider_data'])
        except KeyError:
            raw_data = self._stored.provider_data
            if raw_data is not None:
                value = type(self).provider_data_type.from_network(raw_data)
            else:
                value = None
            self.__dict__['provider_data'] = value
        return value

    @provider_data.setter
    def provider_data(self, value: PT | None) -> None:
        self.__dict__['provider_data'] = value
        self._stored.provider_data = value.to_network() if value is not None else None

    @property
    def ready(self) -> bool:
        """Returns whether the provider advertises being ready."""
        provider_data = self.provider_data
        return provider_data is not None and provider_data.ready and self.charm.unit.name in provider_data.requirers

    def set_data(self, *args: RP.args, **kwargs: RP.kwargs) -> None:
        self.requirer_data_factory = functools.partial(self.requirer_data_type, *args, **kwargs)  # type: ignore[arg-type]
        for relation in self.model.relations[type(self).relation_name]:
            self._update_relation(relation)

    def _on_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        self._update_relation(event.relation)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return
        if not event.relation.data[remote_unit]:
            logging.debug(f"Local service relation provider '{remote_unit.name}' is not providing any data yet.")
            return

        try:
            data = type(self).provider_data_type.load_from_relation(event.relation, remote_unit)
        except (pydantic.ValidationError, ValueError) as e:
            logging.warning(f"Local service relation provider '{remote_unit.name}' provided invalid data: {e}.")
            return

        if not data.is_local:
            return

        if self.provider_unit is None:
            logging.info(f"Local service requirer connected to new provider unit '{remote_unit.name}'.")
            self.on.connected.emit(
                relation=event.relation,
                unit=remote_unit,
            )
        elif self.provider_unit != remote_unit.name:
            logging.error(
                f"Local service requirer already connected to provider unit '{self.provider_unit}'"
                f" cannot also connect to '{remote_unit.name}'."
            )
            return

        previously_ready = self.ready
        self.provider_unit = remote_unit.name
        self.provider_data = data
        self.on.data_changed.emit(
            relation=event.relation,
            unit=remote_unit,
            data=data,
        )
        if self.ready and not previously_ready:
            logging.info(f"Local service provider '{remote_unit.name}' ready.")
            self.on.ready.emit(
                relation=event.relation,
                unit=remote_unit,
            )

    def _on_relation_departed(self, event: ops.RelationDepartedEvent) -> None:
        remote_unit = event.unit
        if not remote_unit:
            return

        if self.provider_unit is None or remote_unit.name != self.provider_unit:
            return

        logging.info(f"Local service requirer disconnected from provider unit '{remote_unit.name}'.")
        # old_provider_unit = self.provider_unit
        # old_data = self.provider_data
        self.provider_unit = None
        self.provider_data = None
        self.on.disconnected.emit(
            relation=event.relation,
            unit=remote_unit,
        )

    def _update_relation(self, relation: ops.Relation) -> None:
        if not relation.active:
            return
        # FIXME: these are due to mypy and pyright not supporting pydantic's
        # field alias functionality. Re-evaluate periodically because they
        # won't be reported once they're no longer necessary.
        # Last check (2026-02-26):
        #  mypy - 1.19
        #  pyright - 1.1.408
        # data = ServerRelationRequirerUnitData(  # type: ignore [reportCallIssue, unused-ignore]
        #     machine_id=ServerRelationRequirerUnitData.get_machine_id(),
        # type: ignore [reportCallIssue, call-arg, unused-ignore]
        # )
        data = self.requirer_data_factory()
        relation.save(data, self.charm.unit)


def LocalRequirer[  # noqa: N802
    PT: LocalRelationProviderUnitData,
    RT: LocalRelationRequirerUnitData,
    **PP,
    **RP,
](
    *,
    relation_name: str,
    provider_data_type: collections.abc.Callable[PP, PT],
    requirer_data_type: collections.abc.Callable[RP, RT],
) -> type[_LocalRequirer[PT, RT, PP, RP]]:
    """Subclass _LocalRequirer via this helper function.

    The passed data types for the unit data bind both the arguments for
    instantiating the unit data and unit data type itself.
    """
    cls: type[_LocalRequirer[PT, RT, PP, RP]] = types.new_class('LocalRequirer', (_LocalRequirer[PT, RT, PP, RP],))
    cls.relation_name = relation_name
    cls.provider_data_type = provider_data_type  # type: ignore[assignment, misc, unused-ignore, reportAttributeAccessIssue]
    cls.requirer_data_type = requirer_data_type  # type: ignore[assignment, misc, unused-ignore, reportAttributeAccessIssue]

    return cls


class RsyncRelationUnitData(BaseRelationData):
    path: str
    module: str
    read_only: bool = pydantic.Field(alias='read-only', default=True)
    comment: str
