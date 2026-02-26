# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Interface definitions for SecEng charms.

Module providing common charm interface functionality used by the Security
Engineering team at Canonical.
"""

import collections.abc
import contextlib
import json
import logging
import traceback
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


class RsyncRelationUnitData(BaseRelationData):
    path: str
    module: str
    read_only: bool = pydantic.Field(alias='read-only', default=True)
    comment: str


class ServerRelationUnitData(BaseRelationData):
    @staticmethod
    def get_machine_id() -> uuid.UUID:
        try:
            machine_id = open('/etc/machine-id').read().strip()
        except OSError as e:
            raise RuntimeError(f"cannot read '/etc/machine-id' file: {e.strerror}") from None
        try:
            return uuid.UUID(machine_id)
        except ValueError:
            raise RuntimeError(f"file '/etc/machine-id' does not contain a 32-hex-digit string: {machine_id}")

    machine_id: uuid.UUID = pydantic.Field(alias='machine-id')

    @property
    def is_local(self) -> bool:
        return self.machine_id == self.get_machine_id()


class ServerRelationProviderUnitData(ServerRelationUnitData):
    ready: bool


class ServerRelationRequirerUnitData(ServerRelationUnitData):
    pass
