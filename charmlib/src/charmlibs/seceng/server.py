# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Requirer interface implementation for server relation.

Module providing the implementation details for charms that are the requirer
side of the server relation and interact with the canonical-seceng-server
charm.
"""

__all__ = ['ServerProvider', 'ServerRequirer', 'ServerProviderUnitData', 'ServerRequirerUnitData']

from .interfaces import LocalProvider, LocalRequirer, LocalRelationProviderUnitData, LocalRelationRequirerUnitData


class ServerProviderUnitData(LocalRelationProviderUnitData):
    """Data sent by a server provider."""


class ServerRequirerUnitData(LocalRelationRequirerUnitData):
    """Data sent by a server requirer."""


# See the comment below for ServerRequirer, applicable here as well.
ServerProvider = LocalProvider(
    relation_name='server',
    provider_data_type=ServerProviderUnitData,
    requirer_data_type=ServerRequirerUnitData,
)


# mypy does not support subclassing dynamic classes, hence the following
# instead of:
# class ServerRequirer(
#     LocalRequirer(
#         relation_name='server',
#         provider_data_type=ServerRelationProviderUnitData,
#         requirer_data_type=ServerRelationRequirerUnitData,
#     ),
# ):
#     """Handle Server relations."""
#
# Have also attempted decorators, but they have the same issue.
# def LocalRequirer[  # noqa: N802
#     PT: LocalRelationProviderUnitData,
#     RT: LocalRelationRequirerUnitData,
#     **PP,
#     **RP,
# ](
#     *,
#     relation_name: str,
#     provider_data_type: collections.abc.Callable[PP, PT],
#     requirer_data_type: collections.abc.Callable[RP, RT],
# ) -> collections.abc.Callable[[type], type[_LocalRequirer[PT, RT, PP, RP]]]:
#
#     def wrapper(cls: type) -> type[_LocalRequirer[PT, RT, PP, RP]]:
#         import types
#
#         cls = types.new_class(cls.__name__, (cls, _LocalRequirer[PT, RT, PP, RP]))
#         cls.relation_name = relation_name
#         cls.provider_data_type = provider_data_type
#         cls.requirer_data_type = requirer_data_type
#
#         return cls
#
#     return wrapper
ServerRequirer = LocalRequirer(
    relation_name='server',
    provider_data_type=ServerProviderUnitData,
    requirer_data_type=ServerRequirerUnitData,
)
