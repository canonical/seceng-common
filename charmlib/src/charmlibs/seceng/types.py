# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Base types used throughout the library.

Module providing a types that are generic and useful throughout the library.
"""

type JSONType = JSON | bool | int | float | str | list[JSONType]
type JSON = dict[str, JSONType]
