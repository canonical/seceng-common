# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import importlib.resources

import pydantic
import pytest
import yaml

from charmlibs.seceng.base import SecretsRoot


def test_config_embedded() -> None:
    with importlib.resources.files(SecretsRoot.__module__).joinpath('secrets.yaml').open('r') as file:
        SecretsRoot.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]


def test_config_invalid() -> None:
    # Extra field
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'x': 0,
                'files': [],
            }
        })  # fmt: skip

    # Wrong user type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'user': 0,
                'files': [],
            }
        })  # fmt: skip

    # Wrong group type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'group': 0,
                'files': [],
            }
        })  # fmt: skip

    # Missing file name
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'variables': {},
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Missing file variables
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Missing file template
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'variables': {},
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file name type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': 0,
                        'variables': {},
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file variables type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'variables': '',
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file templates type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'variables': {},
                        'template': 0,
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file permission type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'permission': 0,
                        'variables': {},
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file variables elements key type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'variables': {0: ''},
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file variables elements value type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'files': [
                    {
                        'name': '',
                        'variables': {'': 0},
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip
