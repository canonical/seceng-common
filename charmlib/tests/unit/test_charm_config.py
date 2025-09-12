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
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Missing debconf name
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'package': '',
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Missing debconf package
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'name': '',
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Missing debconf template
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'name': '',
                        'package': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong debconf name type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'name': 0,
                        'package': '',
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong debconf package type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'name': '',
                        'package': 0,
                        'template': '',
                    },
                ]
            }
        })  # fmt: skip

    # Wrong file templates type
    with pytest.raises(pydantic.ValidationError):
        SecretsRoot.model_validate({
            'foo': {
                'debconf': [
                    {
                        'name': '',
                        'package': '',
                        'template': 0,
                    },
                ]
            }
        })  # fmt: skip
