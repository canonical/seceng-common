# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import importlib.resources

import pydantic
import pytest
import yaml

from charmlibs.seceng.template import TemplateConfig


def test_templates_embedded() -> None:
    with importlib.resources.files(TemplateConfig.__module__).joinpath('templates.yaml').open('r') as file:
        TemplateConfig.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]


def test_templates_invalid() -> None:
    # Extra field
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'foo': 0,
        })  # fmt: skip

    # Wrong user type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'files': [
                {
                    'name': 'foo',
                    'template': '',
                    'user': 0,
                },
            ],
        })  # fmt: skip

    # Wrong group type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'files': [
                {
                    'name': 'foo',
                    'template': '',
                    'group': 0,
                },
            ],
        })  # fmt: skip

    # Missing file name
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'files': [
                {
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Missing file template
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'files': [
                {
                    'name': 'foo',
                },
            ],
        })  # fmt: skip

    # Wrong file name type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'files': [
                {
                    'name': 0,
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Wrong file templates type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
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
        TemplateConfig.model_validate({
            'files': [
                {
                    'name': 'foo',
                    'permission': 0,
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Missing debconf name
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'type': 'password',
                    'package': 'bar',
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Missing debconf package
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 'foo',
                    'type': 'password',
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Missing debconf template
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 'foo',
                    'type': 'password',
                    'package': 'bar',
                },
            ],
        })  # fmt: skip

    # Wrong debconf name type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 0,
                    'type': 'password',
                    'package': 'bar',
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Wrong debconf type type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 'foo',
                    'type': 0,
                    'package': 'bar',
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Wrong debconf package type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 'foo',
                    'type': 'password',
                    'package': 0,
                    'template': '',
                },
            ],
        })  # fmt: skip

    # Wrong debconf templates type
    with pytest.raises(pydantic.ValidationError):
        TemplateConfig.model_validate({
            'debconf': [
                {
                    'name': 'foo',
                    'type': 'password',
                    'package': 'bar',
                    'template': 0,
                },
            ],
        })  # fmt: skip
