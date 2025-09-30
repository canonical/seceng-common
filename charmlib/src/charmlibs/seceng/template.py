# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Support for charm templated actions.

Module providing a TemplateEngine type that can parse files containing the
definition of debconf or file templates which use f-string evaluation within a
given context.
"""

from __future__ import annotations

__all__ = ['Namespace', 'TemplateEngine', 'TemplateError']

import abc
import collections.abc
import dataclasses
import logging
import os
import pathlib
import subprocess
import sys
import typing
from collections import deque

import pydantic
import pydantic_core
import yaml

from . import utils
from .types import JSON, JSONType


class TemplateError(Exception):
    pass


class Action(abc.ABC):
    @abc.abstractmethod
    def execute(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def __eq__(self, other: typing.Any) -> bool:
        # Subclasses of Action must implement __eq__ and __hash__ so that they
        # can be compared to each other to allow duplicates to be removed.
        raise NotImplementedError

    @abc.abstractmethod
    def __hash__(self) -> int:
        raise NotImplementedError

    @staticmethod
    def parse(action: str) -> Action:
        if action.startswith('dpkg-reconfigure:'):
            package = action.split(':', 1)[1]
            return DpkgReconfigureAction(package)
        elif action == 'systemctl:daemon-reload':
            return SystemctlDaemonReloadAction()
        else:
            raise ValueError(f"unsupported action '{action}'")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: typing.Any, handler: pydantic.GetCoreSchemaHandler
    ) -> pydantic_core.CoreSchema:
        return pydantic_core.core_schema.no_info_after_validator_function(cls.parse, handler(str))


class DpkgReconfigureAction(Action):
    def __init__(self, package: str):
        if not package:
            raise ValueError("package must not be empty")
        self.package = package

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, DpkgReconfigureAction):
            return False
        return self.package == other.package

    def __hash__(self) -> int:
        return hash(self.package)

    def execute(self) -> None:
        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if os.geteuid() == 0:
            logging.info(f"About to reconfigure package '{self.package}'.")
            subprocess.check_call(['dpkg-reconfigure', '-fnoninteractive', self.package])
        else:
            logging.warning(f"Skipping reconfigure of package '{self.package}' because we're not running as root.")


class SystemctlDaemonReloadAction(Action):
    def __eq__(self, other: typing.Any) -> bool:
        return type(other) is type(self)

    def __hash__(self) -> int:
        return hash(type(self))

    def execute(self) -> None:
        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if os.geteuid() == 0:
            logging.info("About to reload systemd daemon.")
            subprocess.check_call(['systemctl', 'daemon-reload'])
        else:
            logging.warning("Skipping reloading of systemd daemon because we're not running as root.")


@dataclasses.dataclass(kw_only=True)
class DebconfConfig:
    silentfail: bool = False
    name: str
    type: typing.Literal['password', 'select', 'string']
    package: str
    actions: list[Action] = dataclasses.field(default_factory=list)
    template: str


@dataclasses.dataclass(kw_only=True)
class FileConfig:
    silentfail: bool = False
    name: str
    user: str | None = None
    group: str | None = None
    permission: str | None = None
    actions: list[Action] = dataclasses.field(default_factory=list)
    file: str | None = None
    template: str | None = None

    def __post_init__(self) -> None:
        options = [self.file, self.template]
        if options.count(None) != len(options) - 1:
            raise ValueError("exactly one of file or template must be specified for FileConfig")


class TemplateConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

    debconf: list[DebconfConfig] = []
    files: list[FileConfig] = []


class Namespace:
    def __init__(self, **kwargs: JSONType):
        self.__dict__.update(kwargs)
        self._accessed: set[str] = set()
        self._dirty: set[str] = set()

    def items(self) -> collections.abc.Iterable[tuple[str, JSONType]]:
        for name, value in self.__dict__.items():
            if name and name[0] != '_':
                yield name, value

    def get_access(self) -> set[str]:
        return self._accessed.copy()

    def clear_access(self) -> None:
        self._accessed.clear()

    def is_dirty(self, name: str) -> bool:
        return name in self._dirty

    def mark_dirty(self, name: str) -> None:
        if name not in self.__dict__:
            raise AttributeError(name)
        self._dirty.add(name)

    def __getattribute__(self, name: str) -> typing.Any:
        if name.startswith('__'):
            return super().__getattribute__(name)

        # This is slightly different than the usual attribute lookup, because
        # data descriptors normally take precedence over the instance's
        # dictionary.
        try:
            value = self.__dict__[name]
        except KeyError:
            return super().__getattribute__(name)
        else:
            if name and name[0] != '_':
                self._accessed.add(name)
            return value

    def __setattr__(self, name: str, value: JSONType) -> None:
        self.__dict__[name] = value

    def __getitem__(self, name: str) -> JSONType:
        try:
            return typing.cast(JSONType, getattr(self, name))
        except AttributeError as e:
            raise KeyError(e.name) from None

    def __setitem__(self, name: str, value: JSONType) -> None:
        try:
            setattr(self, name, value)
        except AttributeError as e:
            raise KeyError(e.name) from None


@dataclasses.dataclass(kw_only=True)
class AccessInfo:
    namespace: str
    attribute: str


class State(pydantic.BaseModel):
    context: dict[str, dict[str, JSONType]] = {}
    accessed: dict[str, list[AccessInfo]] = {}


class TemplateEngine:
    def __init__(self, *, context: dict[str, Namespace], state: JSON | None = None, base_dir: pathlib.Path):
        self.context = context
        self.state = State.model_validate(state) if state is not None else State()
        self.base_dir = base_dir

        # Check if any of the values in the context have changed since the last
        # invocation, based on the state.
        for ctx_name, ctx_namespace in context.items():
            state_context: dict[str, JSONType] | None
            try:
                state_context = self.state.context[ctx_name]
            except KeyError:
                state_context = None
            for key, value in ctx_namespace.items():
                if state_context is None or key not in state_context:
                    ctx_namespace.mark_dirty(key)
                elif value != state_context[key]:
                    ctx_namespace.mark_dirty(key)
        self.state.context = {ctx_name: dict(ctx_namespace.items()) for ctx_name, ctx_namespace in context.items()}

    def save_state(self) -> JSON:
        return self.state.model_dump()

    def process(self, *filepaths: pathlib.Path) -> None:
        actions: deque[Action] = deque()
        for filepath in filepaths:
            self._process_template_file(filepath, actions)
        for action in actions:
            action.execute()

    def _process_template_file(self, filepath: pathlib.Path, actions: deque[Action]) -> None:
        def update_actions(new_actions: collections.abc.Iterable[Action]) -> None:
            # This function updates actions (in the outer scope) to add the
            # entries in new_actions, but without duplicating entries in
            # actions unless necessary. The order of items in actions is not
            # changed and nor is the order of items in new_actions. However,
            # new items can be interleaved. If actions already contains an
            # identical (compared with ==) item, a new one is not added, unless
            # the previously mentioned constraints cannot be kept.
            # Example:
            #  - actions is: A, B, C, A
            #  - new_actions is: C, B, A
            #  - result is: A, B, C, B, A
            search_index = 0
            for action in new_actions:
                try:
                    search_index = actions.index(action, search_index)
                except ValueError:
                    actions.insert(search_index, action)

        with open(filepath, 'r') as file:
            try:
                template_config = TemplateConfig.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]
            except pydantic.ValidationError:
                logging.error(f"Failed to load templates configuration file '{filepath}.'")
                raise

        for debconf_entry in template_config.debconf:
            entry_actions = self._process_debconf_entry(debconf_entry)
            update_actions(entry_actions)

        for file_entry in template_config.files:
            entry_actions = self._process_file_entry(file_entry)
            update_actions(entry_actions)

    def _process_debconf_entry(self, entry: DebconfConfig) -> collections.abc.Iterable[Action]:
        if not self._check_dirty_context(f'debconf:{entry.name}'):
            return []

        try:
            value, accesses = self._evaluate_template(entry.template)
        except TemplateError as e:
            if entry.silentfail:
                logging.debug(
                    f"Ignoring debconf option '{entry.name}' for package '{entry.package}'"
                    f" due to missing referenced object: {e.__cause__}."
                )
                return []
            else:
                raise
        try:
            value = subprocess.check_output(
                ['debconf-escape', '-e'],
                input=value,
                text=True,
                encoding=sys.stdin.encoding,
            )
        except subprocess.CalledProcessError as e:
            raise ValueError(f"failed to escape debconf value '{value}': exit code {e.returncode}")

        try:
            subprocess.run(
                ['debconf-set-selections'],
                input=f'{entry.package} {entry.name} {entry.type} {value}',
                text=True,
                encoding=sys.stdin.encoding,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise ValueError(f"failed to run debconf-set-selections: exit code {e.returncode}")
        else:
            logging.info(f"Configured debconf option '{entry.name}' for package '{entry.package}'.")

        self.state.accessed[f'debconf:{entry.name}'] = list(accesses)

        return entry.actions + [DpkgReconfigureAction(entry.package)]

    def _process_file_entry(self, entry: FileConfig) -> collections.abc.Iterable[Action]:
        if not self._check_dirty_context(f'file:{entry.name}'):
            return []

        accesses: collections.abc.Iterable[AccessInfo]

        if entry.file is not None:
            utils.copy_file_secure(
                self.base_dir / pathlib.Path(entry.file),
                pathlib.Path(entry.name),
                user=entry.user,
                group=entry.group,
                mode=int(entry.permission, 8) if entry.permission is not None else 0o600,
                create_parents=True,
            )
            accesses = []
        elif entry.template is not None:
            try:
                content, accesses = self._evaluate_template(entry.template)
            except TemplateError as e:
                if entry.silentfail:
                    logging.debug(
                        f"Ignoring templated file '{entry.name}' due to missing referenced object: {e.__cause__}."
                    )
                    return []
                else:
                    raise
            with utils.open_file_secure(
                pathlib.Path(entry.name),
                user=entry.user,
                group=entry.group,
                mode=int(entry.permission, 8) if entry.permission is not None else 0o600,
                create_parents=True,
            ) as f:
                f.write(content)
        else:
            raise RuntimeError("BUG: entry should have been validated")

        logging.info(f"Created templated file '{entry.name}'.")

        self.state.accessed[f'file:{entry.name}'] = list(accesses)

        return entry.actions

    def _check_dirty_context(self, entry_name: str) -> bool:
        try:
            access_list = self.state.accessed[entry_name]
        except KeyError:
            # If the entry does not have an access history in the state, assume
            # it needs to be processed. This would happen if this is the first
            # time the entry is processed.
            return True

        for access_info in access_list:
            try:
                namespace = self.context[access_info.namespace]
            except KeyError:
                # The current context no longer contains the named namespace,
                # it may no longer be necessary. This is strange, because on an
                # upgrade, the state is supposed to be reset. This means the
                # TemplateEngine was instantiated with a context that contained
                # different keys. Consider this a bug in the application.
                raise RuntimeError(f"BUG: context does not have previously used key '{access_info.namespace}'")
            if namespace.is_dirty(access_info.attribute):
                return True

        # No attribute of any context namespace that was previously accessed
        # was dirty.
        return False

    def _evaluate_template(self, template: str) -> tuple[str, collections.abc.Iterable[AccessInfo]]:
        # First, clear the access for all the namespaces.
        for namespace in self.context.values():
            namespace.clear_access()

        # The following line doesn't actually work if template contains the
        # quote that repr chooses as the outer quote, because of PEP-0701.
        # TL;DR: f'{'hello'}' is valid, but f'{\'hello\'}' isn't and this is
        # what *could* be generated by repr if the input is: {'hello'}.
        # template = 'f' + repr(template)
        # This line won't work if the template contains """ outside of {}
        # expressions; inside they would work. The only alternative is to split
        # by {, taking escaping into account, and concatenate multiple
        # contructed f-strings, which are then evaluated.
        template = f'f"""{template}"""'

        # This is evaluating an f-string taken from a configuration file. This
        # is a dangerous operation with untrusted input (arbitrary execution),
        # but the contents of the file are considered to be trusted (they are
        # embedded in the same distribution artifact as the code that calls
        # this method).
        try:
            value = eval(template, self.context.copy())
        except (AttributeError, KeyError):
            raise TemplateError("referenced object does not exist")

        accesses: list[AccessInfo] = []
        for namespace_name, namespace in self.context.items():
            for attribute in namespace.get_access():
                accesses.append(AccessInfo(namespace=namespace_name, attribute=attribute))

        return value, accesses
