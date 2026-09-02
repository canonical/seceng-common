# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Base classes for SecEng charms.

Module providing base charm classes for common functionality used by the
Security Engineering team at Canonical.
"""

import collections.abc
import dataclasses
import importlib.resources
import logging
import os
import pathlib
import subprocess
import sys
import typing

import ops
import pydantic
import yaml
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from . import utils
from . import workload
from .template import TemplateEngine
from .workload import Wheelhouse, WheelhouseError


# The active version plus one previous, which is the rollback target: reverting
# is a symlink flip, so it only works while the previous venv is still on disk.
_RETAINED_VENVS = 2


class _WheelhouseConfigError(Exception):
    """Report a configuration fault whose message is the blocked status verbatim.

    Separate from ``WheelhouseError`` because these are operator input problems
    rather than install failures, so they are reported as their own message
    instead of being wrapped in "worker install failed".
    """


def _failure_reason(error: Exception) -> str:
    """Summarise an install failure as program plus exit code.

    ``CalledProcessError`` stringifies to its whole command line and is reduced to
    the program and exit code. The credential is on stdin, so no command line
    reaching here can carry it.
    """
    if isinstance(error, subprocess.CalledProcessError):
        command = error.cmd
        program = command[0] if isinstance(command, (list, tuple)) and command else command
        return f'{pathlib.Path(str(program)).name} exited with status {error.returncode}'
    return str(error)


@dataclasses.dataclass(kw_only=True, frozen=True)
class Package:
    name: str
    ppa: str | None = 'ubuntu-security-infra'


@dataclasses.dataclass(kw_only=True, frozen=True)
class Snap:
    name: str
    channel: str = 'stable'


@dataclasses.dataclass(kw_only=True)
class DebconfConfig:
    name: str
    package: str
    template: str


@dataclasses.dataclass(kw_only=True)
class FileConfig:
    name: str
    permission: str | None = None
    template: str


class SecretConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

    user: str | None = None
    group: str | None = None
    debconf: list[DebconfConfig] = []
    files: list[FileConfig] = []


class SecretsRoot(pydantic.RootModel[dict[str, SecretConfig]]):
    def __len__(self) -> int:
        return len(self.root)

    def __iter__(self) -> collections.abc.Iterator[str]:  # type: ignore[override]
        return iter(self.root)

    def __getitem__(self, name: str) -> SecretConfig:
        return self.root[name]

    def __contains__(self, name: str) -> bool:
        return name in self.root

    def items(self) -> collections.abc.Iterable[tuple[str, SecretConfig]]:
        return self.root.items()


class SecEngCharmBase(ops.CharmBase):
    """Common base for SecEng charms.

    A base charm providing support for installing deb packages from PPAs,
    installing a Python workload from a wheelhouse release, and creating files
    from juju secrets.
    """

    package_install_list: list[Package] = []
    snap_install_list: list[Snap] = []
    wheelhouse_install_list: list[Wheelhouse] = []

    secrets_config: str | None = None
    templates: list[pathlib.Path] = []

    _stored = ops.StoredState()  # type: ignore[no-untyped-call]

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._setup_proxies()
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)
        framework.observe(self.on.secret_changed, self._seceng_base_on_secret_changed)
        framework.observe(self.on.upgrade_charm, self._seceng_base_on_upgrage_charm)
        framework.observe(self.on.collect_unit_status, self._seceng_base_on_collect_unit_status)

        self.template_engine = TemplateEngine(self)
        self._stored.set_default(configured_ppas=[], installed_packages=[], wheelhouse_reasons={})

    def _setup_proxies(self) -> None:
        """Set up proxy environment variables based on Juju model configuration."""
        # Check model configurations for proxy settings
        http_proxy = os.environ.get("JUJU_CHARM_HTTP_PROXY")
        https_proxy = os.environ.get("JUJU_CHARM_HTTPS_PROXY")
        no_proxy = os.environ.get("JUJU_CHARM_NO_PROXY")

        if http_proxy:
            os.environ["HTTP_PROXY"] = http_proxy
            os.environ["http_proxy"] = http_proxy

        if https_proxy:
            os.environ["HTTPS_PROXY"] = https_proxy
            os.environ["https_proxy"] = https_proxy

        if no_proxy:
            os.environ["NO_PROXY"] = no_proxy
            os.environ["no_proxy"] = no_proxy

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_ppa_and_packages()
        self._install_snaps()
        self._install_wheelhouses()
        self._install_secrets()
        self._install_templates()

    def _seceng_base_on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        if event.secret.id is not None:
            # Reinstalling handles rotation: each install reads a fresh, uncached token.
            if self._wheelhouse_specs_using_secret(event.secret.id):
                self._install_wheelhouses()
            self._install_secrets(filter_secrets={event.secret.id})
            self._install_templates(dirty_secrets={event.secret.id})

    def _seceng_base_on_upgrage_charm(self, event: ops.UpgradeCharmEvent) -> None:
        # juju refresh preserves configuration, so this is a no-op unless the
        # configured worker version differs from what is installed.
        self._install_wheelhouses()
        self._install_templates()

    def _seceng_base_on_collect_unit_status(self, event: ops.CollectStatusEvent) -> None:
        for spec in self.wheelhouse_install_list:
            for status in self._wheelhouse_statuses(spec):
                event.add_status(status)

    def _install_ppa_and_packages(self) -> None:
        previous_ppas = set(typing.cast(list[str], self._stored.configured_ppas))
        new_ppas = {
            f'ppa:{package.ppa}/{self.config["deployment"]}' for package in self.package_install_list if package.ppa
        }
        for old_ppa in previous_ppas - new_ppas:
            # FIXME: find a solution.
            # Do not do anything, because it could interfere with other charms.
            pass
        for new_ppa in new_ppas - previous_ppas:
            self.unit.status = MaintenanceStatus('Configuring PPA')
            subprocess.check_call(['add-apt-repository', '--yes', '--no-update', '--ppa', new_ppa])
        if new_ppas != previous_ppas:
            subprocess.check_call(['apt-get', 'update'])
            self._stored.configured_ppa = list(new_ppas)
            self._stored.installed_packages = []  # Force reinstallation of packages when PPA changes.

        previous_packages = set(typing.cast(list[str], self._stored.installed_packages))
        new_packages = {package.name for package in self.package_install_list}
        for old_package in previous_packages - new_packages:
            # FIXME: might not be a real issue.
            # Do not do anything, because it could interfere with other charms.
            pass
        for new_package in new_packages - previous_packages:
            subprocess.check_call(['apt-mark', 'install', new_package])
        if new_packages != previous_packages:
            self.unit.status = MaintenanceStatus('Installing Debian packages')
            subprocess.check_call(['apt-get', 'dselect-upgrade', '-y'])
            self._stored.installed_packages = list(new_packages)

    def _install_snaps(self) -> None:
        for snap in self.snap_install_list:
            self.unit.status = MaintenanceStatus(f'Installing Snap: {snap.name} {snap.channel}')
            subprocess.check_call(["snap", "install", "--channel", snap.channel, snap.name])

    def installed_worker_version(self, spec: Wheelhouse) -> str | None:
        """Return the version recorded on disk for one wheelhouse, if any.

        The on-disk stamp is authoritative rather than stored state, so an
        operator can read it directly and it cannot drift from the tree it
        describes.
        """
        return workload.read_stamp(spec.version_stamp)

    def _wheelhouse_specs_using_secret(self, secret_id: str) -> list[Wheelhouse]:
        """Return the wheelhouses whose credential comes from one secret."""
        return [spec for spec in self.wheelhouse_install_list if self.config.get(spec.source_secret_key) == secret_id]

    def _installed_wheelhouses(self) -> dict[str, str]:
        """Return each wheelhouse's active version for the template context.

        Read it at call time because the installing hook changes it between
        construction and render. This reports the active, not configured,
        version.
        """
        installed: dict[str, str] = {}
        for spec in self.wheelhouse_install_list:
            version = workload.current_version(spec)
            if version is not None:
                installed[spec.name] = version
        return installed

    def _wheelhouse_reasons(self) -> dict[str, str]:
        """Return the recorded blocked reason for each failing wheelhouse."""
        return dict(typing.cast(dict[str, str], self._stored.wheelhouse_reasons))

    def _install_wheelhouses(self) -> None:
        """Install every configured wheelhouse without stopping on one failure.

        Record failures rather than raising them, so one wheelhouse cannot stop
        the others or error the hook.
        """
        if not self.wheelhouse_install_list:
            return
        reasons: dict[str, str] = {}
        for spec in self.wheelhouse_install_list:
            try:
                self._install_wheelhouse(spec)
            except _WheelhouseConfigError as error:
                reasons[spec.name] = str(error)
                logging.warning(f"Wheelhouse '{spec.name}' is not configured: {error}")
            except (WheelhouseError, subprocess.CalledProcessError) as error:
                reasons[spec.name] = f'worker install failed: {_failure_reason(error)}'
                logging.exception(f"Wheelhouse '{spec.name}' failed to install.")
        self._stored.wheelhouse_reasons = reasons

    def _install_wheelhouse(self, spec: Wheelhouse) -> None:
        """Install one wheelhouse release, activating it only once it is proven.

        Everything up to ``flip_current`` builds alongside the running version,
        so an earlier failure leaves the previous version serving. Where the
        wheels come from is ``_acquire_wheelhouse``'s decision.
        """
        version = self._wheelhouse_version(spec)
        if self._wheelhouse_is_active(spec, version):
            return

        self.unit.status = MaintenanceStatus(f'installing worker {version}')
        source = self._acquire_wheelhouse(spec, version)

        try:
            if not workload.is_venv_created(spec, version):
                workload.create_venv(spec, version)
            workload.pip_install_wheelhouse(spec, version)
            workload.self_check(spec, version)
            workload.flip_current(spec, version)
        except (WheelhouseError, subprocess.CalledProcessError):
            # A half-built venv left behind would be the newest directory in
            # ``venvs/``, so the next install's prune could retain it as the "one
            # previous" version and delete the working version it exists to roll
            # back to. The active version is never discarded: reaching this guard
            # with it active means a repair attempt on an install that already
            # could not import, so deleting it would remove the unit's interpreter
            # for nothing.
            if workload.current_version(spec) != version:
                workload.remove_venv(spec, version)
            raise
        workload.write_stamp(spec.version_stamp, version)
        workload.write_stamp(spec.source_stamp, source)
        removed = workload.prune_venvs(spec, keep=_RETAINED_VENVS)
        if removed:
            logging.info(f"Pruned worker {', '.join(removed)} for '{spec.name}'.")

    def _acquire_wheelhouse(self, spec: Wheelhouse, version: str) -> str:
        """Put the wheels for one version in ``spec.wheelhouse_dir``.

        Returns a description of where they came from, which the caller records
        in the ``installed-source`` stamp.

        Override to install from somewhere other than a release asset. The
        caller owns venv creation, activation, stamping and pruning, and calls
        this only for a version that is not already active. It handles
        ``_WheelhouseConfigError``, ``WheelhouseError`` and
        ``subprocess.CalledProcessError`` by blocking the unit; anything else
        errors the hook.
        """
        token = self._wheelhouse_token(spec)
        asset = spec.asset_name(version)
        asset_url = workload.resolve_asset_url(spec.repo, version, asset, token)
        tarball = spec.resolved_install_root / asset
        try:
            workload.download_asset(asset_url, tarball, token)
            expected = workload.fetch_checksum(spec.repo, version, asset, token)
            if expected is None:
                # A missing checksum asset means a broken or tampered release; there
                # is deliberately no escape hatch for installing without a checksum.
                raise WheelhouseError(
                    f'release {version} has no {asset}.sha256 checksum asset: refusing to install unverified.'
                )
            workload.verify_sha256(tarball, expected)
            workload.unpack_wheelhouse(tarball, spec.wheelhouse_dir)
        finally:
            # unpack_wheelhouse removes the tarball once it has succeeded; this
            # covers every path that did not get that far.
            tarball.unlink(missing_ok=True)
        return asset_url

    def _wheelhouse_version(self, spec: Wheelhouse) -> str:
        """Return the configured version, or report why it cannot be used."""
        configured = self.config.get(spec.version_config_key)
        version = configured.strip() if isinstance(configured, str) else ''
        if not version:
            raise _WheelhouseConfigError(f'Set {spec.version_config_key}')
        try:
            return workload.validate_version(version)
        except WheelhouseError as error:
            raise _WheelhouseConfigError(str(error)) from error

    def _wheelhouse_token(self, spec: Wheelhouse) -> str:
        """Return the release credential, or report why it cannot be used."""
        secret_id = self.config.get(spec.source_secret_key)
        if not isinstance(secret_id, str) or not secret_id:
            raise _WheelhouseConfigError(f'Set the {spec.source_secret_key} secret')
        try:
            content = self.model.get_secret(id=secret_id).get_content(refresh=True)
        except ops.ModelError as error:
            # ops narrows to SecretNotFoundError only when Juju's stderr says
            # "not found". Catching only that subclass would error the hook and
            # make Juju retry a forgotten ``juju grant-secret`` forever.
            raise _WheelhouseConfigError(
                f'{spec.source_secret_key} secret cannot be read: check it exists and is granted to this application'
            ) from error
        token = content.get(spec.token_key)
        if isinstance(token, str) and token:
            return token
        raise _WheelhouseConfigError(f'{spec.source_secret_key} secret has no {spec.token_key}')

    def _wheelhouse_is_active(self, spec: Wheelhouse, version: str) -> bool:
        """Return whether the requested version is installed, active, and usable."""
        if workload.read_stamp(spec.version_stamp) != version:
            return False
        if workload.current_version(spec) != version:
            return False
        if not workload.is_venv_created(spec, version):
            return False
        try:
            workload.self_check(spec, version)
        except WheelhouseError as error:
            # Reinstalling an active version is safe because its self-check failed.
            logging.warning(f"Reinstalling worker {version} for '{spec.name}': {error}")
            return False
        return True

    def _wheelhouse_statuses(self, spec: Wheelhouse) -> list[ops.StatusBase]:
        """Return the statuses one wheelhouse contributes to collect-status."""
        reason = self._wheelhouse_reasons().get(spec.name)
        if reason:
            # A recorded failure explains any stamp-versus-config gap better
            # than the gap itself.
            return [BlockedStatus(reason)]
        installed = self.installed_worker_version(spec)
        if installed is None:
            return []
        configured = self.config.get(spec.version_config_key)
        if isinstance(configured, str) and configured.strip() and configured.strip() != installed:
            return [
                BlockedStatus(f'worker {configured.strip()} requested but {installed} installed -- reinstall needed')
            ]
        if not workload.service_running(spec.resolved_service_name):
            # Re-evaluate service state during status collection so a workload
            # that later crashes is not reported as active.
            return [BlockedStatus(f'worker {installed} installed but {spec.resolved_service_name} is not running')]
        return [ActiveStatus(f'worker {installed}')]

    def _install_secrets(self, *, filter_secrets: set[str] = set()) -> None:
        # This method should not be called on the install or upgrade hook,
        # because it may rely on package installation from
        self.unit.status = MaintenanceStatus('Installing Secrets')
        logging.warning("About to install secrets...")

        with importlib.resources.as_file(importlib.resources.files() / 'secrets.yaml') as filepath:
            self._install_secrets_file(filepath, filter_secrets=filter_secrets)

        if self.secrets_config is not None:
            self._install_secrets_file(self.charm_dir / self.secrets_config, filter_secrets=filter_secrets)

    def _install_secrets_file(self, filepath: pathlib.Path, *, filter_secrets: set[str] = set()) -> None:
        logging.debug("Parsing secrets file '{}'...".format(filepath))
        with open(filepath, 'r') as file:
            try:
                all_secrets = SecretsRoot.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]
            except pydantic.ValidationError:
                logging.error(f"Failed to load secrets configuration file '{filepath}.'")
                raise

        debconf_packages: set[str] = set()
        debconf_selections: list[str] = []

        for name, secret_id in self.config.items():
            option_type = self.meta.config.get(name)
            if not option_type or option_type.type != 'secret':
                continue
            if name not in all_secrets:
                continue
            if not isinstance(secret_id, str):
                logging.warning(
                    f"Unexpected type for charm configuration item '{name}'"
                    f" of type 'secret': {type(secret_id).__name__}."
                )
                continue
            if filter_secrets and secret_id not in filter_secrets:
                continue

            logging.warning(f"Processing secret '{name}'...")
            secret_entry = all_secrets[name]

            secret_object = self.model.get_secret(id=secret_id)
            secret_content = secret_object.get_content(refresh=True)

            for debconf_entry in secret_entry.debconf:
                value = debconf_entry.template.format(**secret_content)
                try:
                    value = subprocess.check_output(
                        ['debconf-escape', '-e'],
                        input=value,
                        text=True,
                        encoding=sys.stdin.encoding,
                    )
                except subprocess.CalledProcessError as e:
                    raise ValueError(f"failed to escape debconf value '{value}': exit code {e.returncode}")
                debconf_packages.add(debconf_entry.package)
                debconf_selections.append(f'{debconf_entry.package} {debconf_entry.name} password {value}')
                logging.info(f"Queueing debconf option '{debconf_entry.name}' for package '{debconf_entry.package}'.")

            for file_entry in secret_entry.files:
                with utils.open_file_secure(
                    pathlib.Path(file_entry.name),
                    user=secret_entry.user,
                    group=secret_entry.group,
                    mode=int(file_entry.permission, 0) if file_entry.permission is not None else 0o600,
                    create_parents=True,
                ) as f:
                    f.write(file_entry.template.format(**secret_content))
                logging.info(f"Created secrets file '{file_entry.name}'.")

        if debconf_selections:
            try:
                subprocess.run(
                    ['debconf-set-selections'],
                    input='\n'.join(debconf_selections),
                    text=True,
                    encoding=sys.stdin.encoding,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise ValueError(f"failed to run debconf-set-selections: exit code {e.returncode}")
            else:
                logging.info(f"Successfully set {len(debconf_selections)} debconf options.")
        else:
            logging.debug("No debconf options configured.")

        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if debconf_packages and os.geteuid() == 0:
            try:
                subprocess.check_call(['dpkg-reconfigure', '-fnoninteractive'] + list(debconf_packages))
            except subprocess.CalledProcessError as e:
                raise ValueError(f"failed to run dpkg-reconfigure: exit code {e.returncode}")
            else:
                logging.info("Successfully ran dpkg-reconfigure.")

    def _install_templates(self, *, dirty_secrets: set[str] = set()) -> None:
        # This method should not be called on the install hook, because it may
        # rely on package installation from the config changed hook.
        self.unit.status = MaintenanceStatus('Installing templates')
        logging.info("About to install templates...")

        with importlib.resources.as_file(importlib.resources.files() / 'templates.yaml') as filepath:
            self.template_engine.process(
                filepath,
                *(self.charm_dir / template for template in self.templates),
                dirty_secrets=dirty_secrets,
                installed=self._installed_wheelhouses(),
            )
