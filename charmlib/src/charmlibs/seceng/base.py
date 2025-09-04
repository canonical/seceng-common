# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Base classes for SecEng charms.

Module providing base charm classes for common functionality used by the
Security Engineering team at Canonical.
"""

import collections.abc
import contextlib
import dataclasses
import functools
import grp
import importlib.resources
import logging
import os
import pathlib
import pwd
import stat
import subprocess
import typing
from collections import deque

import ops
import pydantic
import yaml
from ops.model import ActiveStatus, MaintenanceStatus


def suppress_wrapper[T, **P](
    callable: collections.abc.Callable[P, T],
    /,
    *exceptions: type[BaseException],
) -> collections.abc.Callable[P, T | None]:
    """Wrap a callable to suppress some of its exceptions.

    The wrapper will return None if an exception is suppressed.
    """

    @functools.wraps(callable)
    def inner(*args: P.args, **kwargs: P.kwargs) -> T | None:
        with contextlib.suppress(*exceptions):
            return callable(*args, **kwargs)
        return None

    return inner


@dataclasses.dataclass(kw_only=True)
class FileConfig:
    name: str
    permission: str | None = None
    variables: dict[str, str]
    template: str


class SecretConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

    user: str | None = None
    group: str | None = None
    files: list[FileConfig]


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

    A base charm providing support for installing deb packages from PPAs and
    creating files from juju secrets.
    """

    package_install_ppa = 'ubuntu-security-infra'
    package_install_list: list[str] = []

    secrets_config: str | None = None

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.install, self._seceng_base_on_install)
        framework.observe(self.on.upgrade_charm, self._seceng_base_on_upgrade)
        framework.observe(self.on.config_changed, self._seceng_base_on_config_changed)

    def _seceng_base_on_install(self, event: ops.InstallEvent) -> None:
        self._install_ppa_and_packages()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_upgrade(self, event: ops.UpgradeCharmEvent) -> None:
        self._install_ppa_and_packages()
        self.unit.status = ActiveStatus('ready')

    def _seceng_base_on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._install_secrets()
        self.unit.status = ActiveStatus('ready')

    def _install_ppa_and_packages(self) -> None:
        self.unit.status = MaintenanceStatus('Installing Debian Package')
        subprocess.check_call(["apt-get", "update"])
        subprocess.check_call(["add-apt-repository", f'ppa:{self.package_install_ppa}/{self.config["deployment"]}'])
        subprocess.check_call(["apt-get", "update"])
        if self.package_install_list:
            subprocess.check_call(["apt-get", "install", "-y"] + self.package_install_list)

    def _install_secrets(self) -> None:
        # This method should not be called on the install or upgrade hook,
        # because it may rely on package installation from
        self.unit.status = MaintenanceStatus('Installing Secrets')
        logging.warning("About to install secrets...")

        with importlib.resources.as_file(importlib.resources.files() / 'secrets.yaml') as filepath:
            self._install_secrets_file(filepath)

        if self.secrets_config is not None:
            self._install_secrets_file(self.charm_dir / self.secrets_config)

    def _install_secrets_file(self, filepath: pathlib.Path) -> None:
        with open(filepath, 'r') as file:
            try:
                all_secrets = SecretsRoot.model_validate(yaml.safe_load(file))  # type: ignore[no-untyped-call]
            except pydantic.ValidationError:
                logging.error(f"Failed to load secrets configuration file '{filepath}.'")
                raise

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

            logging.warning(f"Processing secret '{name}'...")
            secret_entry = all_secrets[name]

            secret_object = self.model.get_secret(id=secret_id)
            secret_content = secret_object.get_content(refresh=True)

            for file_entry in secret_entry.files:
                variables = {}
                for varname, varvalue in file_entry.variables.items():
                    variables[varname] = secret_content[varvalue]

                with self.open_file_secure(
                    pathlib.Path(file_entry.name),
                    user=secret_entry.user,
                    group=secret_entry.group,
                    mode=int(file_entry.permission, 0) if file_entry.permission is not None else 0o600,
                ) as f:
                    f.write(file_entry.template.format(**variables))
                logging.info(f"Created secrets file '{file_entry.name}'.")

    @staticmethod
    @contextlib.contextmanager
    def open_file_secure(
        path: pathlib.Path,
        *,
        user: str | None = None,
        group: str | None = None,
        mode: int = 0o600,
    ) -> collections.abc.Iterator[typing.TextIO]:
        """Securely open a file for writing.

        This code may run as root and needs to safely create files in locations
        owned by a non-privileged user. That means the non-privileged user must
        not be able to influence the file creation in locations it does not
        control.

        If the user parameter is set to a username that does not translate to
        UID 0, that user must not be able to influence the execution of this
        code running with privileges to override a file path that is not
        writable by the user.

        If the user parameter is not set, any non-privileged user must not be
        able to influence the execution of this code running with privileges to
        override a file path that is not writable by the user.

        The value of the input file path is assumed to be trusted, but can
        refer to a file owned by a non-trusted user or with components owned by
        a non-trusted user (e.g. /home/bad-user/filename).

        The function never follows the last component of the path as a symlink
        - it gets replaced by a new regular file that is rename()d over in the
        last directory component of the path.

        Restrictions:
          - The parent paths are owned by UID 0 followed by, optionally the
            user passed as an argument.
          - Directories owned by UID 0 are not writable by any other user
            (unless sticky bit is set).

        Assumptions:
          - Directories owned by root do not have filesystem ACLs (not
            enforced).
          - Hardlink protections are enabled (sysctl fs.protected_hardlinks,
            not enfoced).
          - A root-owned symlink will not be pointing to a user-controlled
            path.
        """
        path = path.absolute()
        uid = pwd.getpwnam(user).pw_uid if user is not None else None
        gid = grp.getgrnam(group).gr_gid if group is not None else None

        with contextlib.ExitStack() as exit_stack:
            dir_fd = None
            enforce_user_owned = False
            seen_dirs: set[tuple[int, int]] = set()
            directory_components = deque(parent.name for parent in reversed(path.parents) if parent.name)
            directory_components.appendleft(path.anchor)
            while directory_components:
                directory_name = directory_components.popleft()
                if directory_name:
                    dir_fd = os.open(directory_name, flags=os.O_PATH | os.O_NOFOLLOW, dir_fd=dir_fd)
                    exit_stack.callback(os.close, dir_fd)

                # An empty component is only added by the symlink follow code
                # below. The initially constructed deque has non-empty
                # components, so dir_fd can never be None here.
                assert dir_fd is not None

                dir_stat = os.stat(dir_fd)
                if (dir_stat.st_dev, dir_stat.st_ino) in seen_dirs:
                    raise OSError("symlink loop detected")
                seen_dirs.add((dir_stat.st_dev, dir_stat.st_ino))

                if dir_stat.st_uid == 0:
                    if enforce_user_owned:
                        raise PermissionError(
                            "cannot traverse directory owned by UID 0 after having previously"
                            " traversed a directory owned by different UID"
                        )
                    if (
                        stat.S_IMODE(dir_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
                        and dir_stat.st_mode & stat.S_ISVTX == 0
                    ):
                        raise PermissionError(
                            "cannot traverse directory owned by UID 0 that is writable by other users"
                        )
                elif uid is not None and dir_stat.st_uid == uid:
                    enforce_user_owned = True
                else:
                    raise PermissionError(f"cannot traverse directory owned by UID {dir_stat.st_uid}")

                if stat.S_ISLNK(dir_stat.st_mode):
                    # It's safe to follow symlinks for directory components
                    # here because either:
                    #  * the link is owned by root and all previous directory
                    #    components were owned by root and the link does not
                    #    point to a user-controlled path (assumption);
                    #  * or, the link is owned by the user and its target is
                    #    owned by the user and all future directory components
                    #    are owned by the user.
                    link_target = os.readlink('', dir_fd=dir_fd)
                    dir_fd = os.open(link_target, flags=os.O_PATH, dir_fd=dir_fd)
                    exit_stack.callback(os.close, dir_fd)
                    directory_components.appendleft('')
                elif not stat.S_ISDIR(dir_stat.st_mode):
                    raise PermissionError("component in path is not a symlink or a directory")

            file_fd = os.open('.', flags=os.O_TMPFILE | os.O_WRONLY, mode=mode, dir_fd=dir_fd)
            exit_stack.callback(os.close, file_fd)

            os.chown(file_fd, uid if uid is not None else -1, gid if gid is not None else -1)

            fileobj = open(file_fd, 'w')
            yield fileobj
            fileobj.flush()

            os.fsync(file_fd)
            tmp_file_name = '.{path.name}.tmp}'
            os.link(f'/proc/self/fd/{file_fd}', tmp_file_name, dst_dir_fd=dir_fd)
            exit_stack.callback(suppress_wrapper(os.unlink, FileNotFoundError), tmp_file_name, dir_fd=dir_fd)

            # FIXME: get rid of rename() and temporary file for linkat() if
            # anything like AT_REPLACE ever becomes available.
            # https://lore.kernel.org/linux-fsdevel/cover.1524549513.git.osandov@fb.com/
            os.rename(tmp_file_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
