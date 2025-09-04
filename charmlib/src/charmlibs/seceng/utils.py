# Copyright 2025 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only

"""Utilities for SecEng charms.

Module providing utility functions and types for charms used by the Security
Engineering team at Canonical.
"""

import collections.abc
import contextlib
import functools
import grp
import os
import pathlib
import pwd
import stat
import typing
from collections import deque


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
    owned by a non-privileged user. That means the non-privileged user must not
    be able to influence the file creation in locations it does not control.

    If the user parameter is set to a username that does not translate to UID
    0, that user must not be able to influence the execution of this code
    running with privileges to override a file path that is not writable by the
    user.

    If the user parameter is not set, any non-privileged user must not be able
    to influence the execution of this code running with privileges to override
    a file path that is not writable by the user.

    The value of the input file path is assumed to be trusted, but can refer to
    a file owned by a non-trusted user or with components owned by a
    non-trusted user (e.g. /home/bad-user/filename).

    The function never follows the last component of the path as a symlink
    - it gets replaced by a new regular file that is rename()d over in the last
      directory component of the path.

    Restrictions:
      - The parent paths are owned by UID 0 followed by, optionally the user
        passed as an argument.
      - Directories owned by UID 0 are not writable by any other user (unless
        sticky bit is set).

    Assumptions:
      - Directories owned by root do not have filesystem ACLs (not enforced).
      - Hardlink protections are enabled (sysctl fs.protected_hardlinks, not
        enfoced).
      - A root-owned symlink will not be pointing to a user-controlled path.
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
        assert len(directory_components) > 0  # Needed by logic below.
        while directory_components:
            directory_name = directory_components.popleft()
            if directory_name:
                dir_fd = os.open(directory_name, flags=os.O_PATH | os.O_NOFOLLOW, dir_fd=dir_fd)
                exit_stack.callback(os.close, dir_fd)

            # An empty component is only added by the symlink follow code
            # below. The initially constructed deque has non-empty components,
            # so dir_fd can never be None here.
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
                    raise PermissionError("cannot traverse directory owned by UID 0 that is writable by other users")
            elif uid is not None and dir_stat.st_uid == uid:
                enforce_user_owned = True
            else:
                raise PermissionError(f"cannot traverse directory owned by UID {dir_stat.st_uid}")

            if stat.S_ISLNK(dir_stat.st_mode):
                # It's safe to follow symlinks for directory components here
                # because either:
                #  * the link is owned by root and all previous directory
                #    components were owned by root and the link does not point
                #    to a user-controlled path (assumption);
                #  * or, the link is owned by the user and its target is owned
                #    by the user and all future directory components are owned
                #    by the user.
                link_target = os.readlink('', dir_fd=dir_fd)
                dir_fd = os.open(link_target, flags=os.O_PATH, dir_fd=dir_fd)
                exit_stack.callback(os.close, dir_fd)
                directory_components.appendleft('')
            elif not stat.S_ISDIR(dir_stat.st_mode):
                raise PermissionError("component in path is not a symlink or a directory")

        if stat.S_IMODE(dir_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("last directory in the path must only be writable by the owner")

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
