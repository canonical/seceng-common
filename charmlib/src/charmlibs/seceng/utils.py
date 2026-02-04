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
import hashlib
import os
import pathlib
import pwd
import re
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


def _open_or_create_directory(
    name: str,
    *,
    dir_fd: int | None,
    create: bool = True,
    uid: int | None = None,
    gid: int | None = None,
) -> int:
    try:
        directory_name, params_string = name.rsplit('!', 1)
    except ValueError:
        directory_name = name
        params = {}
    else:
        params = {
            key: (value if sep else None)
            for key, sep, value in (s.partition('=') for s in re.split(r'\s*,\s*', params_string))
            if key
        }

    while True:
        try:
            return os.open(directory_name, flags=os.O_PATH | os.O_NOFOLLOW, dir_fd=dir_fd)
        except FileNotFoundError:
            if not create:
                raise
            parents_mode = int(params.get('mode') or '0o700', 8)
            try:
                os.mkdir(directory_name, mode=parents_mode, dir_fd=dir_fd)
            except FileExistsError:
                continue

            try:
                new_dir_fd = os.open(directory_name, flags=os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            except (FileNotFoundError, NotADirectoryError):
                continue
            try:
                # If the directory pointed to by dir_fd is a user-controlled
                # path, they could only have replaced the new directory made
                # above with another directory, because otherwise the above
                # open() would have failed due to O_DIRECTORY | O_NOFOLLOW.
                os.chown(
                    new_dir_fd,
                    uid=uid or -1 if 'uid' in params else -1,
                    gid=gid or -1 if 'gid' in params else -1,
                )
            except:
                os.close(new_dir_fd)
                raise
            else:
                return new_dir_fd


@typing.overload
@contextlib.contextmanager
def open_file_secure(
    path: pathlib.Path,
    *,
    user: str | None = None,
    group: str | None = None,
    mode: int = 0o600,
    create_parents: bool = False,
    text: typing.Literal[True] = True,
) -> collections.abc.Iterator[typing.TextIO]: ...


@typing.overload
@contextlib.contextmanager
def open_file_secure(
    path: pathlib.Path,
    *,
    user: str | None = None,
    group: str | None = None,
    mode: int = 0o600,
    create_parents: bool = False,
    text: typing.Literal[False],
) -> collections.abc.Iterator[typing.BinaryIO]: ...


@contextlib.contextmanager
def open_file_secure(
    path: pathlib.Path,
    *,
    user: str | None = None,
    group: str | None = None,
    mode: int = 0o600,
    create_parents: bool = False,
    text: bool = True,
) -> collections.abc.Iterator[typing.BinaryIO | typing.TextIO]:
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

    Each directory component of the path can contain parameters after a '!'
    character, which affect the creation of that directory:
      - mode=X - the directory is created with the specified mode (as octal);
        defaults to 700
      - uid - the directory owner is changed to the user specified as an
        argument to the function, after creation
      - gid - the directory group is changed to the group specified as an
        argument to the function, after creation

    If a directory exists, its mode and owner/group are not changed.

    For example, if the path is /var/lib/foo!mode=710,gid/bar!uid,gid/baz:
      - /var and /var/lib and created as owned by root:root and with mode 700
        (although they would normally exist).
      - /var/lib/foo is created as owned by root:group with mode 710.
      - /var/lib/foo/bar is created as owned by user:group with mode 700.
      - The file baz is created under /var/lib/foo/bar according to the rest of
        the function parameters.
    """
    path = path.absolute()
    uid = pwd.getpwnam(user).pw_uid if user is not None else None
    gid = grp.getgrnam(group).gr_gid if group is not None else None

    with contextlib.ExitStack() as exit_stack:
        dir_fd = None
        prev_dir_fd = None
        enforce_user_owned = False
        seen_dirs: set[tuple[int, int]] = set()
        directory_components = deque(parent.name for parent in reversed(path.parents) if parent.name)
        directory_components.appendleft(path.anchor)
        if any(parent.startswith('!') for parent in directory_components):
            raise ValueError("no path component can begin with the '!' character")
        assert len(directory_components) > 0  # Needed by logic below.

        while directory_components:
            directory_name = directory_components.popleft()
            if directory_name:
                # This is safe because this either opens a path with O_NOFOLLOW
                # in the directory pointed at by dir_fd or it creates a new
                # directory, but one of the following conditions must hold:
                #   * enforce_user_owned = False (which means no
                #     user-controlled path was previously traversed);
                #   * or, the directory pointed to by dir_fd is owned by the
                #     user.
                prev_dir_fd = dir_fd
                dir_fd = _open_or_create_directory(
                    directory_name,
                    dir_fd=dir_fd,
                    create=create_parents,
                    uid=uid,
                    gid=gid,
                )
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
                    not stat.S_ISLNK(dir_stat.st_mode)
                    and stat.S_IMODE(dir_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
                    and dir_stat.st_mode & stat.S_ISVTX == 0
                ):
                    raise PermissionError(f"cannot traverse directory '{directory_name}' owned by UID 0 that is writable by other users")
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
                dir_fd = os.open(link_target, flags=os.O_PATH, dir_fd=prev_dir_fd)
                exit_stack.callback(os.close, dir_fd)
                directory_components.appendleft('')
            elif not stat.S_ISDIR(dir_stat.st_mode):
                raise PermissionError("component in path is not a symlink or a directory")

        if stat.S_IMODE(dir_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("last directory in the path must only be writable by the owner")

        file_fd = os.open('.', flags=os.O_TMPFILE | os.O_WRONLY, mode=mode, dir_fd=dir_fd)
        exit_stack.callback(os.close, file_fd)

        os.chown(file_fd, uid if uid is not None else -1, gid if gid is not None else -1)

        fileobj: typing.BinaryIO | typing.TextIO
        if text:
            fileobj = open(file_fd, 'w')
        else:
            fileobj = open(file_fd, 'wb')
        # mypy does not handle the much simpler:
        # fileobj = open(file_fd, 'w' if text else 'wb')
        yield fileobj
        fileobj.flush()

        os.fsync(file_fd)
        tmp_file_name = f'.{path.name}.tmp'
        os.link(f'/proc/self/fd/{file_fd}', tmp_file_name, dst_dir_fd=dir_fd)
        exit_stack.callback(suppress_wrapper(os.unlink, FileNotFoundError), tmp_file_name, dir_fd=dir_fd)

        # FIXME: get rid of rename() and temporary file for linkat() if
        # anything like AT_REPLACE ever becomes available.
        # https://lore.kernel.org/linux-fsdevel/cover.1524549513.git.osandov@fb.com/
        os.rename(tmp_file_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


class SameDigest(Exception):  # noqa: N818
    """This is only used in control flow."""


def copy_file_secure(
    src: pathlib.Path,
    dst: pathlib.Path,
    /,
    *,
    user: str | None = None,
    group: str | None = None,
    mode: int = 0o600,
    create_parents: bool = False,
    check_hash: str | None = None,
) -> str:
    """Securely copy a file to a destination.

    This function opens the first argument file path for reading and makes use
    of the open_file_secure() function to atomically writes to the file
    referenced by the second argument path.

    Optionally, it can verify if the file that is being copied has a given
    hash value, as previously returned by this function.

    The function always returns a string representing a hash.
    """
    hash = hashlib.sha256()
    try:
        with (
            open(src, 'rb') as src_file,
            open_file_secure(
                dst,
                user=user,
                group=group,
                mode=mode,
                create_parents=create_parents,
                text=False,
            ) as dst_file,
        ):
            while True:
                data = src_file.read(1024 * 1024)
                if not data:
                    break
                hash.update(data)
                dst_file.write(data)
            digest = hash.hexdigest()
            if digest == check_hash:
                raise SameDigest
    except SameDigest:
        pass
    return digest
