"""A container workload's podman keeps its containers' records on tmpfs.

podman records a container's whole environment, `${SECRET:}` values
included, in its database and in the container's config.json, both under
the graphroot on disk. storage.conf's `transient_store` puts both under the
runroot, /run/user/<uid>, instead; the units run every container with --rm
and --replace, so nothing needs them across a boot. A user's storage.conf
replaces what a rootless podman takes from the system's, so the workload's
names that again beside `transient_store`.
"""
import os
import re
import subprocess
import tomllib
from pathlib import Path

import ensure_common
from ensure_common import (
    _descend_nofollow, _provision_dir_secure, _write_file_nofollow,
)
from config_parser import workload_root_dir
from workload_lib import workload_state_dir
from workloadctl_core import toml_string

SYSTEM_FILES = (Path("/etc/containers/storage.conf"),
                Path("/usr/share/containers/storage.conf"))

# What c/storage gives a rootless user from the system's file
# (getRootlessStorageOpts): its driver if that one runs rootless, else its
# driver priority, its pull options, and overlay's ignore_chown_errors. The
# rest is root's: its runroot, graphroot and additional image stores, which
# a rootless podman cannot lock. The graphroot (rootless_storage_path or
# $HOME's) and the runroot (XDG_RUNTIME_DIR's) come from c/storage's
# defaults, as without the file.
ROOTLESS_DRIVERS = ("btrfs", "overlay", "overlay2", "vfs")

# The persistent database, which holds every container podman recorded
# before the store went transient.
PERSISTENT_DB = ("db.sql", "db.sql-wal", "db.sql-shm", "libpod/bolt_state.db")


def _key(key):
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else toml_string(key)


def _value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return toml_string(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    raise ValueError(f"storage.conf value {value!r} is not one this writes")


def _dump(table, path=()):
    lines = []
    if path:
        lines.append("[" + ".".join(_key(k) for k in path) + "]")
    for key, value in table.items():
        if not isinstance(value, dict):
            lines.append(f"{_key(key)} = {_value(value)}")
    for key, value in table.items():
        if isinstance(value, dict):
            lines.append("")
            lines.extend(_dump(value, path + (key,)))
    return lines


def transient_storage_conf(system_text: str) -> str:
    """What a rootless podman takes from the system's storage.conf, made
    transient."""
    system = tomllib.loads(system_text).get("storage", {})
    system_options = system.get("options", {})
    storage = {}
    driver = system.get("driver")
    if driver in ROOTLESS_DRIVERS:
        storage["driver"] = "overlay" if driver == "overlay2" else driver
    elif system.get("driver_priority"):
        storage["driver_priority"] = system["driver_priority"]
    storage["transient_store"] = True
    options = {}
    if "pull_options" in system_options:
        options["pull_options"] = system_options["pull_options"]
    ignore = system_options.get("overlay", {}).get("ignore_chown_errors")
    if storage.get("driver") == "overlay" and ignore is not None:
        options["overlay"] = {"ignore_chown_errors": ignore}
    if options:
        storage["options"] = options
    return "\n".join(_dump({"storage": storage})).lstrip("\n") + "\n"


def system_storage_conf() -> str:
    for path in SYSTEM_FILES:
        try:
            return path.read_text()
        except FileNotFoundError:
            continue
    return ""


def user_storage_conf_path(name: str) -> Path:
    return workload_state_dir(name) / ".config" / "containers" / "storage.conf"


def ensure_transient_store(pw, name: str) -> None:
    """Write the workload's storage.conf, then retire the old database."""
    root = workload_root_dir(name)
    state = workload_state_dir(name)
    conf = user_storage_conf_path(name)
    for directory in (conf.parent.parent, conf.parent):
        if not _provision_dir_secure(root, directory, pw.pw_uid, pw.pw_gid,
                                     0o700):
            raise RuntimeError(f"unsafe path to {directory}")
    content = transient_storage_conf(system_storage_conf()).encode()
    if not _write_file_nofollow(root, conf, content, pw.pw_uid, pw.pw_gid,
                                0o644):
        raise RuntimeError(f"unsafe path to {conf}")
    _retire_persistent_db(pw, root, state)


def _retire_persistent_db(pw, root: Path, state: Path) -> None:
    """Remove the persistent database once no container is recorded in it.

    It is what kept the values on disk. A container still recorded there
    is one started before the store went transient; its unit's --rm takes
    it out at its stop, and the next setup removes the database then. Root
    unlinks in a tree the workload user owns, so each directory on the way
    is opened without following a link.
    """
    graphroot = (state / ".local" / "share" / "containers"
                 / "storage").relative_to(root).parts
    found = []
    for rel in PERSISTENT_DB:
        *sub, leaf = rel.split("/")
        dir_fd = _descend_nofollow(root, (*graphroot, *sub),
                                   f"remove {rel}")
        if dir_fd is None:
            continue
        try:
            os.stat(leaf, dir_fd=dir_fd, follow_symlinks=False)
            found.append((tuple(sub), leaf))
        except FileNotFoundError:
            pass
        finally:
            os.close(dir_fd)
    if not found:
        return
    result = subprocess.run(
        ["runuser", "-u", pw.pw_name, "--",
         "env", f"XDG_RUNTIME_DIR=/run/user/{pw.pw_uid}", f"HOME={state}",
         "podman", "--transient-store=false", "ps", "-aq"],
        capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or result.stdout.strip():
        ensure_common.log(
            f"  Kept the persistent podman database for {pw.pw_name}: "
            + ("containers are still recorded in it"
               if result.returncode == 0 else
               f"podman ps returned {result.returncode}"))
        return
    for sub, leaf in found:
        dir_fd = _descend_nofollow(root, (*graphroot, *sub), f"remove {leaf}")
        if dir_fd is None:
            continue
        try:
            os.unlink(leaf, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(dir_fd)
    ensure_common.log(f"  Removed the persistent podman database for "
                      f"{pw.pw_name}")
