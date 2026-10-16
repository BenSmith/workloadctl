#!/usr/bin/env python3
"""What a share needs on the host, done as root when a member is enabled,
recreated or disabled (shares.py says what a share is).

- Its tree carries the share's category: an fcontext rule, then a relabel.
- Its group owns the tree, group-writable, directories setgid, nothing for
  others: the writers are in the group.
- Its read group has a read ACL, and a default one so new files carry it:
  the readers are in that group.

Whole-tree passes, so at enable and recreate only, never at each start.
Best-effort, like the other fcontext steps: a host without semanage or
setfacl is warned about, not refused.

Installed to /usr/libexec/workloadctl/shares_setup.py.
"""

import grp
import shutil
import subprocess
import tomllib
from pathlib import Path

from cli_log import info, warn
from shares import (
    load_shares, memberships, membership_source, readers_and_writers,
    share_group, share_read_group,
)
from workload_lib import (
    ENABLED_MARKER_NAME, iter_workloads, workload_username,
)

SHARE_SELINUX_TYPE = "container_file_t"

# libselinux's path equivalences: a path under an alias is labelled as the
# same path under its target, and semanage refuses a rule under the alias
# (/var/mnt is /mnt's on Fedora). The local file's are read before the
# distribution's, and the first that matches applies, as libselinux does.
SELINUX_CONFIG = Path("/etc/selinux/config")
SUBS_FILES = ("file_contexts.subs", "file_contexts.subs_dist")


def _run(argv, run=subprocess.run):
    result = run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        warn(f"  WARNING: {' '.join(argv[:3])}: "
             f"{(result.stderr or result.stdout).strip()}")
    return result


def enabled_configs(skip=None) -> dict[str, dict]:
    """Every enabled workload's parsed config, but `skip`."""
    configs = {}
    for name, path in iter_workloads():
        if name == skip or not (path.parent / ENABLED_MARKER_NAME).exists():
            continue
        try:
            with open(path, "rb") as f:
                configs[name] = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            continue
    return configs


def _policy_name(config=SELINUX_CONFIG) -> str:
    try:
        for line in config.read_text().splitlines():
            key, _, value = line.strip().partition("=")
            if key == "SELINUXTYPE" and value:
                return value
    except OSError:
        pass
    return "targeted"


def path_substitutions(policy=None, root=Path("/etc/selinux")):
    """(alias, target) pairs, in the order libselinux tries them."""
    files = root / (policy or _policy_name()) / "contexts" / "files"
    subs = []
    for name in SUBS_FILES:
        try:
            text = (files / name).read_text()
        except OSError:
            continue
        for line in text.splitlines():
            words = line.split()
            if len(words) == 2 and not words[0].startswith("#"):
                subs.append((words[0].rstrip("/"), words[1].rstrip("/")))
    return subs


def labelled_as(path: str, subs) -> str:
    """The path SELinux labels `path` as."""
    for alias, target in subs:
        if path == alias or path.startswith(alias + "/"):
            return target + path[len(alias):]
    return path


def fcontext_pattern(path: str, subs=None) -> str:
    if subs is None:
        subs = path_substitutions()
    return f"{labelled_as(path, subs)}(/.*)?"


def _label(share, run):
    if not shutil.which("semanage"):
        return
    level = f"s0:c{share.category}"
    pattern = fcontext_pattern(share.path)
    listed = run(["semanage", "fcontext", "-l"], capture_output=True,
                 text=True)
    context = next((line.split()[-1] for line in listed.stdout.splitlines()
                    if line.split()[:1] == [pattern]), None)
    if context != f"system_u:object_r:{SHARE_SELINUX_TYPE}:{level}":
        verb = "-m" if context else "-a"
        result = _run(["semanage", "fcontext", verb, "-t", SHARE_SELINUX_TYPE,
                       "-r", level, pattern], run)
        if result.returncode == 0:
            info(f"  Registered SELinux fcontext: {pattern} -> "
                 f"{SHARE_SELINUX_TYPE}:{level}")
    _run(["restorecon", "-RF", share.path], run)


def _own(share, run):
    group, readers = share_group(share.name), share_read_group(share.name)
    _run(["systemd-sysusers", "--inline", f"g {group} -", f"g {readers} -"],
         run)
    _run(["chgrp", "-R", group, share.path], run)
    _run(["chmod", "-R", "g+rwX,o-rwx", share.path], run)
    _run(["find", share.path, "-type", "d", "-exec", "chmod", "g+s", "{}",
          "+"], run)
    if not shutil.which("setfacl"):
        warn(f"  WARNING: no setfacl: share {share.name}'s readers get no "
             f"read access")
        return
    _run(["setfacl", "-R", "-m", f"g:{readers}:rX", share.path], run)
    _run(["setfacl", "-R", "-d", "-m", f"g:{readers}:rX", share.path], run)


def _members(group):
    try:
        return grp.getgrnam(group).gr_mem
    except KeyError:
        return []


def _leave(share, user, run, members=_members):
    """Take a disabled workload's user out of the share's groups."""
    for group in (share_group(share.name), share_read_group(share.name)):
        if user in members(group):
            _run(["gpasswd", "-d", user, group], run)


def apply_shares(config, action: str, run=subprocess.run,
                 configs=None, shares=None, members=_members):
    """Set up (enable) or retire this workload's part in its shares.

    `config` is the workload's WorkloadConfig. At enable every share it is
    in is labelled, owned and given its read group's ACL. At disable its
    user leaves the share's groups, and a share left with no member keeps its
    files and loses its rule.
    """
    own = memberships(config.config)
    if not own:
        return
    if shares is None:
        shares, errors = load_shares()
        for e in errors:
            warn(f"  WARNING: {e}")
    for m in own:
        share = shares.get(m.name)
        if share is None:
            warn(f"  WARNING: share {m.name!r} is not declared; "
                 f"nothing set up for it")
            continue
        if action == "disable":
            _leave(share, workload_username(config.name), run, members)
            if configs is None:
                configs = enabled_configs(skip=config.name)
            readers, writers = readers_and_writers(
                share.name, {n: c for n, c in configs.items()
                             if n != config.name})
            if not readers and not writers and shutil.which("semanage"):
                _run(["semanage", "fcontext", "-d",
                      fcontext_pattern(share.path)], run)
            continue
        _run(["mkdir", "-p", membership_source(share, m)], run)
        _label(share, run)
        _own(share, run)
