#!/usr/bin/env python3
"""What a share needs on the host, done as root when a member is enabled,
recreated or disabled (shares.py says what a share is).

- Its tree carries the share's category: an fcontext rule, then a relabel.
- Its group owns the tree, group-writable, directories setgid, nothing for
  others: the writers are in the group.
- Each reader has a read ACL, and a default one so new files carry it.

Whole-tree passes, so at enable and recreate only, never at each start.
Best-effort, like the other fcontext steps: a host without semanage or
setfacl is warned about, not refused.

Installed to /usr/libexec/workloadctl/shares_setup.py.
"""

import shutil
import subprocess
import tomllib

from cli_log import info, warn
from shares import (
    load_shares, memberships, membership_source, readers_and_writers,
    share_group,
)
from workload_lib import (
    ENABLED_MARKER_NAME, iter_workloads, workload_username,
)

SHARE_SELINUX_TYPE = "container_file_t"


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


def fcontext_pattern(path: str) -> str:
    return f"{path}(/.*)?"


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
        _run(["semanage", "fcontext", verb, "-t", SHARE_SELINUX_TYPE,
              "-r", level, pattern], run)
        info(f"  Registered SELinux fcontext: {pattern} -> "
             f"{SHARE_SELINUX_TYPE}:{level}")
    _run(["restorecon", "-RF", share.path], run)


def _own(share, readers, former_readers, run):
    group = share_group(share.name)
    _run(["systemd-sysusers", "--inline", f"g {group} -"], run)
    _run(["chgrp", "-R", group, share.path], run)
    _run(["chmod", "-R", "g+rwX,o-rwx", share.path], run)
    _run(["find", share.path, "-type", "d", "-exec", "chmod", "g+s", "{}",
          "+"], run)
    if not shutil.which("setfacl"):
        warn(f"  WARNING: no setfacl: share {share.name}'s readers get no "
             f"read access")
        return
    for workload in former_readers:
        user = workload_username(workload)
        _run(["setfacl", "-R", "-x", f"u:{user}", share.path], run)
        _run(["setfacl", "-R", "-d", "-x", f"u:{user}", share.path], run)
    for workload in readers:
        user = workload_username(workload)
        _run(["setfacl", "-R", "-m", f"u:{user}:rX", share.path], run)
        _run(["setfacl", "-R", "-d", "-m", f"u:{user}:rX", share.path], run)


def apply_shares(config, action: str, run=subprocess.run,
                 configs=None, shares=None):
    """Set up (enable) or retire this workload's part in its shares.

    `config` is the workload's WorkloadConfig. At enable every share it is
    in is labelled, owned and given its readers' ACLs, all members' at once,
    so a reader enabled before the writer is still served. At disable its
    own ACL goes, and a share left with no member keeps its files and loses
    its rule.
    """
    own = memberships(config.config)
    if not own:
        return
    if shares is None:
        shares, errors = load_shares()
        for e in errors:
            warn(f"  WARNING: {e}")
    if configs is None:
        configs = enabled_configs(skip=config.name)
    others = {n: c for n, c in configs.items() if n != config.name}
    for m in own:
        share = shares.get(m.name)
        if share is None:
            warn(f"  WARNING: share {m.name!r} is not declared; "
                 f"nothing set up for it")
            continue
        readers, writers = readers_and_writers(share.name, others)
        if action == "disable":
            if m.access == "read":
                _own(share, readers, [config.name], run)
            if not readers and not writers and shutil.which("semanage"):
                _run(["semanage", "fcontext", "-d",
                      fcontext_pattern(share.path)], run)
            continue
        source = membership_source(share, m)
        _run(["mkdir", "-p", source], run)
        if m.access == "read":
            readers = sorted({*readers, config.name})
        _label(share, run)
        _own(share, readers, [], run)
