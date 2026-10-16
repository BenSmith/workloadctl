#!/usr/bin/env python3
"""A workload's SELinux level: two MCS categories of its own.

Every container and VM of a workload runs at this level, and its whole
tree and egress PKI carry it, so a process of another workload is refused
them by SELinux whatever their modes say (audit F3). Derived from the
workload uid, like the per-workload addresses, so it survives a recreate
and no two workloads share it. Nothing registers it as a rule: the setup
unit stamps it at each boot (ensure_common.stamp_selinux_labels).

Installed to /usr/libexec/workloadctl/workload_mcs.py.
"""

from workload_addr import UID_MAX, UID_MIN

CATEGORIES = 1024

# Workload pairs come from the categories below this, shares (shares.py) from
# those at and above it. A process of a share's members holds its own pair and
# the share's category; were a share's category one a workload pair used, that
# process would hold some other workload's whole pair as well. C(300, 2) pairs
# cover every uid in the workload range.
WORKLOAD_CATEGORIES = 300

# The type a workload's tree carries throughout: what rootless podman uses,
# or what a confined QEMU can open its disks with.
CONTAINER_TREE_TYPE = "container_file_t"
VM_TREE_TYPE = "svirt_image_t"


def mcs_categories(uid: int) -> tuple[int, int]:
    """The two categories, lower first: the uid offset's place in the
    pairs of WORKLOAD_CATEGORIES, in order."""
    if uid < UID_MIN or uid > UID_MAX:
        raise ValueError(
            f"UID {uid} is outside the workload range {UID_MIN}-{UID_MAX}; "
            f"no SELinux level is derivable for it")
    rank = uid - UID_MIN
    low = 0
    while rank >= WORKLOAD_CATEGORIES - 1 - low:
        rank -= WORKLOAD_CATEGORIES - 1 - low
        low += 1
    return low, low + 1 + rank


def mcs_level(uid: int, share_categories=()) -> str:
    """`s0:cA,cB` for the workload with this uid, with the categories of
    the shares it is in (shares.py) beside its pair."""
    categories = sorted({*mcs_categories(uid), *share_categories})
    return "s0:" + ",".join(f"c{c}" for c in categories)
