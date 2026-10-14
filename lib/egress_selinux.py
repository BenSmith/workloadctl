#!/usr/bin/env python3
"""How QEMU enters a confined SELinux domain, and which policy modules ship.

Split out of vm.py, where this sat under a `# --- SELinux confinement ---`
header that had accumulated three other topics beneath it -- nft JSON payload
parsing, conntrack pressure, and the filter's element commands -- none of which
has anything to do with SELinux. A section header that names one of the four
things below it is worse than none: it tells a reader the block is about a
subject it has largely stopped being about.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed.

Installed to /usr/libexec/workloadctl/egress_selinux.py.
"""

import os
import socket

from config_parser import SOCKET_DIR
from workload_mcs import mcs_level


# QEMU runs as svirt_t (alias qemu_t), the domain the shipped policy already
# maintains for a hypervisor process hosting an untrusted guest. We deliberately
# do NOT author a wl_vm_t: svirt_t is a virt_domain and an mcs_constrained_type
# that already declares the entrypoints this needs, including
#   allow svirt_t qemu_exec_t:file entrypoint;
#   allow svirt_t passt_exec_t:file { entrypoint execute ... };
#   allow svirt_t swtpm_exec_t:file { entrypoint execute ... };
# so swtpm would transition to swtpm_t the moment QEMU is svirt_t, with no
# rules of ours. passt is not QEMU's child (see VM_PASST_TYPE).
#
# At the workload's own level (workload_mcs), as libvirt's sVirt gives each VM
# a category pair: the VM's disks and state carry it, so a QEMU escape is held
# from another VM's files by SELinux as well as by its uid.
VM_QEMU_TYPE = "svirt_t"


def vm_qemu_context(uid: int) -> str:
    """The context QEMU runs in for the workload with this uid."""
    return f"system_u:system_r:{VM_QEMU_TYPE}:{mcs_level(uid)}"


# The host-global policy delta VM confinement needs: a domain for the virtiofsd
# sidecar, and passt's start beside QEMU.
# Installed by the RPM rather than shipped through the per-workload
# [security].selinux_policy bundle: nothing in it is per-workload, and N
# identical copies would race semodule while gated on a flag that has nothing to
# do with whether virtiofs works. See security/workload-vm.cil.
VM_SELINUX_MODULE = "workload-vm"
VM_SELINUX_CIL = "/usr/share/workloadctl/workload-vm.cil"

# The inspector's and the responder's domains, installed the same way and for
# the same reason. Named here rather than only in the spec because `diagnose`
# compares each loaded module against the source the RPM shipped: a module
# missing from that list is a domain whose policy can drift out from under a
# running host with nothing saying so, which is the failure the check exists
# for. They replaced workload-proxy, which the RPM's %post now removes.
INSPECT_SELINUX_MODULE = "workload-inspect"
INSPECT_SELINUX_CIL = "/usr/share/workloadctl/workload-inspect.cil"
VM_RESOLVE_SELINUX_MODULE = "workload-resolve"
VM_RESOLVE_SELINUX_CIL = "/usr/share/workloadctl/workload-resolve.cil"
VM_CLOCK_SELINUX_MODULE = "workload-clock"
VM_CLOCK_SELINUX_CIL = "/usr/share/workloadctl/workload-clock.cil"

# --- The label the QMP socket directory has to carry ---
#
# The type SOCKET_DIR must carry, and the fcontext pattern the RPM's %post
# registers to give it that type. A confined QEMU cannot create a socket under
# /run's default var_run_t, so without this the guest dies before it binds QMP
# and the only symptom is a timeout that names nothing SELinux.
#
# Two spellings, both needed. svirt_var_run_t is an ALIAS: it is what the rule
# is written with (and what the policy and every doc call it), but the kernel
# stores the real name, so getfattr, `ls -Z` and matchpathcon all report
# qemu_var_run_t. A label comparison that knows only one of them is wrong half
# the time, which is why `diagnose`'s socket-label check accepts either.
VM_SOCKET_SELINUX_TYPE = "svirt_var_run_t"
VM_SOCKET_SELINUX_TYPE_REAL = "qemu_var_run_t"
VM_SOCKET_FCONTEXT_PATTERN = f"{SOCKET_DIR}(/.*)?"


# The transition needs a wrapper, and only a wrapper. `SELinuxContext=` in the
# unit does NOT work: systemd execs from init_t and the policy has no
# init_t -> svirt_t transition, deliberately — libvirt reaches svirt_t through
# its own virtqemud_t. But the domain VM units run in today may do it:
#   allow unconfined_service_t virt_domain:process transition;
# so `runcon <context> qemu-system-x86_64` from workload-vm-notify succeeds with
# no local policy at all.
#
# runcon rather than a setexeccon() call in Python, for two reasons. lib/ has no
# third-party dependencies and the stdlib has no SELinux binding, so the
# alternative is a new python3-libselinux Requires for one call. And runcon
# execs the target in its own process, which scopes the pending exec context to
# the child by construction — setexeccon() in the parent would leave it armed
# for whatever that process execs next.
#
# runcon must exec QEMU DIRECTLY. The entrypoint above is on qemu_exec_t; a
# shell in between is bin_t and the transition is refused.
VM_RUNCON_BIN = "/usr/bin/runcon"

# Presence means selinuxfs is mounted, i.e. SELinux is enabled. Enforcing vs
# permissive is not consulted: permissive is exactly the mode an AVC harvest
# runs in, so the transition has to happen there too or the harvest measures the
# wrong domain. Only a *disabled* host skips it, where setexeccon() would fail
# and take QEMU down with it.
SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce"


def selinux_enabled(root: str = "") -> bool:
    """Whether SELinux is enabled on this host (selinuxfs mounted)."""
    return os.path.exists(root + SELINUX_ENFORCE_PATH)


def qemu_launch_argv(qemu_cmd: list[str], uid: int, *,
                     enabled: bool | None = None,
                     runcon: str = VM_RUNCON_BIN) -> list[str]:
    """`qemu_cmd`, prefixed with runcon so QEMU enters svirt_t.

    Returns `qemu_cmd` unchanged when SELinux is disabled or runcon is missing,
    so a non-SELinux host still boots VMs — unconfined, as it was before ADR 006
    step 3. It is `workloadctl diagnose` that reports the difference; failing
    the start here would turn "this host has no SELinux" into "VMs do not run".
    """
    if enabled is None:
        enabled = selinux_enabled()
    if not enabled or not os.path.exists(runcon):
        return list(qemu_cmd)
    return [runcon, vm_qemu_context(uid), *qemu_cmd]


# passt runs beside QEMU rather than under it, so QEMU can run its own
# -sandbox with spawn=deny: a filter QEMU installs is inherited by anything
# it starts, and passt fails under it. workload-vm-notify starts passt in
# passt_t directly, at the VM's level; workload-vm.cil allows the one
# transition (unconfined_service_t to passt_t) the shipped policy leaves to
# svirt_t. Not by way of svirt_t: runcon's context overrides the policy's
# type_transition, and svirt_t may enter passt_exec_t itself, so passt would
# run as svirt_t, which cannot create the user namespace passt isolates
# itself in.
VM_PASST_TYPE = "passt_t"

# The kernel labels a socket with its creator's sockcreate context, so a
# pair made at QEMU's context is the pair QEMU's own passt netdev made: one
# QEMU may use, and one workload-vm.cil lets passt_t read and write.
SOCKCREATE_ATTR = "/proc/thread-self/attr/sockcreate"


def vm_passt_context(uid: int) -> str:
    """The context passt runs in for the workload with this uid."""
    return f"system_u:system_r:{VM_PASST_TYPE}:{mcs_level(uid)}"


def passt_launch_argv(passt_cmd: list[str], uid: int, *,
                      enabled: bool | None = None,
                      runcon: str = VM_RUNCON_BIN) -> list[str]:
    """`passt_cmd`, prefixed with runcon so passt enters passt_t."""
    if enabled is None:
        enabled = selinux_enabled()
    if not enabled or not os.path.exists(runcon):
        return list(passt_cmd)
    return [runcon, vm_passt_context(uid), *passt_cmd]


def vm_socketpair(uid: int, *, enabled: bool | None = None,
                  attr: str = SOCKCREATE_ATTR):
    """A connected unix stream pair labelled with QEMU's context."""
    if enabled is None:
        enabled = selinux_enabled()
    if not enabled:
        return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fd = os.open(attr, os.O_WRONLY)
    try:
        os.write(fd, vm_qemu_context(uid).encode())
        try:
            return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        finally:
            # An empty write resets it, so this process's own later sockets
            # (QMP's) are labelled as before.
            os.write(fd, b"")
    finally:
        os.close(fd)
