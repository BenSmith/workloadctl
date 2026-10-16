# Security model

What workloadctl confines a workload with, layer by layer: what each layer
holds, and where it stops. Two positions are considered: code running in a
workload, and code that has escaped its container to the host as the
workload's user, in the workload's SELinux context. Kernel exploits, host
root, the operator and physical access are outside it.

## Identity

Each workload runs as a user of its own, `_wl-<name>`: no login shell, no
password, no sudo, its own subordinate id ranges and runtime directory, and
nothing on the host but its own containers or QEMU. sshd refuses a `_wl-`
login and reads no key from a workload's home.

**Where it stops:** a workload given a host group has what the group gives:
alloy's `systemd-journal` reads every journal on the host, which is its job.

## User namespaces

A container's uids map only into the workload's subordinate uid range and
its own host uid; its gids into its subordinate gid range, its own gid and
the groups its config names (`[security].extra_groups`, and a writer's share
groups). A host id takes one container id; the generator warns when a map
would name one twice, which podman resolves by dropping the first.

## Capabilities

A container gets podman's default set, never `CAP_SYS_ADMIN`, unless the
workload is `privileged`. `[security].capabilities` names a smaller set.

## Seccomp

Every container runs under the baseline, `seccomp-workload-baseline.json`,
or the profile derived from it for one workload
(`[security].seccomp_allow`, `seccomp_netlink`, `seccomp_32bit`). It
refuses new user namespaces, the mount API, vsock, the kernel log, the
socket families and inet protocols (SCTP, L2TP, SMC) no workload uses, and
generic netlink and sock_diag (whose requests load the module they name);
families nothing names either way are allowed and logged. A 32-bit x86
syscall kills the thread: there `socket()` is `socketcall`, whose family
the filter cannot read. [Seccomp Filtering](workloads.md#seccomp-filtering)
has the lists.

**Where it stops:** a workload with `seccomp_32bit` (the Steam bundles) runs
32-bit code, whose sockets the family rules do not see. One with
`seccomp_netlink = ["generic"]` (the WireGuard bundles) can still make the
kernel load a module by its generic netlink family name; the image's
module refusals are what stop that. `privileged`, and a
`seccomp=` profile of the workload's own, replace the baseline;
`privileged` also runs as `spc_t`, which may still load modules.

## SELinux

Containers run as `container_t`, QEMU as `svirt_t`, passt as `passt_t`,
virtiofsd as `wlvfsd_t`, each at the workload's own level: two categories
derived from its uid. Everything under its `data/` and `state/` carries the
same level, so another workload's process is refused those files whatever
their mode. A share is labelled with a category of its own, which only its
members' processes hold. `[security].selinux_policy` adds a policy scoped to
one workload. No workload domain may make the kernel load a module, so a
family whose module the host has not loaded is refused whatever the image's
module list says. [SELinux Confinement](workloads.md#selinux-confinement)
has the details.

**Where it stops:** the level is stamped by the setup unit, not registered
as a rule, so a relabel puts the tree back at `s0` until the next boot or
`recreate`. A volume outside the workload's tree keeps the label it has.

## Mounts, devices and sockets

A workload sees its own tree and what its config mounts. A read-only host
tree is mounted recursively read-only (`rro`), so nothing mounted beneath it
is writable either. A streaming workload opens `/dev/uinput` and the devices
uinput makes, through the `uinput` group, and not the host's keyboards and
mice.

**Where it stops:** uinput has no scope: what a streaming workload types
reaches whatever holds the host's focus. A container given the host's
journal socket sets its own entries' identifier and priority; journald
stamps their uid and unit, which `logs` and alloy go by.

## Network

`[network]` decides what a workload reaches. A pasta workload reaches none
of the host's loopback services; a filtered one reaches only the names its
policy lists, through the egress inspector, and none of the host's own
addresses. [Network Modes](workloads.md#network-modes) and the
[egress architecture](egress-and-broker-architecture.md) have the rest.

**Where it stops:** a host-network workload shares the host's network,
loopback included. A bridged VM takes a real address on the bridge, and no
egress policy reaches it.

## The unit around a workload

The systemd unit that runs a workload's podman, or QEMU, confines what an
escaped process keeps: a read-only system (`ProtectSystem=strict`) with
writes only where the workload's data lives, a private `/tmp`, and no
`AF_ALG` or `AF_PACKET` sockets. QEMU runs its own seccomp filter
(`-sandbox`, libvirt's default set, `spawn=deny` included): passt and the
bridge helper are started beside it, not by it.

## Secrets

Credentials are encrypted at rest and decrypted into tmpfs for their own
workload. A `[[secrets.files]]` entry is readable by its workload alone. A
`${SECRET:}` variable reaches the container's environment, and podman's
records of it are on tmpfs too: each container workload's podman store is
transient. [Secrets](secrets.md) has the details.

**Where it stops:** a value in the environment is visible to every process
in the container. Images and the containers' writable layers are on disk.

## Root's work in a workload's tree

Setup runs as root inside directories the workload's user owns. Every write,
chown and removal there walks the path without following a link, so a link
the workload plants cannot steer root to another file.

## moatery's services

The egress inspector, the credential broker and the DNS responder run
beside a workload, not in it. Their policy and status files are root's, and
the egress CA's key is labelled so that no container reads it.

## Resources and logs

`[resources]` caps a workload's memory and CPU. A container's output goes to
the journal under its own name, rate limited, and never to the host's
terminals.

**Where it stops:** there is no disk quota: a workload can fill the
filesystem `/var/lib/workloads` is on, which is `/var`'s unless the host
gives it one of its own. A bundle with no `memory_max` is capped only by the
slice.

## Supply chain

On the hypervisor image, images from `registry.local` are
signature-verified. The forge's image build
scans each image before pushing it, refusing a fixable critical CVE that is
not accepted in `cve-allowlist.txt`, and rebuilds the images weekly;
`diagnose` reports an image older than 30 days. The OS images are scanned
too, report only, and the hypervisor image stages its updates for a reboot
the operator chooses.

**Where it stops:** a running workload keeps the image it was created from
until it is recreated.
