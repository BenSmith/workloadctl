# 8. Security and confinement

This chapter describes what confines a workload, one layer at a time, and
where each layer stops. It starts with who is trusted, because every layer
is sized to that answer, and ends with where images come from. Every
`[security]` key is in [the schema reference](../schema-reference.toml).

## The threat model

Two positions are considered: code running inside a workload, and code that
has escaped its container or its guest onto the host, where it runs as the
workload's user in the workload's SELinux context. Each layer below is
described by what it denies those two. A kernel exploit, root on the host,
the operator and physical access to the machine are outside the model.

### Configurations are trusted as root

A workload's TOML and the files beside it are root-equivalent input. A
`[host] setup` script runs as root at `enable`. A volume can mount any host
path. `[security]` can add capabilities, turn on `privileged`, load an
SELinux policy module and have the host load kernel modules. `install`,
`duplicate` and `restore` write configurations as root. `validate` and the
generator catch mistakes, not intent: a hostile TOML that is well formed
passes them.

So whoever can write to `/etc/workloads.d/` can do what root can. Enable a
workload only from a source you would give root to. workloadctl confines the
software a workload runs, not the person who wrote its configuration.

Secret names follow from this. Any TOML may reference any secret on the host
that is not scoped to another use ([Who can read a secret](07-secrets.md#who-can-read-a-secret)).
A rule about which names a TOML may use would protect nothing from someone
who can already write a TOML. What is kept apart is the decrypted value,
which only its own workload's user can read.

### The workload is not

The one party the design does not trust is the workload itself: the software
in a container, a VM's guest operating system, and whatever either of them
downloads. A filtered workload is where this is sharpest, because its filter
exists to hold that party to a policy. So every mechanism aimed at the guest
of a filtered workload is enforced by the host and keyed on the workload's
user: the redirect of its traffic to the inspector, the resolver that
answers its DNS, and the broker's check of who is calling. None of them
depends on anything the workload is told, is configured with, or can
decline.

## Identity

Each workload runs as its own system user, `_wl-<name>`, with no login
shell, a locked password and no sudo. It has its own subordinate ID ranges
and its own runtime directory, and nothing runs as it but the workload: its
containers and their podman, or its QEMU and the helpers beside it. Storage,
outbound network policy and the credential broker all key on this user, and
nothing inside the workload can change it.

The package installs an sshd drop-in,
`/etc/ssh/sshd_config.d/40-workloadctl.conf`, which refuses a login as any
`_wl-` user and reads no authorized key from their home directories, which
the workloads can write. sshd reads it the next time it starts. The ways into
a workload are `workloadctl exec` and `shell`, run by an administrator with
`sudo`.

**Where it stops.** The workload user has what its groups give it.
`[security] extra_groups` adds it to host groups, and each one is a real
grant: `systemd-journal` reads every journal on the host, `input` reads
every keystroke, `disk` reads and writes every disk.
[Device nodes](04-containers.md#device-nodes) lists the usual ones.

## User namespaces

A container never runs in the host's user namespace. Under the default,
`userns = "keep-id"`, the container's UIDs map into the workload's
subordinate UID range, except the one equal to the workload user's own UID,
which maps to the workload user. Its GIDs map into the subordinate GID range,
plus the workload's own GID and the groups the configuration names: those in
`extra_groups` and those of the shares it joins. Container root is a
subordinate ID, and a file it writes belongs to an ID no host account has.

`keep-id:uid=N,gid=N` moves the workload user to UID N inside the container,
and `keep-id:uid=0,gid=0` makes container root the workload user, still in a
private namespace. Those are the forms for an image that runs as a fixed
user or has to run as root; [Who owns the files](04-containers.md#who-owns-the-files)
covers them.

`userns = "host"` is different in kind. The container shares the user
namespace the workload's own podman runs in instead of getting one of its
own, so container root is the workload user itself. It is needed only when a
container must see host-side UIDs through a host mount, as a metrics agent
reading `/host/proc` does. Because it removes the per-workload namespace,
`validate`, `enable` and the boot generator all refuse it unless the
workload acknowledges it:

```toml
[security]
userns = "host"
unsafe_host_userns = true
```

`status` and `diagnose` then show the posture every time they run.

In a pod-mode workload the pod owns the user namespace, so `userns` and the
maps below belong in the top-level `[security]`. In bridge mode each
container's `[containers.security]` sets its own.

### Explicit ID maps

When a keep-id workload has `extra_groups`, workloadctl writes its user
namespace as explicit maps: the workload user's UID and GID to the keep-id
target, and each extra group's GID to the same GID inside. For anything
those don't cover, `extra_uidmaps` and `extra_gidmaps` add maps of your own,
in podman's `--uidmap` syntax, `+<container id>:@<host id>:<count>`. The `+`
adds the map to the others rather than replacing them, and the `@` makes the
second number an ID on the host. `{UID}` and `{GID}` stand for the workload
user's own IDs.

The maps apply under every `keep-id` form and are ignored under
`userns = "host"`. A host ID must be one the workload user is allowed to
map: its own UID or GID, an ID in its subordinate range, or the GID of a
group in `extra_groups`, which workloadctl delegates to it when the workload
starts. podman refuses to start a container whose map names any other host
ID.

A host ID can stand for only one container ID, and when two maps name the
same host ID, podman keeps the last one. That makes an explicit map a way to
move an ID. Say an image expects the GPU group at GID 44 and the host's
`video` group is GID 39:

```toml
[security]
extra_groups = ["video"]
extra_gidmaps = ["+44:@39:1"]
```

The automatic map puts host GID 39 at 39 inside; the explicit one comes
later and wins, so the group appears at 44 and container GID 39 falls to a
subordinate ID. The generator logs a warning whenever a map names a host ID a
second time, and `workloadctl doctor` shows it. Here the move is the point,
but the same rule catches the workload's own IDs, which are always mapped: a
map onto `{UID}` or `{GID}` moves the workload user away from its keep-id
target. To make container root the workload user, write
`userns = "keep-id:uid=0,gid=0"` instead.

## Capabilities

A process running as root inside a container holds podman's default
capabilities: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`,
`NET_BIND_SERVICE`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID` and
`SYS_CHROOT`. A process running as any other user holds none but what the
workload adds. Every capability is held inside the container's user
namespace, so it acts on what that namespace owns: `NET_ADMIN` configures
the container's own network stack, not the host's.

`capabilities` adds to that set; nothing in the TOML takes one away:

```toml
[security]
userns = "keep-id:uid=0,gid=0"
capabilities = ["NET_ADMIN"]
```

In a workload of several containers, each container's
`[containers.security]` has its own list.

`privileged = true` turns off most of what this chapter describes: the
container gets every capability, every host device node the workload user
can open, no seccomp filter, and no SELinux label of its own, running as
`spc_t`. It is a workload-level setting in the top-level `[security]`, and
the generator warns whenever a workload uses it. Prefer the specific
capability.

## Seccomp

Every container runs under a seccomp filter, the baseline profile at
`/usr/share/containers/seccomp-workload-baseline.json`, or a profile derived
from it for one workload. It starts from podman's own default and refuses
more.

### What the baseline refuses

| Call | Why it is refused | Fails with |
|---|---|---|
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` | Inspect another process, or take its memory or its file descriptors | `ENOSYS` |
| `keyctl` | The kernel keyring | `ENOSYS` |
| `bpf`, `perf_event_open` | Load eBPF programs; performance counters, a side channel between containers | `EPERM` |
| `clone` and `unshare` with a namespace flag | In a new user namespace the workload's user is root, with the mount calls and the rest of what root may do there | `EPERM` |
| `clone3` | Its flags are behind a pointer the filter cannot read; glibc falls back to `clone` | `ENOSYS` |
| `mount`, `umount2`, `pivot_root`, `fsopen`, `move_mount` and the other mount calls | Rearrange the filesystem | `EPERM` |
| `syslog` | Read the kernel's log, whatever the host's `kernel.dmesg_restrict` says | `EPERM` |
| `socket` with `AF_VSOCK` | A vsock reaches the host, or a VM on it, around the network namespace and every filter on it | `ENOSYS` |
| `socket` with `AF_ALG` | The kernel's crypto API, opened to user space; built into the kernel, where no module refusal reaches | `ENOSYS` |
| `socket` with an uncommon family | X.25, AX.25, NET/ROM, ROSE, ATM, PPPoX, IEEE 802.15.4, NFC, CAIF, Phonet, ISDN, RDS, TIPC, LLC, KCM, RxRPC, Qualcomm IPC, SMC and MCTP: rarely used, with a record of kernel bugs | `ENOSYS` |
| `socket` with inet's L2TP, SCTP or SMC protocol | Each is a module of its own | `ENOSYS` |
| `socket` with netlink's xfrm, crypto, RDMA, iSCSI or SCSI transport protocol | Rarely used; xfrm is built into the kernel, where no module refusal reaches | `ENOSYS` |
| `socket` with netlink's generic or sock_diag protocol | A request names a module and the kernel loads it, and the name is inside the message, where the filter cannot read it | `ENOSYS` |
| any 32-bit (x86 or x32) system call | See below | killed: `Bad system call`, exit status 159 |

The error tells you which rule refused a call. A call the profile never
mentions falls to the default and fails with `ENOSYS`, "Function not
implemented", as if the kernel lacked it: gdb prints `ptrace: Function not
implemented`. A call it refuses by name, or one gated on a capability the
container lacks, fails with `EPERM`, "Operation not permitted". An `EPERM`
from a call the profile allows comes from SELinux, not seccomp.

Sockets are allowed by family. Unix, inet and inet6 sockets are allowed
(apart from the three inet protocols above), and so are netlink's route,
netfilter and uevent protocols. A family or netlink protocol that is in
neither the allowed nor the refused list is allowed and logged: each such
`socket()` leaves a seccomp audit record, which `journalctl
_AUDIT_TYPE=1326` shows.

The baseline also drops x86_64's 32-bit sub-architectures. On 32-bit x86
every `socket` rule is folded into the `socketcall` multiplexer, with the
address family behind a pointer, so a 32-bit `socketcall` could open any
family, vsock included, past every refusal above. Without the
sub-architectures, a 32-bit system call is refused as a bad architecture:
the kernel kills the calling thread, so a 32-bit program dies at its first
system call with `Bad system call (core dumped)`, exit status 159, and a
`SECCOMP` audit record carrying `sig=31 arch=40000003`.

Most services never make any of these calls.
[Troubleshooting](10-troubleshooting.md#seccomp) covers recognising a
refusal; the rest of this section is about opening the filter for the
workload that needs it.

### Opening it for one workload

`seccomp_allow` allows named system calls on top of the baseline. A
debugger needs three:

```toml
[security]
seccomp_allow = ["ptrace", "process_vm_readv", "process_vm_writev"]
```

A program that sandboxes itself in namespaces of its own fails under the
baseline. bubblewrap, which Steam's runtime and Flatpak are built on, stops
with `bwrap: No permissions to create a new namespace`. Its workload allows
the calls bubblewrap makes:

```toml
[security]
seccomp_allow = ["clone", "mount", "pivot_root", "umount2", "unshare"]
```

Other programs carry on without the namespace part of their sandbox rather
than fail: GTK's image loaders log `Glycin running without sandbox`, and
Firefox still applies its own seccomp filter.

`seccomp_netlink` takes back one of the two refused netlink protocols, by
name. `wg`, and so `wg-quick`, configures a WireGuard link through generic
netlink, and `ss` lists sockets through sock_diag:

```toml
[security]
seccomp_netlink = ["generic"]
```

`seccomp_32bit` puts the 32-bit sub-architectures back, for a workload that
runs 32-bit code, such as Steam's client:

```toml
[security]
seccomp_32bit = true
```

Any of the three gives the workload a profile of its own, which the
generator writes beside its units as
`/run/systemd/system/workload-<name>.seccomp.json`: the baseline as
installed at that moment, with the named calls taken out of every rule that
refuses them and allowed outright, the named netlink protocols allowed, and
the 32-bit sub-architectures restored if asked for. One profile serves every
container of the workload, so the keys go in the top-level `[security]`, and
`validate` refuses them in `[containers.security]`, beside a `seccomp=`
option, with `privileged`, and on a VM.

The profile is rebuilt whenever the units are, so a new baseline from a
package upgrade reaches a workload at the next boot or `enable`, and `drift`
and `doctor` report the old profile until then. A pet container keeps the
profile it was created with until `recreate`. After changing any of these
keys, run `sudo workloadctl recreate <name>`.

To replace the baseline rather than add to it, name a profile in
`security_opt`. These are three alternatives:

```toml
[security]
security_opt = ["seccomp=/usr/share/containers/seccomp.json"]   # podman's default
security_opt = ["seccomp=/etc/containers/my-profile.json"]      # one of your own
security_opt = ["seccomp=unconfined"]                           # none at all
```

`security_opt` is the one key that expands `${WORKLOAD_NAME}`,
`${WORKLOAD_INSTANCE_DIR}`, `${WORKLOAD_ROOT_DIR}`, `${WORKLOAD_STATE_DIR}`
and `${WORKLOAD_DATA_DIR}`, so a bundle can point at a profile its setup
script wrote beside the instance's TOML. An option with an unknown token is
dropped with a warning, and a dropped `seccomp=` leaves the container on the
baseline.

Some operations are gated twice. A debugger's `ptrace` has to get past
seccomp and SELinux both, so a call that `seccomp_allow` lets through can
still fail with `EPERM`. That is SELinux's refusal;
[A policy of the workload's own](#a-policy-of-the-workloads-own) is the fix.

### Where it stops

`seccomp_32bit` brings back the family-blind `socketcall` with the 32-bit
code, so that workload's 32-bit programs can open any socket family.
`seccomp_netlink = ["generic"]` lets a workload ask the kernel to load a
module by its generic netlink family name; under SELinux enforcing that
request is refused like every other module request (below), and without
SELinux only the host's own modprobe configuration refuses it. `privileged`
and a `seccomp=` profile of your own replace the baseline altogether.

A VM's QEMU is not under the baseline. It runs QEMU's own sandbox
(`-sandbox`, with the set libvirt uses by default, including `spawn=deny`),
and passt and the bridge helper are started beside it rather than by it.

## SELinux

SELinux is the layer that separates workloads from each other and from the
host when file modes would let them through.

### Domains and levels

Containers run as `container_t`, or a type of their own (below). QEMU runs
as `svirt_t`, passt as `passt_t`, and a VM's virtiofs sidecars as
`wlvfsd_t`. Each runs at the workload's own **level**, `s0:cA,cB`: two MCS
categories derived from the workload user's UID, so no two workloads share
one and it survives a `recreate`.

The workload's whole tree under `/var/lib/workloads/<name>/`, and its egress
inspector's CA and caches under `/var/lib/workloadctl/egress/<name>/`, carry
the same level. A process of another workload is refused those files by
SELinux whatever their modes say, and that holds for QEMU and virtiofsd as
much as for containers. A file a workload creates takes its directory's
level, so new files keep it.

The level is stamped by the workload's setup unit each time it runs, not
registered as a file-context rule. A relabel, such as `restorecon -RF` or an
autorelabel, puts the tree back at `s0` until the setup unit next runs, at
boot or on `sudo workloadctl recreate <name>`. Use `recreate` rather than
`restorecon` to repair it. If the setup unit cannot stamp the tree, it fails
and the workload does not start. `workloadctl diagnose` reports files under
`data/` that are not at the level, as `mcs_labels`.

A `security_opt` that names a level of its own (`label=level:...`) or turns
labelling off (`label=disable`) takes the container off the workload's
level, and a `privileged` container has no label at all.

### Files outside the tree

A volume outside the workload's tree keeps the label it has. `Z` on a volume
relabels a host directory with the workload's level
([Volumes](04-containers.md#volumes)); never use it on a system directory.

A directory several container workloads use is a **share**, declared in
`/etc/workloads.d/shares.toml` and joined from each workload
([Sharing a directory between workloads](04-containers.md#sharing-a-directory-between-workloads)).
Its files carry an MCS category of the share's own, from the range 300 to
1023 that no workload pair uses, and its members' processes hold that
category beside their own pair. A workload outside the share is refused its
files, whatever their modes. Writers own the tree through the group
`wl-share-<name>`; readers get read access through `wl-share-<name>-ro` and a
read-only mount, so a reader cannot plant a file a writer then trusts.
Membership is by group rather than user because a process keeps its groups
whatever UID it runs as inside the container. A pod has one user namespace
and one label, so in a multi-container workload the mount, not the label, is
what keeps the share from the containers that do not list it. `diagnose`
reports each share's label as `share[<name>]`.

A filesystem that cannot store labels, such as CIFS, NFS or vfat, gives
every file the same label, so SELinux cannot tell two workloads apart there,
and ownership and mode are the whole of the separation
([Host paths on other filesystems](04-containers.md#host-paths-on-other-filesystems)).

### Kernel modules

A `socket()` for a family the kernel has not loaded asks the kernel to load
that family's module, and Fedora's policy lets every domain ask.
workloadctl's policy takes that away from every container domain, from
QEMU, passt and virtiofsd, and from the egress inspector, the DNS responder
and the clock keeper. Such a socket fails unless the host has already loaded
the module, as it has loaded bluetooth on a host with an adapter. The host's
own services load modules as before.

The refusal covers every container on the host running in `container_t` or a
type derived from it, including containers you run by hand outside
workloadctl. A privileged container's `spc_t` keeps the permission, which is
why toolbox containers are unaffected, and why `privileged` gets around it.

A workload whose software needs a module names it, and its setup unit loads
it before any of its containers start:

```toml
[security]
kernel_modules = ["wireguard"]
```

Without it, wg-quick's `ip link add ... type wireguard` fails inside the
container with "Unknown device type". A module the host's modprobe
configuration refuses, or one that does not exist, fails the setup unit by
name, and the workload does not start. `kernel_modules` is for containers
only, in the top-level `[security]`; a VM's guest loads its own kernel's
modules.

### A policy of the workload's own

A workload that needs rights beyond the container domain, such as reading
the host's journal or using a GPU's device nodes, gets an SELinux type of its
own rather than extra rules on `container_t`. A policy module is loaded host
wide, so a rule written against `container_t` would widen every container on
the host. A per-workload type keeps the extra rights to the one workload.

```toml
[security]
selinux_policy = true
```

With `selinux_policy = true`, `enable` loads the workload's `policy.cil` as
a module named `wl_<name>`, and the containers run as `wl_<name>.process`,
with dashes in the name turned into underscores. `disable` removes the
module. In a workload of several containers, every container runs as that
type; the key belongs in the top-level `[security]`.

`policy.cil` is found like any other control file: an override in
`/etc/workloads.d/<name>/` wins, then a copy in the bundle's local layer
`/etc/workloadctl/bundles/<bundle>/`, then the bundle's copy under
`/usr/share/workloadctl/workloads/<bundle>/`. For a workload of your own,
put it beside the TOML. It is a CIL block whose name is the placeholder
`__WL_MODULE__`, which `enable` replaces with `wl_<name>`. It inherits the
complete container domain from the base templates container-selinux ships in
`/usr/share/udica/templates/`, and adds the rules the workload needs:

```
(block __WL_MODULE__
    (blockinherit container)
    (blockinherit net_container)

    (allow process syslogd_var_run_t (dir (open read search getattr watch)))
    (allow process syslogd_var_run_t (file (open read getattr map))))
```

`(blockinherit container)` is required. `net_container` gives network
access, which most workloads need. Inside the block, `process` is the
workload's own type.

Files in the local layer need no relabelling. They carry `/etc`'s `etc_t`
where shipped ones carry `usr_t`, and the build, the policy load, the setup
script and a system service the script starts all read them as they are.

#### Writing it with udica

udica, an optional package ([Installing](02-installing.md)), writes the
policy for you. It reads what a container is configured to touch, its
mounts, devices and ports, from `podman inspect`, and folds in what it needs
at run time from the audit log.

**1. Start from the skeleton.** Put the block above, without the `allow`
lines, in `/etc/workloads.d/<name>/policy.cil`, set `selinux_policy = true`
and enable the workload. It now runs as `wl_<name>.process` with the
container domain's rights and nothing more, which gives you a type to work
on.

**2. Generate the base** from the container's configuration:

```bash
sudo workloadctl incant <name> -- inspect workload-<name> > /tmp/<name>.json
udica -j /tmp/<name>.json wl_<name>
```

In a workload of several containers, inspect `workload-<name>-<container>`.

**3. Collect what it needs at run time.** Access an application needs only
while running, such as JIT `execmem`, a debugger's `ptrace` or a sandbox's
mounts, never appears in its configuration, so you collect it by using the
application. Make just this workload's type permissive, so it runs
unhindered while the rest of the host stays enforcing, and turn off
`dontaudit` rules so that denials the policy normally hides are logged too:

```bash
sudo semanage permissive -a wl_<name>.process
sudo semodule -DB
#   ...exercise the application: start it, open a project, build, debug...
sudo ausearch -m avc -ts recent | grep wl_<name> > /tmp/<name>-avcs.log
```

`-ts recent` covers the last ten minutes; for a longer session give
`ausearch` the time you started instead.

**4. Fold it in and go back to enforcing.**

```bash
udica -j /tmp/<name>.json -a /tmp/<name>-avcs.log wl_<name>
sudo semodule -B
sudo semanage permissive -d wl_<name>.process
```

Don't skip the last two commands: until they run, the workload is
unconfined in practice and the host logs every hidden denial.

udica writes `wl_<name>.cil`. Don't load it as it is: copy its `(allow
process ...)` lines, and any `(blockinherit ...)` of a template other than
`container`, into the block in your `policy.cil`. Then load it:

```bash
sudo workloadctl enable <name>
```

A change to the policy alone takes effect in the running container at once,
without a `recreate`. For a bundle's policy, `sudo workloadctl edit <name>
policy.cil` makes the override for you, and prints the same `enable` to
load it.

Two traps. A `filecon` line in `policy.cil` for a path under
`/var/lib/workloads` or `/run/workload-vm` is silently ignored, because
workloadctl registers its own file-context rules for those trees with
`semanage`, and those outrank any module's. `validate` warns about it; label
such paths with `semanage fcontext` instead. And a denial that never
appears, even with the type permissive, is usually one a `dontaudit` rule
hides: run `semodule -DB` before you conclude the log is complete, and
`semodule -B` afterwards.

A `wl_` module outlives a workload whose TOML is deleted by hand.
`sudo workloadctl cleanup` lists the modules no configuration declares, with
the other leftovers it finds, and `--apply` removes them.

### VMs

A VM's QEMU runs as `svirt_t`, the domain the distribution's policy already
maintains for a hypervisor hosting an untrusted guest. This applies to every
VM workload and has no setting. passt runs beside it as `passt_t`, and each
virtiofs sidecar as `wlvfsd_t`, from a module the package loads. The VM's
tree is labelled `svirt_image_t`, a rule `enable` registers for each VM, so a
confined QEMU can open its disks. All of them run at the workload's level,
as containers do, so a QEMU that escapes its guest is held from every other
VM's disks and files by SELinux as well as by its user.

`selinux_policy` means something different on a VM. The `wl_<name>.process`
type is applied by podman, and a VM makes no podman call, so a block written
for a container type confines nothing. A VM's `policy.cil` is instead a set
of extra rules for `svirt_t`, and because every VM on the host runs as
`svirt_t`, such a rule applies to all of them, not only to the VM that ships
it.

On a host with SELinux disabled, VMs run unconfined rather than failing to
start, and the levels, the module refusal and the per-workload types all do
nothing. `workloadctl diagnose` reports which case a VM is in, as
`vm_confinement`.

Two more things belong to a VM's confinement and are covered in
[VM workloads](05-vms.md): `shell` and `exec` verify the guest against a host
key pinned when the VM is provisioned, with no trust on first use
([What a seed file must carry](05-vms.md#what-a-seed-file-must-carry)), and a
drop-in that adds `NoNewPrivileges=` or `DynamicUser=` to a VM or sidecar
unit stops it from entering its domain
([What breaks a share](05-vms.md#what-breaks-a-share)).

### Policy modules on bootc hosts

The package loads four policy modules when it is installed or upgraded:
`workload-vm` (the virtiofs sidecar's domain, passt's rules, and the module
refusal), `workload-inspect` (the egress inspector), `workload-resolve` (the
DNS responder) and `workload-clock` (the VM clock keeper). Each is followed
by a relabel of the program it confines.

On a bootc host, an image update does not replace SELinux policy the host
has changed locally, and nothing recompiles the policy at boot. Every host
with workloadctl installed has changed it, because the package registers
file-context rules at install. So the image can carry a new module while the
host keeps enforcing the old one. A workload's own `wl_` module is worse off:
`enable` added it on the host, and no image update ever replaces it.

`workloadctl diagnose` checks both against the policy actually in force:
`selinux_module_current` for the four host modules and
`workload_selinux_module_current` for a workload's own. To load the host
modules by hand:

```bash
sudo semodule -i /usr/share/workloadctl/workload-vm.cil
sudo restorecon /usr/libexec/virtiofsd
sudo semodule -i /usr/share/workloadctl/workload-inspect.cil
sudo restorecon /usr/libexec/moatery/moat-inspect
sudo semodule -i /usr/share/workloadctl/workload-resolve.cil
sudo restorecon /usr/libexec/moatery/moat-resolve
sudo semodule -i /usr/share/workloadctl/workload-clock.cil
sudo restorecon /usr/libexec/workloadctl/workload-vm-clock
```

A workload's own module is reloaded with `sudo workloadctl enable <name>`.
[The VM runtime](../dev/vm-runtime.md#selinux-internals) describes how the
domains are entered, for maintainers.

## Mounts, devices and sockets

A workload sees its own tree and whatever its configuration mounts, and
nothing else of the host's filesystem. A host tree mounted `ro` is read-only
at its own mount only; mount it `rro` and everything mounted beneath it is
read-only too ([Read-only all the way down](04-containers.md#read-only-all-the-way-down)).

**Where it stops.** Mounting a device node `ro` does not make the device
read-only. A read-only mount refuses writes to files, directories and
links, not writes through a device node, so a block device the workload user
can open is one it can write, whatever the volume's options say. Grant a disk
only to a workload you would trust with every byte on it.

`/dev/uinput` has no scope. A workload given it, through `[devices] input =
true` or as a device of its own, creates input devices, and what it types
reaches whatever holds the host's focus.

A container given the host's journal socket sets its own entries' identifier
and priority. journald stamps each entry with the sender's UID and unit,
which `workloadctl logs` and log shippers go by, and the package configures
journald (`ForwardToWall=no`) not to broadcast an emergency entry to every
logged-in terminal. A container's own output reaches the journal at its
unit's priority whatever it claims, under its own name, and rate-limited.

## What an escaped process keeps

The systemd unit that runs a workload's podman, or its QEMU, bounds what a
process that escapes the container or guest still has. The host's
filesystem is read-only to it (`ProtectSystem=strict`), except the
workload's own tree, its runtime directory, and the host paths of writable
volumes outside the tree. It has a private `/tmp`, and it cannot open
`AF_ALG` or `AF_PACKET` sockets. `[resources]` caps its memory and CPU
([Resource limits](04-containers.md#resource-limits)).

When setup runs as root inside directories the workload's user owns, every
write, change of owner and removal walks the path without following a link.
A link the workload plants cannot steer root to another file.

**Where it stops.** There is no disk quota. A workload can fill the
filesystem `/var/lib/workloads` is on, which is `/var`'s unless you give it
one of its own. A workload with no `memory_max` is capped only by the slice
it runs in, which it shares with the others there.

## Network

`[network]` and `[vm.network]` decide what a workload can reach. A filtered
workload reaches only the names and addresses its policy lists, and none of
the host's own addresses. A pasta container reaches none of the services
listening only on the host's loopback. A VM reaches neither the host's
loopback nor its main address. [Networking](06-networking.md) covers the
stances and how to write a policy.

**Where it stops.** An unfiltered pasta container reaches every host service
listening on all addresses, through the host address pasta maps for it
(`host.containers.internal`), whatever the host's firewall closes to the
LAN. A `mode = "host"` container shares the host's network, loopback
included. A bridged VM has a real address on your LAN, and no egress policy
reaches it.

The egress inspector, the credential broker and the DNS responder run beside
a workload, not inside it. Their policy and status files belong to root, and
the inspector's CA key carries a label no container domain may read.

## Secrets

A secret is encrypted at rest and decrypted into memory, separately for each
workload that uses it. A secret mounted as a file is readable by that workload
alone. A `${SECRET:...}` variable reaches the container's environment, and
podman's record of that environment is in memory too, because each container
workload's podman keeps its container state on tmpfs. [Secrets](07-secrets.md)
covers the rest.

**Where it stops.** A value in the environment is visible to every process
in the container. Images and containers' writable layers are on disk, so a
secret the software writes there stays.

## Image trust

### Which images podman accepts

A container image is accepted or refused by the host's
`/etc/containers/policy.json`, which podman reads for every pull, whether it
runs as a workload's user or as root. workloadctl ships no policy of its own,
and Fedora's default accepts unsigned images from every registry but Red
Hat's.

A stricter policy refuses by default, requires signatures from your own
registry, and names the public registries whose unsigned images you accept:

```json
{
  "default": [{"type": "reject"}],
  "transports": {
    "docker": {
      "registry.example.com": [
        {"type": "sigstoreSigned", "keyPath": "/etc/pki/containers/registry.example.com.pub"}
      ],
      "docker.io": [{"type": "insecureAcceptAnything"}],
      "quay.io": [{"type": "insecureAcceptAnything"}]
    },
    "containers-storage": {"": [{"type": "insecureAcceptAnything"}]},
    "docker-archive": {"": [{"type": "insecureAcceptAnything"}]},
    "oci-archive": {"": [{"type": "insecureAcceptAnything"}]}
  }
}
```

The most specific scope wins, so `ghcr.io/your-namespace` can require a
signature while the rest of `ghcr.io` does not. Keep the local transports
open: an image you `build` reaches a workload's own store through
`podman save` and `podman load`, which a refuse-by-default policy without
`docker-archive` blocks.

Third-party images are accepted unsigned in that policy on purpose. A
workload must be able to run public images, and there is no signature to
check where the publisher does not make one.

**Where it stops.** The policy governs what is pulled on your behalf. Rootless
podman prefers a `~/.config/containers/policy.json` of the user's own, and a
workload user's home is its `state/` directory, which it can write. A process
that has escaped as the workload user can run that user's podman under a
policy of its choosing; it cannot change what other workloads or root pull.

### Holding an image still

What compensates is that an image changes only when you ask it to. `pull`
is not an update setting: it becomes `podman run --pull=` in the unit's
start command. `"always"` and `"newer"` therefore pull at every start of the
service, every boot and every restart included, with no health check and no
way back. Keep `"missing"`, or `"never"` for an image you build. Every
bundle the package ships uses one of those two, and the test suite holds
them to it.

The deliberate path is `sudo workloadctl update <name>`. It pulls the
current tag and, if the image changed, keeps the outgoing one as a rollback
target, restarts the workload, checks that it came back up, and puts it back
on the previous image if it did not
([Updating container images](09-operating.md#updating-container-images)).
A running workload keeps the image it was created from until `update` or
`recreate` replaces its container. `workloadctl diagnose` reports an image
built more than 30 days ago.

`"never"` means never from a registry, not never changing: an image you
build reaches the workload from root's image store on `enable`, `recreate`
and `update` ([Building your own image](04-containers.md#building-your-own-image)).
`update` has nothing to pull for a workload whose every image is `"never"`,
and says to build it instead.

### What floats

A tag is a name, not a content address, and `update` fetches whatever it
points at now. No bundle the package ships pins an image by digest, so
"held" means held in time, not by content. Some tags float without looking
like it: `:vulkan`, `:server-vulkan` and `:default-cpu` move exactly as
`:latest` does, and the bundles that use them say so in a comment. To pin by
content, name the image by digest (`name@sha256:...`).

A VM's cloud image is the exception: `cloud_image_url` requires a `sha256:`
checksum, which the download is checked against every time it is used. A
`local_image` is copied with no check ([Image sources](05-vms.md#image-sources)).
