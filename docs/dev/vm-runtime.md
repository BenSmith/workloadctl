# The VM runtime

This is the maintainers' map of what runs a VM workload on a host: which
unit starts which process, who reads which file, where each SELinux
transition happens, and how the disks are built and rotated. How to write
and run a VM is in the manual's [VM workloads](../manual/05-vms.md). The
egress inspector, the DNS responder and the credential broker a filtered VM
runs behind are in [the egress guide](egress.md), and how units come to
exist at boot is in [boot and generation](boot-and-generation.md).

`lib/gen_vm.py` writes every unit below, `generate_vm_workload` being the
entry point. The runtime half lives in the `libexec/workload-vm-*` helpers,
each a thin `main()` over a `lib/` module.

## The units

| Unit | Kind | Runs as | Runs |
|---|---|---|---|
| `workload-<name>-setup.service` | oneshot, `RemainAfterExit=yes` | root | `systemd-sysusers`, then `workload-ensure-user` |
| `workload-<name>-build.service` | oneshot, `RemainAfterExit=yes` | root | `workload-vm-build-disk` |
| `workload-<name>-virtiofs-<tag>.service` | `Type=exec`, one per volume | `_wl-<name>`, `wlvfsd_t` | `virtiofsd` |
| `workload-<name>.service` | `Type=notify` | `_wl-<name>` | `workload-vm-notify`, which starts passt and QEMU |
| `workload-<name>-clock.timer` and `.service` | timer and oneshot | `_wl-<name>`, `wlclock_t` | `workload-vm-clock` |

A filtered VM adds `workload-<name>-inspect.socket` and its service,
`workload-<name>-resolve.socket` and its service unless `resolver = "none"`,
and `workload-<name>-broker.service` when it declares a credential. Those
are described in [the egress guide](egress.md).

### What starts what

Nothing starts a VM's units except through `workload-<name>.service`. At
boot, `workload-generate` enqueues `systemctl start --no-block` for every
enabled workload's main unit, and the CLI's lifecycle commands start or
restart it. Everything else arrives through the main unit's dependencies:

- `Requires=` and `After=` the setup unit, the build unit, every virtiofs
  sidecar, and, for a filtered VM, the inspector socket, the responder
  socket and the broker. `Requires=` is deliberate for the egress units: a
  failed arming prestart has to keep the VM down rather than let it boot
  unprotected.
- `Wants=` and `After=` `network-online.target`, for a passt VM only. passt
  copies the guest's address and gateway from the host, and the netdev
  prestart reads the host's default route.
- `Wants=` the clock timer, never `Requires=`. The timer is `PartOf=` and
  `After=` the VM from its own side, so it runs only while the VM does, and a
  keeper that cannot start never holds the VM up.

The build unit `Requires=` and orders `After=` the setup unit, and carries
`ConditionPathExists=!state/system.qcow2`. Each sidecar `Requires=` the
setup unit and the VM, orders `After=` setup and `Before=` the VM, and is
`PartOf=` the VM, so stopping or restarting the VM takes the sidecars with
it. A sidecar whose share root lies outside the workload's tree gets
`RequiresMountsFor=` that path, and each `[vm].after_mounts` entry adds an
ordering-only `After=` on its `.mount` unit, which leaves the VM bootable
while a nested remote filesystem is down.

The setup and build units are `RemainAfterExit=yes`, which is the property
to remember: once active they stay active, and restarting the VM re-runs
neither. Three paths re-run setup on purpose. `enable` calls
`workload-ensure-user` directly from `provision_user`
(`lib/provisioning.py`). `recreate` (`cmd_recreate`) and `edit`'s apply step
both `systemctl restart` the setup unit. The build unit's condition means it
builds only when the system disk is missing, and `update` does not go
through it at all: `VMSubstrate.reprovision` runs
`workload-vm-build-disk <name> --update` itself and then restarts the VM.

### The main unit

For a passt VM the main unit runs three root prestarts, each `+`-prefixed so
it runs outside the unit's sandbox:

1. `workload-vm-netdev` writes `/run/workload-env/workload-<name>.passt`, an
   environment file holding `WL_PASST_DNS`, passt's DNS options derived from
   the host's resolver and default route. It cannot run in the generator,
   which runs before there is a default route. systemd re-reads
   `EnvironmentFile=` for every `Exec*` line, so the start that follows sees
   the file. It always exits 0.
2. `workload-vm-filter up` applies the nftables skeleton and this
   workload's elements. It has no `-` prefix: a filtered VM whose policy
   cannot be armed must not start.
3. `workload-vm-svcaddr up` puts the VM's own derived `198.18.x.y` address
   on the shared dummy link, so a host service can publish on it
   (`lib/svcaddr_arm.py`).

`ExecStopPost=` undoes the last two with `-+`, so a crashed or killed VM
does not leave its UID armed or its address on the link. `ExecStop=` is
`workload-vm-shutdown`, which sends `system_powerdown` over `qmp.sock` and
blocks for up to 80 seconds until QEMU exits. It has to block: systemd
starts its kill phase as soon as `ExecStop=` returns, and a powerdown that
returned at once would be followed within milliseconds by a `SIGTERM` to
QEMU. `TimeoutStopSec=90` is the backstop.

The unit owns `RuntimeDirectory=workload-vm/<name>` with
`RuntimeDirectoryPreserve=yes`. The sidecars use that directory for their
sockets and must not declare it themselves, or stopping one would remove the
directory from under QEMU.

The sandbox is `ProtectSystem=strict` with the state and data directories
writable, `PrivateTmp=yes` and `RestrictAddressFamilies=~AF_ALG AF_PACKET`.
There is no `NoNewPrivileges=`, because QEMU reaches `svirt_t` by a domain
transition and no-new-privs refuses that transition. QEMU's own seccomp
filter is on its command line instead (`QEMU_SANDBOX` in `lib/vm_defs.py`).
QEMU runs directly in this unit's cgroup, so `[resources]` binds here.

A bridged VM has none of the three prestarts or the two stop-posts, and
orders only after its prerequisites.

## workload-vm-notify

The main unit's `ExecStart=` is

```
workload-vm-notify <name> --passt <passt argv> -- <qemu argv>
```

or `--bridge <bridge> --` in place of the passt words. The whole QEMU
command line is in the unit file. The program is `lib/vm_notify.py`
(`split_argv`, `supervise`, `run_qemu`), and it stays alive as the unit's
main PID for the guest's lifetime.

### passt and QEMU on one socket pair

For a passt VM the wrapper:

1. makes a connected Unix stream pair labelled with QEMU's context, by
   writing that context to `/proc/thread-self/attr/sockcreate` around the
   `socketpair()` call (`vm_socketpair`, `lib/egress_selinux.py`);
2. starts passt on one end, as
   `runcon system_u:system_r:passt_t:<level> passt … --fd <n>`;
3. replaces the `@passt-fd@` token in QEMU's
   `-netdev stream,id=net0,server=off,addr.type=fd,addr.str=@passt-fd@` with
   the other end's number;
4. starts QEMU as `runcon system_u:system_r:svirt_t:<level> qemu-system-x86_64 …`,
   passing that fd, and closes its own copies.

passt runs beside QEMU rather than under it because whatever QEMU starts
inherits QEMU's seccomp filter, and passt fails under `-sandbox on`. With
passt started by the wrapper, QEMU runs libvirt's default sandbox including
`spawn=deny`. A bridged VM is handled the same way: the wrapper runs the
setuid `qemu-bridge-helper` with `--use-vnet --fd=`, receives the tap's
descriptor over `SCM_RIGHTS`, and QEMU takes it as `-netdev tap,fd=`.

passt's argv comes from `build_passt_argv`: `--quiet --foreground`, the
derived MAC, the management forward `-t 127.128.x.y/2222:22`, one `-t` or
`-u` per published port (separate options, because passt allows one leading
address per comma list and the management forward always carries one),
`--map-host-loopback none`, `--search none`, `--outbound-if4/6` when
`outbound_if` is set, and `$WL_PASST_DNS`. passt keeps the workload UID only
because it is not started as root, since as root it drops to `nobody`. The
unit's `User=` is what makes the UID a per-VM network identity, and a test
holds it.

### Readiness and what the wrapper watches

The wrapper connects to `qmp.sock`, negotiates, and polls `query-status`
until the vCPUs run, then sends `READY=1` (`NotifyAccess=all`). The connect
and each read get 60 seconds, because QEMU opens the listener before machine
init and services it only once its main loop runs. If the guest does not
reach the running state in 120 seconds, no `READY=1` is sent and
`TimeoutStartSec=300` decides. Any other QMP failure still sends `READY=1`,
with `STATUS=Degraded: …`, so a broken monitor does not hang the unit.

Two daemon threads then run beside QEMU:

- **The passt watch.** If passt exits and QEMU has not followed within three
  seconds, outside a stop, the wrapper terminates QEMU and exits 1, so the
  unit fails. A guest with no network otherwise looks healthy from
  everywhere.
- **The provisioning watch.** Every 15 seconds for up to 30 minutes it asks
  the guest over SSH, on the management address, whether cloud-init
  finished, and records the answer in `state/.cloud-init-provisioned`
  (`lib/vm_provision.py`). It uses SSH because the guest agent runs in
  `virt_qemu_ga_t` inside the guest, which stock guest policy keeps away
  from cloud-init's state. `workload-ensure-user` reads that marker when it
  decides whether to reuse the instance ID, and rotates it once per lineage
  after a recorded failure (`_resolve_cloud_init_instance_id`,
  `lib/ensure_vm.py`).

The exit status is QEMU's. With `[vm].restart = "on-reboot"`, QEMU gets a
third monitor, `qmp-notify.sock`, which the wrapper reads for the
`SHUTDOWN` event: `guest-reset` exits 133 (`VM_REBOOT_EXIT_CODE`), which the
unit's `Restart=on-failure` relaunches, and `guest-shutdown` exits 0. The
wrapper forwards `SIGTERM` and `SIGINT` to QEMU, but in an ordinary stop
`ExecStop=` has already powered the guest off before systemd signals
anything.

## The runtime directory

Everything a running VM exposes on the host is in `/run/workload-vm/<name>/`:

| Path | Who serves it | Who uses it |
|---|---|---|
| `qmp.sock` | QEMU | the notify wrapper (readiness), `ExecStop=`, `incant`, `info`, `backup`'s pause, `pcap`'s guest-side capture |
| `qmp-metrics.sock` | QEMU | the Prometheus exporter and `stats`, for queries only (`lib/vm_metrics.py`) |
| `qmp-notify.sock` | QEMU, in on-reboot mode only | the notify wrapper's `SHUTDOWN` watch |
| `ga.sock` | QEMU, relaying `qemu-guest-agent` | the clock keeper, guest address lookup, `backup`'s resync |
| `console.sock` | QEMU's serial port | `shell --console`, through `socat` |
| `virtiofs-<tag>.sock` | each sidecar | QEMU's `vhost-user-fs-pci` device |
| `cloud-init.iso` | the setup unit | QEMU's read-only CD drive |

The QMP monitors are separate because a monitor serves one client at a
time. The exporter scrapes every 15 seconds; on a shared monitor, a scrape
in flight when `ExecStop=` sends `system_powerdown` would make the powerdown
wait, the stop would time out, and the guest would be killed rather than
shut down. The `SHUTDOWN` watch gets its own monitor for the same reason.
`ga.sock` speaks the guest-agent protocol, not QMP: it has no greeting and
no `qmp_capabilities`, and every client starts with `guest-sync` and a
nonce, because a reply left queued by an earlier client that timed out
would otherwise be read as the answer.

The directory needs the `svirt_var_run_t` type (an alias; `ls -Z` shows
`qemu_var_run_t`), and the RPM's `%post` registers
`/run/workload-vm(/.*)?` for it. Registering the rule is not enough. The
kernel labels a new file from its parent directory and never reads
`file_contexts`, so a directory created under `/run` is `var_run_t`, and a
confined QEMU then cannot create its sockets or read the seed.
`setup_workload_runtime_dir` (`lib/ensure_common.py`) runs `restorecon` on
the directory before anything is written into it, at every boot, since
`/run` is a tmpfs.

## The virtiofs sidecar

`generate_virtiofs_service` writes one unit per `[vm].volumes` entry. The
manual covers what a share looks like from the guest; this is why the
daemon is built the way it is.

### No privileges, because the ID map leaves nobody to impersonate

`virtiofsd` serves each request under the requesting guest user's IDs,
switching credentials per request, and that switch is what would need
`CAP_SETUID`, `CAP_SETGID`, and `fowner`/`fsetid` to carry modes across it.
The sidecar's ID map makes the switch unnecessary. For both UIDs and GIDs it
passes `map:1000:<uid>:1`, `squash-guest:0:<uid>:1000` and
`squash-guest:1001:<uid>:<tail>`: guest 1000 maps to the workload user in
both directions, and every other guest ID is squashed one way onto it. Every
guest ID therefore arrives as the daemon's own UID, and `virtiofsd` skips
the switch when the two are equal. The unit runs as `_wl-<name>` with
`CapabilityBoundingSet=` and `AmbientCapabilities=` empty.

The map is load-bearing for function as well as security. If a change lets
another guest ID through, the sidecar fails with `EPERM` on the switch
rather than quietly needing privilege back, and that is the failure
direction to keep.

The ranges must partition, since `virtiofsd` rejects overlapping entries,
and the tail stops one short of 2³², because ranges are half-open and built
with `checked_add`. So guest ID 4294967295 escapes the map and is
identity-mapped. For it `virtiofsd` calls `setresuid(-1, 4294967295, -1)`,
which the kernel reads as "leave unchanged", so the file takes the daemon's
current UID. Unprivileged, that is the workload user; a sidecar running as
root would hand a guest naming that ID a root-owned file. This is the
sharpest reason the sidecar must stay unprivileged.

### Sandbox and confinement

The unit passes `--sandbox=none`. `chroot` mode needs euid 0 outright, and
`namespace` mode needs user namespace creation, capabilities in the new
namespace and mount permissions across several types, a poor trade for a
process holding no capabilities. `virtiofsd` still installs its own seccomp
filter, and sets no-new-privs on itself after the exec while doing so, which
is the only reason no-new-privs shows on the running process.

Three layers confine it instead. DAC: it is the workload's own unprivileged
user. The unit's mount namespace: `ProtectSystem=strict` with
`ReadWritePaths=` naming only the share and the runtime directory, plus
`ProtectProc=invisible`, `PrivateTmp=yes`, and `ProtectHome=yes` unless the
share is under `/home`, `/root` or `/run/user`, which `ProtectHome=` would
mask. And the `wlvfsd_t` domain, entered through `SELinuxContext=` at the
workload's level.

The unit must never gain `NoNewPrivileges=`, or `DynamicUser=`, which
implies it. Under no-new-privs the kernel refuses any domain transition not
bounded by the caller, `wlvfsd_t` is not bounded by `init_t`, and the exec
fails `203/EXEC` with "Permission denied" and this record in the audit log:

```
type=SELINUX_ERR op=security_bounded_transition seresult=denied
  oldcontext=system_u:system_r:init_t:s0
  newcontext=system_u:system_r:wlvfsd_t:s0
```

`SELinuxContext=` does not avoid it, since the check is on the transition
however it is requested. The seccomp-based options (`PrivateDevices=`,
`ProtectKernel*=`, `SystemCallFilter=` and the like) do not force
no-new-privs for a system service, whose manager holds `CAP_SYS_ADMIN`; they
are absent only because nobody has tested them against `virtiofsd`.

### Smaller choices in the unit

- `--inode-file-handles=never`. The default, `prefer`, needs
  `CAP_DAC_READ_SEARCH` in the initial user namespace, so it can only fail
  and fall back, leaving a warning and one `dac_read_search` AVC per start
  that look like a policy bug.
- `LimitNOFILE=1000000`. `virtiofsd` wants that many descriptors and cannot
  raise its own hard limit unprivileged, so systemd raises it first; the
  daemon then skips its own `setrlimit`, which is why the policy has no
  `process setrlimit`.
- `ExecStartPre=+/bin/rm -f` of the socket and its `.pid` file. `virtiofsd`
  opens the pid file `O_CREAT|O_WRONLY` at mode 0600, so a leftover owned by
  another user stops the daemon with "Error creating pid file … Permission
  denied". Removing it is safe against a live peer, because `virtiofsd`
  takes an `flock` and re-checks the inode. The `+` is needed because
  `SELinuxContext=` applies to every `Exec*` line and `wlvfsd_t` may enter
  only `virtiofsd`.
- `Type=exec` and an `ExecStartPost=` that waits for the socket.
  `virtiofsd` sends readiness only after QEMU connects, which would deadlock
  with `Type=notify` and `Before=` the VM.
- `--announce-submounts` or `--no-announce-submounts`, always one of them,
  because `virtiofsd`'s own default has changed between implementations.

On the QEMU side, a VM with volumes has its RAM in a shared
`memory-backend-memfd` with a NUMA node on it, which `virtiofsd` maps. The
generator puts a 1 MiB spare memfd backend ahead of guest RAM. It guards
against a double close in QEMU's own passt netdev, which could take the
first memory backend's descriptor. The stream netdev in use does not have
that close, and the spare stays until a start loop shows guest RAM's
descriptor is safe without it.

### A share over the guest's home

cloud-init writes `authorized_keys` in its init stage and mounts volumes in
the config stage after it, so a share mounted at the login user's home
hides the key on every boot. `seed_vm_home_share_ssh_key`
(`lib/vm_ssh_keys.py`) writes the workload's public key into the share on
the host, before the seed is built, whenever the setup unit runs. It adds to
the file and never rewrites a line already there. Because it is root
writing into a tree the workload user owns, it descends with `O_NOFOLLOW`
(`_descend_nofollow`) and opens the file the same way, so a swapped-in
symlink fails the start rather than redirecting the write. A failure is
fatal to setup. A share outside the workload's tree is skipped with a
warning, because the walk needs a root-owned anchor to be safe.

## The `wlvfsd_t` rule list

`security/workload-vm.cil` carries the rules, one comment per rule. The
domain exists because once QEMU is `svirt_t`, SELinux checks `connectto`
against the peer process's domain, and Fedora ships no `virtiofsd` domain;
an unconfined sidecar would need a blanket
`svirt_t → unconfined_service_t` connect rule. The file explains why a
dedicated domain is better than that one line.

The domain is granted the types workloadctl itself labels: `svirt_image_t`
for a VM's tree, `qemu_var_run_t` for the runtime directory, `svirt_tmpfs_t`
to map QEMU's memfd, `svirt_t` Unix stream sockets, a search on
`container_file_t`, and `filesystem getattr` on both `fs_t` and
`svirt_image_t`. The second is for a share mounted with
`context=…svirt_image_t…`, where the superblock carries that type and `df`
in the guest otherwise fails. It grants no capability at all: with an empty
bounding set a capability rule could only describe a privilege the daemon
does not hold, so a capability denial for `wlvfsd_t` means the unit has
changed.

Extend the list only by rebuilding it. A permissive harvest yields exactly
the classes its workout exercised and nothing warns about the rest, so an
incomplete workout produces a module that serves a share until one ordinary
operation fails. Remove every `wlvfsd_t` rule, then:

```bash
sudo semanage permissive -a wlvfsd_t
sudo semodule -DB          # dontaudit rules hide some denials otherwise
# drive a live guest through the workout
sudo grep -a 'scontext=[^ ]*:wlvfsd_t' /var/log/audit/audit.log | grep -a denied
sudo semanage permissive -d wlvfsd_t && sudo semodule -B
```

The workout covers create, read, write, truncate and append; mkdir and
rmdir; symlinks read, created, renamed and deleted; hard links; FIFOs and
Unix sockets created and deleted; chmod, chown and utimes on files,
directories and each of the three special classes (`mkfifo -m`, `chmod` on
a bound socket, `lutimes` and `lchown` on a symlink); rename within a
directory and across directories, for a FIFO and a socket as well as a
file; `statfs`; a first-boot cloud-init; and a clean stop. The classes an
incomplete workout drops are the ones below `file`:

| Class or permission | What a guest loses without it |
|---|---|
| `lnk_file` | `ln -s` anywhere in the share |
| `fifo_file`, `sock_file` | a build that opens a FIFO; a daemon binding a socket in its home |
| `dir setattr` | chmod, chown and utimes on a directory; cloud-init chowns a home |
| `dir rename`, `dir reparent` | `mv` within a directory and between directories |
| `file link` | hard links |
| `setattr` on the three special classes | `mkfifo -m`; `chmod` on a socket; `lutimes`/`lchown` on symlinks, which `cp -a`, `rsync -a` and `tar -xp` do to every symlink |
| `rename` on `fifo_file`, `sock_file` | `mv` of a FIFO or socket |

None of these is reachable by a test that reads the rendered unit.
`tests/cli_surface/test_runtime_vm_virtiofs.py` checks the posture and the
workout on a real guest, as part of `just test-runtime`.

## The clock keeper

A vCPU pause rewinds the guest's clock by its length, permanently, and NTP
does not repair it: a filtered guest cannot reach NTP, and a stock chrony
only steps during its first three updates. The keeper repairs any VM's
clock without knowing why it is wrong, so no path that pauses vCPUs needs a
hook of its own.

`generate_vm_clock_timer` writes a timer with `OnActiveSec=60s`,
`OnUnitActiveSec=60s` and `AccuracySec=5s`. Both are monotonic, and the
monotonic clock does not advance while the host is suspended, so a host
resumed after hours ticks within a minute of resuming.
`generate_vm_clock_service` writes a oneshot as the workload user in
`workloads.slice`, with `ConditionPathExists=` on `ga.sock`, so a tick that
lands while the VM is down is skipped rather than failed. It runs in the
sidecar sandbox (`harden_sidecar` in `lib/gen_egress.py`) with
`RestrictAddressFamilies=AF_UNIX`, eight tasks and 64 MiB.

It runs in `wlclock_t` (`security/workload-clock.cil`), entered by a type
transition from `init_t` on the file context of
`/usr/libexec/workloadctl/workload-vm-clock`. The domain may connect to
`svirt_t`'s `ga.sock` and do little else. It exists because the keeper
parses bytes written by a process inside the guest, which is exactly what
the design distrusts, and it keeps that parser out of the inspector's
domain.

Each tick is `keep_guest_clock` (`lib/vm_clock.py`). It connects to the
agent with a 1.5-second budget, syncs with a nonce, and reads
`guest-get-time` bracketed by two host timestamps, taking the offset from
their midpoint. Within five minutes it does nothing and says nothing.
Beyond that it calls `guest-set-time` with explicit nanoseconds and logs one
line, or exits 1 if the guest refuses. With no agent it is silent: a guest
without `qemu-guest-agent` is supported, and a keeper that said so every
minute would bury the journal. `diagnose` is where that state, and a clock
past the threshold, become failed checks (`lib/diagnose_vm_clock.py`).
`backup --consistency crash` resyncs right after its own unpause at a
one-second threshold (`BACKUP_RESYNC_THRESHOLD_SECONDS`, `lib/backup.py`),
since it knows it just paused the guest.

### Measured behaviour

`tests/manual/clock_rig.py` measures this on a KVM host under enforcing
SELinux whose clocksource is the TSC:

| | Result |
|---|---|
| Drift with no correction | about 10 ppm, 3.7 s over four and a half days |
| A 120 s vCPU pause | the guest falls back 119.98 s, within 25 ms of the pause |
| After resuming, uncorrected | still 119.3 s behind; nothing puts it back |
| `ptp_kvm` in the guest | repairs the pause alone in 24 s; chrony selects `PHC0` at about 874 ns |
| `guest-set-time` with nanoseconds | works: 119.3 s behind becomes +0.7 s |
| `guest-set-time` with no argument | fails: `hwclock: select() to /dev/rtc0 to wait for clock tick timed out` |
| A guest 7200 s behind, keeper held off | every fresh leaf fails (`certificate is not yet valid`) while the inspector reports healthy |
| The same guest, keeper released | back within a minute, the keeper in `wlclock_t`, and the leaf validates |

The no-argument `guest-set-time` reads the guest's RTC, and that read is
what fails; the explicit form writes it and succeeds. The keeper uses only
the explicit form.

### The guest's half: `ptp_kvm`

`lib/vm_ptp.py` holds the text every seed workloadctl renders carries. It
has three pieces. A `modules-load.d` entry loads `ptp_kvm`, which no cloud
image loads on its own. A udev rule names the device `/dev/ptp_kvm` by the
driver's `clock_name`, because `/dev/ptpN` is numbered in allocation order.
A `runcmd` block loads the module and waits up to five seconds for the
device; if the device and `/etc/chrony.conf` both exist and the marker line
is absent, it deletes the `pool` lines, appends
`refclock PHC /dev/ptp_kvm poll 2 dpoll -2 offset 0` and `makestep 1 -1`,
and restarts chronyd.

`makestep 1 -1` is the line that fixes the bug, letting chrony step at any
time instead of only at start. The chrony edit is conditional because
chronyd treats a refclock it cannot open as fatal, and an unconditional
edit would leave a guest on an unsupported host with no time service at
all. The `pool` line goes because in a filtered guest the responder answers
every name with the inspector's address, so chrony would dial UDP 123 there
for the guest's whole life, counted as wrong-port self-dials.

The guest driver uses KVM's clock-pairing hypercall, which KVM answers only
when the host's clocksource is the TSC. On an `hpet` or `acpi_pm` host the
module fails to load in every guest with `Operation not supported`, and
those guests depend on the keeper alone.

The built-in seed takes the files and the `runcmd` lines from
`vm_ptp_kvm_seed_files` and `vm_ptp_kvm_runcmd_lines`. The starter seed in
`workloads/vm-base/cloud-init/user-data` carries the same text, and the
`init --scratch-vm` stub in `lib/scratch_vm.py` is byte-identical to it, which
`tests/test_catalog.py` asserts. `tests/test_vm_ptp_kvm.py` covers what each
piece is for.

## Disks and generations

`workload-vm-build-disk` is `build_disks` in `lib/vm_disk_build.py`. It runs
as root and treats `state/` and `data/` as the workload user's, since any
name in them may be a link that user planted. So the work happens in a
root-only temporary directory under the workload root (`.disk-build-*`), and
the image cache (`.image-cache/`) and bootc's output (`.bib-build/`) live
there too. The finished system disk is chowned to the workload user and
moved into `state/` by the no-follow walk (`_install_file_nofollow`),
replacing what is at the name. A new data disk is linked into `data/` only
where nothing exists.

The system disk comes from one of three builders: `build_from_cloud_image`
over `download_cloud_image` (`lib/vm_image_fetch.py`), which caches by the
URL's file name, verifies SHA-256 on every use and re-downloads on a
mismatch, then reflink-copies a qcow2 or converts anything else with
`qemu-img`; `build_from_local_image`, a reflink copy with no check; or
`build_from_bootc_image`, which runs `bootc-image-builder --type qcow2`. A
`system_disk_size` is applied with `qemu-img resize` before the disk is
installed. The data disk is `qemu-img create` of `data_disk_size`, made when
`data.qcow2` does not exist.

With `--update`, `rotate_generations` (`lib/vm_disk_generations.py`) first
renames `system.qcow2` to `system.qcow2.gen-<max+1>` and prunes the oldest
generations beyond `rollback_keep`, never counting the one it just made, so
`rollback_keep + 1` remain. QEMU keeps writing to the renamed inode until
the restart, so the new generation holds the guest's state at shutdown. If
the build raises, the rotated disk is renamed back and the VM keeps running
on it. Generation numbers only grow, so the highest is always the newest.

Rollback is `VMSubstrate.rollback_to` (`lib/substrate_vm.py`), and it is
non-destructive ([ADR 003](../adr/003-vm-rollback-non-destructive.md)). It
stops the VM, because renaming the open disk would leave the old guest
writing to an unlinked inode. It rotates the current disk out to a new
highest generation, moves the chosen generation into place, prunes with the
rotated disk exempt, and starts the VM. If moving the target in fails, the
rotated disk is put back first. `rollback` always picks the highest
generation, which after one rollback is the disk it replaced, so a second
rollback rolls forward. A pet VM is never rotated: `reprovision` restarts it
and `rollback` refuses.

A rebuilt system disk boots with the seed's existing instance ID and no
cloud-init state, so cloud-init does its first-boot work again. Two seams
here are worth knowing:

- The provisioning marker is keyed by instance ID, and the watch returns at
  once when the marker already vouches for that ID, so the first boot of a
  disk rebuilt by `update` is not watched.
- The build unit's `ConditionPathExists=!state/system.qcow2` means a
  `data_disk_size` added after the first build is not acted on by the next
  start. `build_disks` would create the data disk, but only `update`
  reaches it on a VM that already has a system disk.

## Boot, from host to guest

1. The shell generator `workload-generator` emits `workload-generate.service`
   into `basic.target.wants`. That oneshot, ordered after `sysinit.target` and
   before `basic.target`, writes each enabled workload's sysusers file and
   units into `/run/systemd/system/` and a `multi-user.target.wants` link for
   the main unit, then enqueues the main units in one `systemctl start
   --no-block`. See [boot and generation](boot-and-generation.md).
2. The setup unit runs `systemd-sysusers` and then `workload-ensure-user`
   (`provision` in `lib/ensure_user.py`). For a VM, in order: the home
   directory, the provenance record and group membership; then NVRAM, a copy
   of `OVMF_VARS.fd` made once and never overwritten. Then the runtime
   directory, relabelled, and the in-tree volume directories; the SSH keypair;
   the home-share key; the guest's SSH host keypair; the egress CA and its PKI
   directories for a filtered VM; the seed ISO; the workload's MCS level
   stamped on its tree; and the environment file. A failure in group
   membership, NVRAM, any of the keys, the CA, the seed or the label stamp
   fails the unit, and the VM does not start. A seed-contract refusal exits 2,
   so `enable` can print it as an operator error rather than a crash.
3. The build unit builds the system disk, if there is none.
4. The sidecars start, and for a filtered VM the inspector socket, the
   responder socket and the broker.
5. The main unit runs its prestarts, and the notify wrapper starts passt and
   QEMU and sends `READY=1`. The clock timer starts beside it.
6. In the guest, OVMF boots from the read-only `OVMF_CODE` and the VM's own
   `nvram.fd`. cloud-init finds the seed on a CD drive labelled `CIDATA`,
   reads the instance ID from its `meta-data`, and runs its per-instance
   modules if this disk has not seen that ID.
7. The provisioning watch records whether that run succeeded.

The seed is `build_cloud_init_iso` (`lib/ensure_vm.py`). It renders the
built-in user-data (`lib/vm_default_seed.py`) or substitutes into the
operator's file (`substitute_template`, `lib/secrets_template.py`), applying
the seed contract to the latter. A relative `user_data_file` is found with
`control_file_source` (`lib/workloadctl_core.py`), the chain every control
file uses. It pins the guest host key in
`state/.ssh/vm_known_hosts`, keyed by `HostKeyAlias=<name>` so the
management address never matters to the pin. Then it fingerprints the
rendered text into `state/.cloud-init-fingerprint`. If the ISO already
exists, the fingerprint matches and no heal is due, it stops there. The
instance ID in `state/.cloud-init-instance-id` is kept when the fingerprint
matches and minted afresh when it does not. The ISO is staged in
`/run/workload-vm/_seed/<name>/`, root's and 0700, built with `xorriso` or
`genisoimage` as volume `CIDATA`, and renamed into place at mode 0640, owned
by the workload user. The staging directory is then removed. All of it is
on tmpfs, so decrypted secrets in the seed never reach the host's disks.

## SELinux internals

| Process | Domain | How it gets there |
|---|---|---|
| `workload-vm-notify` | `unconfined_service_t` | systemd's default for a `bin_t` service |
| QEMU | `svirt_t` | `runcon` from the wrapper; the shipped policy allows `unconfined_service_t` to transition into `virt_domain` |
| passt | `passt_t` | `runcon` from the wrapper; the transition rule is in `workload-vm.cil` |
| `virtiofsd` | `wlvfsd_t` | `SELinuxContext=` and an `init_t` type transition on its file context |
| `workload-vm-clock` | `wlclock_t` | an `init_t` type transition on its file context |

Every one of them runs at the workload's level, `s0:cA,cB`, two categories
from the 300 below `c300` derived from the UID (`lib/workload_mcs.py`). A
share a workload belongs to adds its own category from `c300` upward.

`SELinuxContext=` cannot put QEMU in `svirt_t`, because the policy has no
`init_t → svirt_t` transition; libvirt gets there through `virtqemud_t`.
`runcon` from the wrapper works because the wrapper is
`unconfined_service_t`, and it must exec QEMU directly: the entrypoint is
`qemu_exec_t`, and a shell in between is `bin_t`, which is refused. `runcon`
is used rather than `setexeccon()` because `lib/` has no third-party
dependencies, and because `runcon` scopes the exec context to the one
child.

passt needs three rules from `workload-vm.cil`. Shipped policy lets only
`svirt_t` enter `passt_t`, and passt run as `svirt_t` cannot create the user
namespace it isolates itself in, so the module allows
`unconfined_service_t → passt_t`. Two `fd use` rules let passt and QEMU use
descriptors the wrapper opened. The third rule matters most: the socket
pair carries QEMU's label, so passt must read and write an `svirt_t`
`unix_stream_socket`. Shipped policy does not allow that and dontaudits it,
so without the rule passt fails with
`Failed to add fd to epoll: Operation not permitted`, the guest has no
network, and the audit log is empty unless you run `semodule -DB`.

A VM's tree under `/var/lib/workloads/<name>/` is `svirt_image_t`: `enable`
registers that fcontext rule for the workload, which overrides the RPM's
blanket `container_file_t` rule (`apply_vm_fcontext`,
`lib/workload_selinux.py`). The setup unit then stamps type and level in one
pass on every run (`stamp_selinux_labels`, `lib/ensure_common.py`). The
level is not registered anywhere, so a relabel puts the files back at `s0`
until the next setup run. The runtime directory is `svirt_var_run_t`, as
above.

`workload-vm.cil` also denies `module_request` to `container_domain`,
`svirt_t`, `passt_t` and `wlvfsd_t`, and `workload-clock.cil` denies it to
`wlclock_t`, so a socket for an unloaded protocol family cannot make the
kernel load a module on a workload's behalf.

The modules are installed by the RPM's `%post`, each followed by a
`restorecon` of the binary its file context names (`/usr/libexec/virtiofsd`,
`/usr/libexec/workloadctl/workload-vm-clock`), because `semodule` does not
relabel existing files. On a bootc host the policy store is in `/etc`, which
ostree merges three ways, so an image update does not deliver a changed
module to a host that has ever loaded a local one. `diagnose` compares each
loaded module with the shipped source. Loading by hand is the same pair of
steps:

```bash
sudo semodule -i /usr/share/workloadctl/workload-vm.cil
sudo restorecon /usr/libexec/virtiofsd
sudo semodule -i /usr/share/workloadctl/workload-clock.cil
sudo restorecon /usr/libexec/workloadctl/workload-vm-clock
```

On a host with SELinux disabled, meaning `/sys/fs/selinux/enforce` is
absent, the wrapper drops `runcon` and makes an unlabelled socket pair, and
the VM runs unconfined rather than failing to start. Permissive mode still
transitions, so a permissive harvest measures the real domains.
`diagnose` reports which case a host is in.
