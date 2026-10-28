# Boot and generation

This is the maintainers' map of how a workload's TOML becomes running units:
what starts the generator and what it writes, which files a workload owns and
who reads each one, what the setup unit does before anything of the workload
runs, and how the CLI is layered over all of it. The units a VM runs are
described in [the VM runtime](vm-runtime.md), and the egress inspector,
responder and broker in [the egress plane](egress.md). The operator's side of
the same machinery is in the manual, starting at [the TOML is the source of
truth](../manual/01-concepts.md#the-toml-is-the-source-of-truth).

## Two stages at boot

systemd runs `generators/workload-generator`, a shell script, with its other
generators at boot and on every `daemon-reload`. It writes one unit,
`workload-generate.service`, into the generator output directory and links it
into `basic.target.wants`. That unit is a oneshot with
`DefaultDependencies=no`, ordered `After=sysinit.target` and
`Before=basic.target`, whose `ExecStart=` is
`/usr/libexec/workloadctl/workload-generate /run/systemd/system`.

The real work runs in that oneshot because systemd expects a generator to be
fast and minimal (systemd.generator(7)), and current systemd holds generators
to a time budget that Python's import overhead alone can exceed. As a unit
ordered after `sysinit.target` it has a writable `/etc` and no budget, and it
still finishes before `basic.target`, ahead of any workload unit.

The split has a consequence you have to keep in mind: `daemon-reload` re-runs
the shell generator, which rewrites the oneshot's unit, but it does not run the
oneshot again. Editing a TOML and reloading regenerates nothing. The CLI runs
the Python half itself when it needs units rewritten (see [Regenerating from
the CLI](#regenerating-from-the-cli)).

`generators/workload-generate` is `main()` over `gen_run.run`, plus two guards
that must hold before any of the project's modules is imported. It writes its
first log lines to `/dev/kmsg` itself, so an import that fails is still
reported. And it sets `SYSTEMD_NSS_BYPASS_BUS=1`: before `basic.target` there
is no `systemd-userdbd` to answer, and the first `pwd` lookup through
nss-systemd would otherwise block for about 45 seconds and hold up boot with
it. It also turns off bytecode writing, since `/usr` may be read-only. A failed
import, and any exception inside `run`, is logged and the process exits 0.
Nothing in generation may fail boot.

The generator logs through `gen_common.log_msg`, to `/dev/kmsg`, or to stderr
when `WORKLOAD_GENERATE_LOG_STDERR` is set or the kernel log cannot be written.
`doctor` collects those lines from both `journalctl -b -k -g workload-generate`
and `journalctl -b -u workload-generate.service`, keeping the ones that name
the workload or look like errors (`cmd_doctor._generator_lines`).

## One generator run

`gen_run.run` takes an output directory as its one positional argument, and
two flags, `--workload NAME` and `--no-start`. It hands the directory to
`gen_common.set_output_dirs`, with `SYSUSERS_DIR` overriding where the sysusers
file goes, and every writer reads it back through `services_dir()` and
`sysusers_dir()`. They are functions rather than module constants so that no
module can import a copy of the default and write into the live
`/run/systemd/system` during a test.

`generate_all` then takes every bundle `iter_workloads` finds under
`/etc/workloads.d/`, or `WORKLOAD_CONFIG_DIR`:

1. It reads the name of every enabled bundle first (`enabled_workload_names`),
   across the whole directory even when the run is narrowed to one workload,
   so each workload's `requires` and `after` can be checked against the full
   set.
2. For each bundle, `generate_workload` skips it without an `.enabled` marker,
   refuses it when `[workload].name` differs from the directory name (the units
   are named from the TOML, while the CLI and the marker go by the directory),
   and skips it when `validate_workload_config` returns any error. A `requires`
   or `after` naming an unknown workload is only a warning.
3. A container workload has the shares it belongs to resolved into its
   configuration (`shares.resolve`).
4. `resolve_uid` takes the UID from the passwd entry if the user exists. If
   not, it allocates one under `subid_lock` and writes the workload's sysusers
   file before releasing the lock (`gen_common.pin_allocated_uid`). The
   allocator counts the UIDs in pending sysusers files as taken
   (`workload_uid._reserved_uids_in_pending_sysusers` reads
   `/run/systemd/system` and `/run/sysusers.d`), because the user does not
   exist until the setup unit runs `systemd-sysusers`, possibly much later.
   `claim_uid` adopts the workload-range owner of an existing `data/` or
   `state/` under `/var/lib/workloads/<name>/` rather than allocating afresh,
   so a workload whose passwd line vanished in a deployment rollback gets back
   the UID its files and its derived subordinate range belong to. If another
   user now holds that UID, it allocates a new one and warns.
5. The substrate's generator writes the files: `gen_vm.generate_vm_workload`
   or `gen_container.generate_container_workload`.

An exception in one workload is logged and the loop moves on. A container
workload whose main unit cannot be rendered, such as one whose seccomp
profile cannot be derived, keeps the files written before the failure but
gets no main unit and no start.

The generator only writes. At boot `/run` is an empty tmpfs with nothing stale
in it, and between boots removing a disabled workload's files is `disable`'s
job.

### The start enqueue

When the output directory is the live `/run/systemd/system` and `--no-start`
was not given, a run ends with `systemctl daemon-reload` and one `systemctl
start --no-block` naming the main unit of every workload it wrote
(`gen_common.enqueue_starts`). The `multi-user.target.wants` links it wrote do
nothing on this boot: systemd built the transaction for `multi-user.target`
before the oneshot ran, when the workload units did not exist, and it does not
re-read the `.wants` directory of a target already queued. An explicit start
job joins the running queue regardless. `--no-block` keeps the oneshot, and
with it `basic.target`, from waiting for containers to come up.

It is one call because the enqueue is the only part of a run whose cost grows
with the number of workloads, and the run sits ahead of `basic.target`. If
systemctl rejects the batch, which a single unloadable unit can cause, it
retries one unit at a time so the others still start.

Everything else in a workload's start follows from that job on its main unit:
see [What starts a container's units](#what-starts-a-containers-units) below,
and [What starts what](vm-runtime.md#what-starts-what) for a VM.

## The files a workload owns

A workload's **run-files** are its per-workload files under
`/run/systemd/system/` and `/run/workload-env/`. Most are units and some are
not, so the set is defined as files. `run_files.workload_run_files(config)` is
its one definition: it returns a `WorkloadRunFile(path, kind, role, emitted)`
per file, and every caller derives the set from there rather than spelling
names itself. The generator takes its destinations from the same list
(`gen_common.emitted_run_paths`, remapped onto its output directories), so it
cannot name a file differently from the code that later removes it.

| File under `/run/systemd/system/` | Kind | For |
|---|---|---|
| `workload-<name>.conf` | `sysusers` | every workload |
| `workload-<name>-setup.service` | `unit` | every workload |
| `workload-<name>.service` | `unit` | every workload: the container's unit in `single` mode, the umbrella in `pod` and `bridge` mode, the QEMU unit for a VM |
| `multi-user.target.wants/workload-<name>.service` | `wants-symlink` | every workload |
| `user@<uid>.service.d/50-workload.conf` | `dropin` | every container workload |
| `workload-<name>-pod.service` | `unit` | `pod` mode |
| `workload-<name>-net.service` | `unit` | `bridge` mode |
| `workload-<name>-<container>.service` | `unit` | each container in `pod` or `bridge` mode |
| `workload-<name>.seccomp.json` | `seccomp` | a container workload with `seccomp_allow`, `seccomp_netlink` or `seccomp_32bit` |
| `workload-<name>-build.service` | `unit` | every VM |
| `workload-<name>-clock.timer` and `-clock.service` | `unit` | every VM, bridged ones included |
| `workload-<name>-virtiofs-<tag>.service` | `unit` | each VM volume |
| `workload-<name>-inspect.socket` and `-inspect.service` | `unit` | an inspected workload, either substrate |
| `workload-<name>-resolve.socket` and `-resolve.service` | `unit` | a workload with the DNS responder |
| `workload-<name>-broker.service` | `unit` | an inspected workload that declares a credential |

The predicates behind the three egress rows are in [the egress
plane](egress.md#which-workloads-get-what). The sysusers file sits beside the
units despite its suffix, because `sysusers_dir()` defaults to the services
directory. The seccomp profile is the baseline installed when the generator
ran, with the workload's extra syscalls, netlink protocols and 32-bit
architectures allowed; the containers' `--security-opt=seccomp=` names it.

Three more are written at runtime rather than by the generator:

| File under `/run/workload-env/` | Written by |
|---|---|
| `workload-<name>.env` | `workload-ensure-user`, at every setup run |
| `workload-<name>.secrets` | `workload-write-env`, for a `single`-mode container |
| `workload-<name>-<container>.secrets` | `workload-write-env`, for each container in `pod` or `bridge` mode |

### Two views of one list

Callers slice the list along two axes, which is why each entry carries both a
`kind` and an `emitted` flag.

The **emitted view** is the entries with `emitted` true: the files that exist
for this exact configuration. The generator writes from it, and `status`,
`logs`, `doctor`, `edit` and the substrates take their unit names from it,
mostly through `workload_service_units` (the emitted units, optionally by
role).

The **removable view** is every entry whose kind is not `env-file`. It
over-lists on purpose: `-pod` and `-net` for every container workload whatever
its mode, the egress units for every workload of the substrate, the seccomp
profile for every container workload. A workload that switches a feature off
or changes mode between `enable` and `disable` still has the old files removed
and the old helper units stopped. `disable` stops and resets every `unit` entry
other than the main unit, then unlinks every entry of the removable view with
`missing_ok`; stopping an absent unit is harmless.

The **env-tree** entries are `kind == "env-file"`, never emitted, and removed
only by `disable --purge`. A plain `disable` leaves a stopped workload's
`.secrets` files in place until a purge or a reboot. `workload-<name>.secrets`
is listed for every workload, and the per-container ones for every container,
whether or not they declare a secret; removal tolerates the missing ones.

The drop-in's path needs the workload's UID, which is read from the passwd
database. Once the user is gone it is left out of the list rather than
reconstructed, since a query must not allocate a UID; the container substrate's
teardown removes the empty `user@<uid>.service.d` directory itself.

`drift` cannot start from one configuration: it compares generated and live
trees in both directions, across every workload, to find stale files as well
as changed ones. `RUN_TREE_SCANS` is its glob per kind, with `content` saying
whether the kind is compared byte for byte or, for the wants link, by presence,
and `name_filtered` saying whether `drift <name>` can scope it. The drop-in is
keyed by UID, so it is always in scope.
`TestRunTreeScansCoverRunFiles` in `tests/test_workload_run_files.py` holds the
scans to the kinds the list produces.

### What is not a workload's

Some files are easy to count as a workload's and must not be:
`workload-generate.service`, which is global; any reference to another
workload's unit in a `Requires=`, `After=`, `--pod=` or `--network=` line;
`provenance.json` and `operations.log` at the workload root, which are in
`/var` and must survive a plain `disable`; and the inspector's policy document
under `/run/workload-vm/_policy/<name>/`, which `drift` compares separately
([the egress plane](egress.md#who-writes-and-reads-each-file)). Nothing writes
a per-workload tmpfiles file, and `/run/sysusers.d/` is read by the UID
allocator but never written. `tests/test_workload_run_files.py` asserts that no
host-global unit name appears in any workload's set, which would let one
workload's `disable` remove what others depend on.

### Adding a run-file

A new per-workload file is a change in four places: the generator that writes
it; `workload_run_files`, with an `emitted` predicate that is the same one the
generator writes on, listed unconditionally if a configuration can turn it off;
a `RUN_TREE_SCANS` row if it lands under `/run/systemd/system` with a new kind,
or `drift` never looks at it; and the table above. `workload_lib` has
`workload_service_name` and `workload_container_name` for the two plainest
names. Anything derived from a workload's name comes from the list.

## What starts a container's units

| Unit | Shape | Pulled in by | Runs |
|---|---|---|---|
| `workload-<name>-setup.service` | root oneshot, `RemainAfterExit=yes` | every unit that needs the user | `systemd-sysusers`, `workload-ensure-user` |
| `workload-<name>.service`, `single` mode | `Type=exec` as `_wl-<name>` | the boot enqueue, the CLI | the prestarts below, then `podman run` (for a pet, `podman create` once and `podman start`) |
| `workload-<name>-pod.service` or `-net.service` | oneshot, `RemainAfterExit=yes`, as `_wl-<name>` | the umbrella | the stale-pause cleanup, removal of a leftover pod or network, the filter, then `podman pod create` or `podman network create` |
| `workload-<name>-<container>.service` | `Type=exec` as `_wl-<name>` | the umbrella | `workload-write-env` when it has secrets, then `podman run` |
| `workload-<name>.service`, `pod` or `bridge` mode | oneshot, `RemainAfterExit=yes`, `/bin/true` | the boot enqueue, the CLI | nothing |

In `single` mode the container's unit `Requires=` and orders `After=` the setup
unit, along with the egress sidecars it uses. Its prestarts are, in order:
`workload-write-env` when it has secrets, the NVIDIA CDI check for an NVIDIA
GPU, the stale-pause cleanup, and `workload-container-filter up` when it is
filtered.

In `pod` and `bridge` mode the umbrella `Requires=` the setup unit, the head
(the pod or network oneshot) and every member, and orders after all of them,
so it is active only when they are and fails when any member fails. The head
`Requires=` the setup unit and the egress sidecars and is `PartOf=` the
umbrella. Each member `Requires=`, `BindsTo=` and orders after the head, and is
`PartOf=` the umbrella. [The egress plane](egress.md#the-units-and-what-starts-them)
explains why the egress wiring is on the head rather than the umbrella.

`[workload].requires` becomes `Wants=`, and `after` becomes `After=`, on each
container unit: the main unit in `single` mode, each member otherwise. A VM's
units carry neither.

## The setup unit and workload-ensure-user

`gen_common.generate_setup_service` writes the same setup unit for both
substrates:

```ini
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/systemd-sysusers /run/systemd/system/workload-<name>.conf
ExecStart=/usr/libexec/workloadctl/workload-ensure-user <name>
```

`workload-ensure-user` is the second `ExecStart=` of this unit. It is not a
prestart of the workload's own unit, and the separation is the point: those
units run with `User=_wl-<name>`, and systemd resolves `User=` before it runs
any of a unit's commands, prestarts included, so no unit can create the user
it runs as. The setup unit runs as root with no sandbox.

Every unit that needs the user `Requires=` it and orders after it: the
container's unit or the umbrella and head, a VM's main, build and virtiofs
units, and the egress sockets and broker.

### When it runs

`RemainAfterExit=yes` means that once the unit is active it stays active, and
neither starting nor restarting the workload runs it again. So
`workload-ensure-user` runs:

- at boot, when the first unit that requires it starts;
- in `enable`, where `provisioning.provision_user` runs `systemd-sysusers` and
  `workload-ensure-user` directly and waits for them, before anything starts;
- in `recreate`, which restarts the setup unit (`cmd_recreate`), and for a VM
  restarts it again in `VMSubstrate.reprovision`;
- in `edit`'s apply step for a VM, which restarts the setup unit and then the
  VM. For a container the apply step restarts only the workload's unit, so
  setup does not run.

`disable` stops and resets the setup unit with the others, so the next start
after a re-enable runs it from scratch. `start`, `restart` and `update` do not
restart it, so they run it only if it is inactive, which after a boot it never
is.

The program is `ensure_user.ensure_user`. It takes a per-workload `flock` on
`/run/lock/workloadctl/<name>.lock` for the whole run, because two runs can
overlap (an `enable` beside a boot start or a `recreate`) and almost every
step is check-then-create. Whichever run gets the lock second finds the work
done. If the lock cannot be taken it runs unlocked rather than refusing.

### Its steps

`provision` runs the steps below in order. Every step is idempotent. A step
marked fatal ends the run with exit 1 and fails the unit, which keeps the
workload down; the others log a warning and carry on.

For both substrates:

1. Look up `_wl-<name>`. Missing is fatal: `systemd-sysusers` has just run, so
   it failed.
2. Warn if the passwd home is not the workload's `state/` directory. The units
   set `HOME` themselves, but podman's healthcheck timer inherits the user
   manager's home.
3. Load the TOML (fatal).
4. Create `state/` and `data/`, owned by the user, mode 0700.
5. Write the provenance marker, best-effort (see [Deployment
   provenance](#deployment-provenance)).
6. Join the user to its groups (fatal). `systemd-sysusers` reports success for
   an `m` line naming a group that exists only in `/usr/lib/group`, as `video`,
   `render` and `input` do on Fedora bootc, without adding the member. So
   `join_image_groups` copies such a group's line into `/etc/group` under
   `/etc/.pwd.lock` and runs `systemd-sysusers --inline` again for the missing
   memberships.

For a container, then, all fatal but the last:

7. The subordinate ranges (`ensure_container.configure_subuid_subgid`): the
   derived main range in `/etc/subuid` and `/etc/subgid`, and a one-GID
   `/etc/subgid` entry for each `extra_groups` group unless `userns` is
   `"host"`. An existing main entry is never corrected, since shifting a
   mapping under a running container corrupts its namespace. If anything was
   added it runs `podman system migrate` as the user.
8. The transient podman store (`podman_storage.ensure_transient_store`; see
   [How a secret reaches a container](#how-a-secret-reaches-a-container)).
9. `modprobe` of each `[security] kernel_modules` entry, since no workload
   domain may make the kernel load a module.
10. For an inspected container: the runtime and policy directories, the egress
    CA, its bundle and the PKI directories ([the egress
    plane](egress.md#who-writes-and-reads-each-file)).
11. The volume directories inside the workload's tree, and the parents of a
    mount point nested inside another volume. Paths outside the tree are the
    operator's to create.
12. Ownership of the `[setup] required_files` inside the tree, which the
    operator usually copies in as root.
13. The environment file.
14. The workload's SELinux level, stamped on its tree and its egress PKI
    (`ensure_common.stamp_selinux_labels`).
15. Linger: `loginctl enable-linger`, then a wait until
    `user@<uid>.service` is active (`service_runtime.ensure_runtime_dir`).
16. The manager's slice (`ensure_manager_slice`; see [Cgroup
    placement](#cgroup-placement)). A failure here is only a warning.

A VM's steps after the first six are listed in [the VM
runtime](vm-runtime.md#boot-from-host-to-guest). A VM's run can also exit 2,
`SEED_CONTRACT_EXIT`, when the operator's cloud-init seed breaks its contract;
`provision_user` turns that into a `UsageError` whose message the helper has
already printed.

### The environment file

The generator runs before the user exists, so nothing UID-dependent that
systemd must expand can go into a unit. `write_environment_file` puts it in
`/run/workload-env/workload-<name>.env`: `XDG_RUNTIME_DIR=/run/user/<uid>` and
`HOST_IP`, the source address of the host's default route, or empty. Every
container unit and head unit, and a VM's main unit, reads it with
`EnvironmentFile=-/run/workload-env/workload-<name>.env`, and the containers
receive `--env HOST_IP=${HOST_IP}`. An explicit `HOST_IP` in the TOML's
environment takes precedence.

`/run/workload-env` is created 0755 by `systemd/workloads-dirs.conf`, not
0700, because the workload user's podman has to traverse it to read its own
`--env-file`. The secrets files carry their own confidentiality.

## How a secret reaches a container

The operator's view is in [Secrets](../manual/07-secrets.md#giving-a-secret-to-a-container).
This is the path a value takes.

**At generation.** `secrets_template.auto_detect_credentials` scans one
container's environment and `[secrets] files` for references, ignoring escaped
ones, and `gen_container._credential_loads` writes one
`LoadCredentialEncrypted=<name>:/etc/credstore.encrypted/<name>` line per
credential on that container's own unit. Plain environment values go on the
`podman run` line as `--env`; any value containing `${SECRET:...}` is left off
it. If any value references a secret, the container gets `--env-file
/run/workload-env/<container>.secrets`, where `<container>` is
`workload-<name>` in `single` mode and `workload-<name>-<container>`
otherwise. Each `[secrets] files` entry becomes `--volume
/run/user/<uid>/workload-secrets/<container>/<credential>:<path>:<mode>,Z`. If
the container has either, its unit runs
`ExecStartPre=+/usr/libexec/workloadctl/workload-write-env <name>`, with the
container's name as a second argument in `pod` and `bridge` mode.

**At each start.** systemd decrypts the unit's credentials into
`/run/credentials/<unit>/` and sets `CREDENTIALS_DIRECTORY` for every command
of the unit. The `+` prestart runs `secrets_env.write_secrets_env` as root:

- If the container's environment references a secret, it resolves the values
  from `CREDENTIALS_DIRECTORY`, refuses one containing a newline, and writes
  `KEY=value` lines to the `.secrets` file, opened 0600 before anything is
  written and then given to the workload user. If it no longer references one,
  it deletes any `.secrets` file left from when it did, since nothing else
  would remove the plaintext before a purge or a reboot.
- For `[secrets] files`, it recreates
  `/run/user/<uid>/workload-secrets/<container>/` root-owned and 0700, copies
  each credential in at mode 0444 (0644 for `mode = "rw"`), and only then hands
  the directory to the workload user. Every component is opened without
  following links, because the runtime directory belongs to the workload user,
  who could plant one.

Then `podman run`, as the workload user, reads the `--env-file` and mounts the
copies. The copies exist because systemd's decrypted file is labelled
`init_var_run_t`, which no container domain may read; `:Z` relabels the copy to
the container's own category pair. Credentials are per container because
`LoadCredentialEncrypted=` attaches to the unit that lists it, so in a pod each
member's unit loads only what that member references, and two members starting
together never write the same file.

An escaped-only environment (`$${SECRET:name}`) demands no credential, so its
unit has no `LoadCredentialEncrypted=` and no `CREDENTIALS_DIRECTORY`;
`write-env` still writes the literal value and does not require the directory.

**podman's own copy.** podman records a container's whole environment,
resolved secrets included, in its database and in the container's
`config.json`. `ensure_transient_store` writes
`state/.config/containers/storage.conf` with `transient_store = true`, so both
live under the runroot, `/run/user/<uid>/containers`, in memory. A user's
`storage.conf` replaces everything a rootless podman would take from the
system's, so the file also carries over the parts that apply to a rootless
user: the driver if it runs rootless (otherwise the driver priority), the pull
options, and overlay's `ignore_chown_errors`. The step then removes the
persistent database under the graphroot once `podman --transient-store=false
ps -aq` shows no container recorded in it.

**After a stop.** systemd removes `/run/credentials/<unit>/` when the unit
stops. The `.secrets` file and the copies under `/run/user/<uid>/` stay until
the next start rewrites them, a `disable --purge` removes them, or the host
reboots.

## Cgroup placement

Rootless podman asks the workload user's systemd manager for a transient
`libpod-<id>.scope`, so every container's processes sit under
`user@<uid>.service`, outside the system unit that started them. [ADR
001](../adr/001-container-cgroup-placement.md) chose to keep that placement
(option 1b) and move the manager instead. For each container workload the
generator writes this drop-in (`gen_common.generate_user_dropin`):

```ini
# Workload web: redirect user@10004 into workloads.slice (ADR 001 option 1b)
# Generated by workload-generate (<version>)

[Service]
Slice=workloads.slice
MemoryMax=4G
```

`Slice=` is `[resources] slice`, `workloads.slice` by default, and the
directives after it come from the top-level `[resources]` through
`gen_common.cgroup_directives` (`CGROUP_SCALAR_KEYS` and `CGROUP_LIST_KEYS`).
Moving the manager moves the whole subtree, so a workload-level cap binds every
container together and every workload shares the slice's aggregate limits.
Per-container limits are podman flags on each `podman run`. A VM has no
drop-in: QEMU runs in its own system unit, and the same `cgroup_directives`
are written there.

The drop-in alone does not move the manager. Linger starts
`user@<uid>.service` through logind, which places it under `user-<uid>.slice`
and ignores `Slice=`, and does so again at every boot. Only a restart by PID 1
honours the drop-in. `ensure_manager_slice`, the last step of setup, reads the
manager's `ControlGroup` and restarts `user@<uid>.service` when it is not under
`/<slice>/user@<uid>.service`. Restarting the manager kills everything under
it, which is why this happens in setup, before any container exists. A test of
placement must read `/proc/<pid>/cgroup`, as the ADR explains. Resource
properties apply again on `daemon-reload`, but slice membership does not, so a
changed `slice` takes effect at the next setup run.

Three things in a container's units follow from the payload living outside
them. systemd's `KillMode=` cannot reach the container, so a cattle
container's unit outside `pod` mode carries `ExecStopPost=-/usr/bin/podman rm
-f -t0 <container>` for a container whose podman client was killed. (In `pod`
mode the head's `ExecStop=` removes the pod; a pet is never removed.) The
default `Type=exec` stays, because a readiness message comes from a process in
the manager's cgroup and systemd credits it to the manager, not to the
workload's unit. And `systemctl status workload-<name>` shows only the podman
client.

### The stale pause

The head unit runs two tolerant prestarts before its first podman command:

```ini
ExecStartPre=-/usr/bin/podman system migrate
ExecStartPre=-/usr/bin/rm -f /run/user/<uid>/libpod/tmp/pause.pid /run/user/<uid>/libpod/tmp/ns_handles
```

The head is the container's own unit in `single` mode and the pod or network
oneshot in `pod` and `bridge` mode (`gen_container_heads._head_unit`). Member
units never run them: killing the pause there would pull it out from under the
pod and the containers already running.

The problem they solve comes from the placement. Rootless podman keeps a pause
process holding its namespaces, and podman moves it into a
`podman-pause-*.scope` under the user manager, where it outlives the unit. It
still holds the mount namespace of the activation that started it, whose
`PrivateTmp=` `/tmp` systemd has since deleted. The next `podman run` takes the
rootless shortcut of joining the existing pause's namespaces, whatever the
`userns` mode, and pasta, which mounts a tmpfs over `/tmp` in its sandbox,
fails with `ENOENT`, so the unit restart-loops. `podman system migrate` stops
the old pause, but returns before doing so if stopping any container fails, so
the `rm` follows it: without `pause.pid` and `ns_handles` the shortcut is not
taken, and podman starts a fresh pause in the live mount namespace. A workload
on the host network starts no pasta and is unaffected, but the cleanup runs
for every head regardless.

## The build stamp

Every unit file the generator writes, and the drop-in, carries
`run_files.GENERATED_BY` in its header:

```
# Generated by workload-generate (<version>-<release>)
```

The version is `workload_lib.WORKLOADCTL_VERSION`, which the RPM's `%install`
writes into `_version.py` and which `--version` also reports; a source
checkout reports `0-dev`. The sysusers file, the seccomp profile and the wants
link carry no stamp.

Units live in `/run` and are rewritten only at boot or when a command
regenerates them, so two kinds of staleness can arise between boots, and
`run_files` has a check for each. `units_outdated` catches an edited TOML: it
is true when the TOML's mtime is more than a second newer than the main
unit's. `units_from_other_build` catches an upgraded package, which moves
neither mtime: it reads the stamp back from the main unit through
`GENERATED_BY_RE` and returns the version when it differs from the running
build. A stamp with no version reads as `UNSTAMPED_BUILD`; a missing unit, or
one with no stamp at all, gives `None`. `status` prints a warning for each and
reports them as `config_stale` and `units_generated_by` in its JSON;
`diagnose`, and `doctor` through it, has the checks `config_current` and
`units_current`. The remedy for both is `recreate`, or a reboot: `enable` on a
running workload rewrites the files but starts nothing. On a bootc host
the build skew cannot arise, since new code only runs after a reboot, which
regenerates everything.

`drift` normalises the stamp away. `cmd_drift.collect_drift` rewrites
`GENERATED_BY_RE` matches on both sides to the unversioned form before
comparing, along with the scratch directory's path. `drift` answers whether
the running units match what the TOML produces now, and a package upgrade
would otherwise mark every workload as drifted, including those whose units
are byte-identical apart from the stamp. The build question has its own check.

## Regenerating from the CLI

`provisioning.regenerate_units` runs

```
/usr/libexec/workloadctl/workload-generate /run/systemd/system --workload <name> --no-start
```

and then `systemctl daemon-reload`. `enable` (through `generate_units`), the
apply step of `edit`, and `recreate` call it.

`--workload` matters because an unfiltered run rewrites the units of every
enabled workload. Acting on one would silently replace a bystander's unit
files while its service ran on the old ones, and since `drift` compares
against the files in `/run`, that bystander's drift would disappear from view.
An unfiltered live run would also enqueue a start for every workload,
including one the operator had stopped. The filter applies after the name
pre-scan, so a narrowed run still checks `requires` and `after` against every
enabled workload.

`--no-start` matters because each verb starts or restarts the workload itself,
after the steps that must come first. In `enable` the order is generate,
provision the user, transfer the image into the user's store, start. A start
enqueued by the generator would cold-start the containers before the
transfer, pinning a fresh cattle container to the stale image in the user's
store.

`enable` runs `generate_units` with `WORKLOAD_GENERATE_LOG_STDERR=1`, so the
generator's reason for skipping a workload reaches the operator instead of the
kernel log. Because the generator exits 0 whatever happens, `enable` then
checks that the workload's sysusers file exists. If it does not, usually
because the UID range is exhausted, it removes the `.enabled` marker and fails
with `LifecycleError(1)`.

The whole of `cmd_enable`, in order: create the `.enabled` marker (the
generator only emits enabled workloads) and reload; run the preflight checks;
run the `[host]` setup hook; load the workload's SELinux module; register a
VM's file context; generate; `provision_user`; apply share memberships;
transfer images for a container; and `start_service`, which clears any
start-limit state left on the unit name and starts the main unit with
`--no-block`. A failure before anything starts removes the marker again, so a
workload that did not come up is left disabled.

`drift` runs the same generator unfiltered into a temporary directory, with
`WORKLOAD_CONFIG_DIR` set and `SYSUSERS_DIR` pointing at that directory. The
start enqueue never fires there, because the output is not the live directory.
For each `RUN_TREE_SCANS` row it compares the generated files against the live
ones and the live ones against the generated, so a file the generator would no
longer write is reported too, and it exits 1 when anything differs.

## The CLI's layers

`bin/workloadctl` is `main()` over `cli_main.run`. `cli_main.main` builds the
parser (`cli_parser.build_parser`), configures the prose channel once from the
parsed arguments, creates a `WorkloadManager`, and calls the handler the
subcommand registered as `func`, as `handler(args, manager)`.

Handlers are the `cmd_<verb>` functions in `lib/cmd_*.py`. Most modules hold
one verb; a few hold a family: `cmd_lifecycle` (start, stop, restart,
recreate, reboot, build), `cmd_inspect` (list, status), `cmd_interact` (logs,
exec, shell, cp, incant), `cmd_catalog` (catalog, init, duplicate, install),
`cmd_update` (update, rollback) and `cmd_backup` (backup, restore). Code that
several verbs share is not a `cmd_` module: `provisioning` (preflight, user
provisioning, image transfer, unit generation), `host_setup`,
`workload_selinux`, and the diagnose battery behind `diagnose` and `doctor`.

### The exit code

Only `bin/workloadctl` and `lib/cmd_*.py` may end the process. Every other
module in `lib/` raises a typed exception, and `cli_main.run` maps it to the
exit status:

| Raised | Exit status |
|---|---|
| `UsageError` | 2 |
| `LifecycleError` | the return code of the systemctl or podman call that failed |
| `ImageTransferError`, `ProvisionFailed`, `NotRoot`, `WorkloadMasked`, `WorkloadUserNotFound`, `FileNotFoundError` | 1 |
| `KeyboardInterrupt` | 130 |
| `SystemExit` from a handler | its code; a message is printed and becomes 1 |
| anything else | 1, with the traceback and a line calling it a workloadctl bug |

A handler may also return a nonzero integer, which becomes the status;
`egress` and `pcap` report failure that way. Most raisers print their own
diagnostic first, so the ladder adds a message only for the types whose
raisers do not.

The rule exists because `SystemExit` derives from `BaseException` and passes
straight through `except Exception:`. At a leaf that is what you want; in a
helper it ends the process past a caller that meant to recover.
`ProvisionFailed`, `BackupError` and `NotApplicable` are also caught where a
loop has to continue, so `update --all` and `backup --all` count failures
per workload instead of dying on the first. `tests/test_layering.py` parses
every non-`cmd_` module in `lib/` and fails if it calls `sys.exit`,
`os._exit`, `exit` or `quit`, so the rule is checked, and it covers a new
module the moment it exists.

### Prose and output

`lib/cli_log.py` separates two kinds of text. **Prose** is what a command says
about what it is doing: progress, status, warnings. It goes through
`cli_log.info` to stdout, and `warn` and `error` to stderr, so severity
survives a redirect. **Output** is what the command was asked for: reports,
plans, JSON documents, and the passthrough of `logs`, `incant` and `stats`. It
is a plain `print()`.

That split is what makes `--quiet` safe: it raises the logger's threshold to
warnings, which silences the narration and never the answer or a failure. The
handlers look up `sys.stdout` and `sys.stderr` for each record, so a caller
that redirects them later, as the tests do, still captures the text.

`--json` means two things. The mutating verbs (`enable`, `disable`, `start`,
`stop`, `restart`, `reboot`, `recreate`, `build`, `update`, `rollback`) get
`-q`/`--quiet` and `--json` from one shared parent parser that also sets
`emits_result`. Their `--json` turns on `json_mode`, which reserves stdout for
the result object that `cli_log.emit_result` prints:

```
{"command": ..., "ok": ..., "workloads": [{"workload": ..., "result": ...}, ...]}
```

with verb-specific keys such as a dry-run `plan` beside them. When such a
command fails before it reports, the exit ladder calls `emit_failure`, which
prints a document with `ok` false and an `error`, unless a result was already
emitted. A read verb's `--json` means that it prints its own report as JSON;
`cli_main.main` then sets only `quiet`, because `json_mode` would let a failure
document land beside the report on the same stream. The read verbs take no
`--quiet`, since they have no narration to silence. `pcap` has its own `-q`
and `--json`.

### The operations log

`cli_log.emit_result` also hands its rows to `oplog.record`, whether or not
`--json` was given, so the log and the JSON result are the same dict and a
verb that learns to report something new records it with no second call. The
administrative verbs that have no result document of their own (`create`,
`init`, `duplicate`, `install`, `edit`, `backup`, `restore`, `cp`) call
`emit_result` for the log alone. `secret`, whose credential store belongs to
no workload, and `cleanup`, whose subjects have no configuration left, do not
record.

`oplog.record` appends one JSON line per row to
`/var/lib/workloads/<name>/operations.log`: the row, plus `ts` (UTC),
`command`, `ok`, `user` and `user_source`. The user comes from the audit login
UID in `/proc/self/loginuid` (`login`), which survives `sudo` and `su -` and
cannot be changed from userspace; then from `SUDO_USER` (`sudo`); then from the
real UID (`system`). An unset login UID marks automation, so a timer's
`update --all` reads as `system`.

Each row's `result` is classified against two sets:

- `RECORDED_RESULTS`, the outcomes that changed something, are written;
- `IGNORED_RESULTS` (`dry-run`, `listed`, `unchanged`, `skipped`, `purged`)
  are not;
- anything else is written and warned about once, naming both sets.

It is an allowlist because `update --all` on a fleet that did not move reports
`unchanged` for every workload, and nothing rotates the file. A new verb, or a
new result string, has to be added to one of the sets.

The file sits at the workload root, beside `state/` and `data/` and in
neither: `backup` captures only `data/`, so a restore on another host does not
import this host's history, and the root is not owned by the workload user, so
the workload cannot rewrite its own record. `disable --purge` deletes the root
and the log with it. The configuration verbs run before `enable` has made the
root, so `record` creates it for a workload that has a TOML, and for a name
with no TOML warns and records nothing. Writes are `O_APPEND`, mode 0644, and
best-effort: a failure warns once per process and never fails the command. It
is a record of outcomes, not an audit trail, since root can edit it.

### Dry runs

`--dry-run` exists where a truthful plan can be computed: `disable`
(`cmd_disable._disable_plan`), `update` (`cmd_update._update_plan`) and `pcap`.
`cleanup` is a dry run unless given `--apply`. The plan functions are
read-only and run before any mutation. `_disable_plan` enumerates from the same
sources the real teardown acts on (`workload_run_files`, the passwd database,
the subid files, the data directory, and the substrate's `teardown_plan`) and
lists only what is present, so whatever it leaves out, `disable` will not
touch. `_update_plan` names the images it would pull and the image each would
roll back to, without predicting whether a pull brings anything new. Both are
separate code rather than the real path with its writes switched off, because
such a plan is only as trustworthy as the last guard someone remembered to
add. `pcap` builds one plan object that both the dry run and the
capture use. The other mutating verbs have no `--dry-run`: their plan would
restate the verb. Previewing a configuration edit is `drift`.

### Substrate dispatch

The substrate is chosen from the declaration, never from runtime state:
`substrate.get_substrate(config, manager)` returns a `VMSubstrate` when the
TOML has a `[vm]` section and a `ContainerSubstrate` otherwise. Each lives in
its own module (`substrate_vm`, `substrate_container`) and imports the port for
its base class and exceptions, so the router imports them inside its body to
avoid a cycle. A verb whose behaviour varies by substrate is written once
against the port; verbs that do not vary, such as `create`, `list`, `validate`
and `secret`, bypass it.

The required primitives are abstract methods, so a substrate cannot exist
without them: `liveness`, `gating_units`, `capture`, `exec`, `open_shell`,
`lifecycle`, `rollback_targets`, `rollback_to`, `rollback`, `control` and
`uses_inspect`. The optional ones have a default in the base class:

| Primitive | Default | Container | VM |
|---|---|---|---|
| `resource_usage` | `NotApplicable` | podman's figures | from `qmp-metrics.sock` |
| `endpoints` | `NotApplicable` | published ports | default |
| `addresses` | `NotApplicable` | default | the guest's addresses |
| `logs` | runs the given `journalctl` argv | default | default |
| `reprovision` | `NotImplementedError` | pull and restart | rebuild the disk and restart |
| `teardown`, `teardown_plan` | `[]` | the drop-in directory; on purge, the subid ranges and the runtime directory | on purge, the runtime directory and the workload's nftables elements |

The capability matrix is therefore what each class defines, not a list kept
somewhere. Two questions travel on two channels. "This substrate cannot answer"
is `NotApplicable`, carrying a reason, which the caller prints before exiting
0 (`stats`) or counting the workload as skipped (`update`). "It can, and there
is nothing right now" is the type's empty value in band: `endpoints` returns
`[]` with no ports published, `addresses` returns `[]` before the guest has a
lease, `reprovision` returns `None` when nothing changed. A new primitive
should prefer an empty container to a `None` sentinel, so the nothing case has
the shape of the something case. The teardown pair defaults to `[]` rather
than `NotApplicable` because having no state of its own to remove is a
coherent answer.

`resource_usage(json_out=True)` returns rows keyed by `STAT_ROW_KEYS`, one
schema for both substrates. A key a substrate has no source for is `None`,
not 0: a VM has no block I/O figure, and a zero would read as an idle disk.

`gating_units` names the units that must succeed before the main unit can
start. A VM returns its setup and build units; a container returns none.
`cmd_lifecycle.effective_state` walks them when the main unit is not active,
so `list` reports `failed` and names the failed unit rather than a bare
`inactive`, and `status` shows them beside the main unit.

## Deployment provenance

On an ostree or bootc host, `/etc` belongs to each deployment and `/var` is
shared. A workload's identity (its TOML, its passwd line, its subid ranges) is
in `/etc` and its state is in `/var`, so a `bootc rollback` takes a workload's
identity away and leaves its state behind, where `cleanup` would take it for an
orphan. [ADR 005](../adr/005-var-state-deployment-provenance.md) records the
decision; this is the mechanism.

`workload-ensure-user` writes `/var/lib/workloads/<name>/provenance.json` on
every run, after creating the home directories
(`ensure_common.record_deployment_provenance`, calling
`deployment.write_marker`):

```json
{
  "name": "web",
  "deployment": "<64 hex digits>.<serial>"
}
```

The file is root's, mode 0644, replaced atomically, and rewritten only when
its content changes, so a boot that provisions nothing new does not touch
`/var`. It sits in the workload root, which the workload user does not own, so
a workload cannot rewrite the record that decides whether its state may be
swept. The marker means the deployment that last provisioned the state, not
the one that created it: a workload carried forward to a new deployment and
then deleted there must name the new one, or `cleanup` would spare it while
the old deployment survived as the rollback target.

`deployment.booted_deployment_id` resolves the `ostree=` argument on
`/proc/cmdline`, which is a symlink, and takes the target's base name when it
matches `<64 hex>.<serial>`. The argument's own checksum is the boot checksum,
not the deployment's, so only the resolved link identifies the deployment. Off
ostree the field is `null`.

`cleanup` asks `deployment.other_deployments_state` before calling any
workload root an orphan. It returns the deployment to spare the state for only
when `/ostree/deploy` is readable, the marker parses and names this workload,
and its deployment is not the booted one but still exists under some
stateroot (`deployment_exists` globs `/ostree/deploy/*/deploy/<id>`, since
`/var` may be shared across stateroots). Every uncertainty (no ostree, no
marker, a corrupt one, one for another workload, an unresolvable command line)
returns `None`, leaving `cleanup` with its ordinary rule, so the marker can
only ever withhold a deletion. Spared state is listed under "State from another
deployment — not swept". `status --json` reports the marker's deployment as
`state_deployment`.

The marker deliberately holds no UID or subid range: the owner of `data/` is
the UID, one `stat` away, and the range is derived from it. Allocation uses
that directly (`claim_uid`, in [One generator run](#one-generator-run)). Nor is
the marker a run-file: it is in `/var`, a plain `disable` must leave it, and
there is nothing for `drift` to compare it with.
