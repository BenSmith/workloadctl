# 1. Concepts

workloadctl runs long-lived services on a single Linux host. You describe a
service in a TOML file, and workloadctl provisions everything it needs: an
unprivileged system user, systemd units, storage, secrets, networking, and
the commands to update it, roll it back, back it up and take it away again.
This chapter covers the handful of ideas the rest of the manual builds on.

## Workloads

A **workload** is a directory under `/etc/workloads.d/` holding a
`workload.toml`:

```
/etc/workloads.d/webserver/
├── workload.toml
└── .enabled          # present once the workload is enabled
```

The directory can carry whatever else the workload needs beside the TOML: a
`Containerfile` for an image built on the host, a `setup.sh` run at enable
time, a `policy.cil` granting SELinux rights, a `cloud-init/` seed for a VM.
These are the workload's **control files**.

The `.enabled` marker is what makes a workload start at boot. `workloadctl
enable` creates it and `disable` removes it; a workload without one is
configured but inert.

## Two substrates

A workload runs on one of two **substrates**, chosen by what its TOML
declares:

- A **container** workload has a `[container]` section, or several
  `[[containers]]`. It runs under rootless podman. Several containers can
  share a network namespace and talk over localhost (`mode = "pod"`) or each
  have their own and find each other by name (`mode = "bridge"`).
- A **VM** workload has a `[vm]` section instead. It runs as a QEMU/KVM
  virtual machine with UEFI firmware, a system disk built from a cloud image,
  an optional data disk, and a cloud-init seed.

Both substrates share one configuration model and one command surface.
`status`, `logs`, `update`, `rollback`, `backup` and the rest mean the same
thing whichever one a workload runs on, and a command that cannot apply to a
substrate says so rather than doing something approximate.

## One workload, one user

Every workload runs as a system user of its own, `_wl-<name>`, with a UID
from 10000 up, no login shell, no password, and a private range of
subordinate UIDs and GIDs. A container workload's containers run under that
user's own rootless podman; a VM workload's QEMU process is owned by it. No
workload's processes run as root on the host, and no two workloads share an
identity.

That user is more than hygiene. Because the host assigns it, nothing inside
the workload can forge it, and so it is the handle everything else holds:
storage is owned by it, outbound network policy matches on it, and the
credential broker identifies its caller by it. When the manual says a
control is enforced "by the host", this is usually how.

## Bundles and instances

workloadctl ships a catalogue of ready-made workloads, called **bundles**,
under `/usr/share/workloadctl/workloads/`. `workloadctl catalog` lists them,
and `workloadctl init <bundle>` stamps one into `/etc/workloads.d/` as an
**instance** you can edit and enable.

`init` copies only the TOML. The bundle's control files stay in `/usr` and
are read from there, so an instance picks up bundle fixes when the package
is upgraded. To change one control file for one instance, `workloadctl edit
<name> <file>` makes a copy-on-write override of it, much as `systemctl
edit` does for a unit. One bundle can back several instances
(`init <bundle> --as <name>`), each with its own TOML, user and data.

`/etc/workloadctl/bundles/` is a second bundle layer, one directory per
bundle, that the admin writes. A directory there named after a shipped bundle
overrides it file by file, for every instance of that bundle: its copy of a
file wins over the shipped one, and the files it doesn't carry still come
from the package. A directory with a name nothing ships, holding a
`workload.toml`, is a bundle of your own, and `catalog`, `init`, `edit` and
`info --files` treat it like a shipped one. On an image-based host this is
how to change or add a bundle without rebuilding the image, since `/etc`
keeps local additions across updates.

A file in the local layer stops following the package: when an update changes
the shipped bundle, your copy stays as it is, so a changed `Containerfile`
can end up paired with your older `setup.sh`. `catalog` shows such a bundle as
`shipped+local`, and `info --files` names the file that wins. A
`workload.toml` there changes what `init` copies; instances already made keep
their own TOML.

You don't need a bundle: `workloadctl create` writes a TOML from command-line
flags, and any directory holding a `workload.toml` can be installed with
`workloadctl install`.

## The TOML is the source of truth

workloadctl never asks you to write a systemd unit. At every boot it reads
each enabled workload's TOML and generates the units into
`/run/systemd/system/`, so they always describe the configuration on disk.
A broken workload never blocks boot: generation reports the problem and
carries on.

Between boots, the commands regenerate what they need. Two distinctions
matter in practice:

- `restart` restarts what is running and does **not** apply edits to the
  TOML. `recreate` applies them: it regenerates the units and replaces the
  container, or re-renders a VM's cloud-init seed and restarts the VM on
  it.
- `workloadctl drift <name>` tells you whether the running units still
  match what the TOML would produce now.

Run `workloadctl validate <name>` after editing a TOML. It checks the file
against the schema and catches the mistakes the schema can see before a
start fails.

## State and data

Each workload's files on the host live under `/var/lib/workloads/<name>/`,
split by whether they can be rebuilt:

- `state/` is the workload user's home. It holds the podman image store and
  container layers, or a VM's system disk, firmware variables and SSH key.
  Everything here can be rebuilt from the TOML and the image, so `backup`
  skips it.
- `data/` is what cannot be rebuilt: volumes declared as `./name` in the
  TOML, and a VM's data disk. `backup` captures it.

A workload's **lifecycle** says which side its own filesystem is on. A
`cattle` workload (the default) is disposable: a container's writable layer
is thrown away on every stop, and a VM's system disk is rebuilt on `update`.
Anything it must keep goes in a volume or on the data disk. A `pet` workload
keeps its container layer or its VM system disk across restarts and
updates. Either way, `backup` captures only `data/`, so what must survive
the loss of the host belongs there.

## Network stances

A container uses pasta networking by default: it gets its own network stack,
and the ports listed in its TOML are published on the host's address. It can
also share the host's network (`mode = "host"`) or have none.

A VM never gets a bridge of its own unless you provide one. Its traffic
leaves the host as ordinary connections owned by its workload user, which is
what lets the host police it. A VM is in one of three stances:

- **filtered** (the default): everything it sends is dropped except what its
  policy names, and web traffic is inspected by host name;
- **open**: not policed, but still isolated from the host and from other
  workloads;
- **bridged**: given a real address on a LAN bridge you provision, which
  takes it outside the host's policing altogether.

A container uses the same filtering mechanism when its `[network]` section
names the hosts it may reach.

## When to use something else

Podman Quadlets generate a systemd unit from a container spec, and if that is
what you want they are simpler. workloadctl starts a layer earlier and
finishes a layer later: it owns the user, the subordinate ID ranges, the
storage, the secrets and the update path, and it treats a VM as the same kind
of object as a container.

workloadctl manages one host. It has no scheduler, no cluster, no failover
and no fleet-wide policy; each host is configured on its own.

Configs under `/etc/workloads.d/` are trusted as root is. A TOML can run a
setup script as root, mount any host path and request capabilities, so never
enable one from a source you would not give root to. The workload's own
software is what workloadctl confines, not the person writing its TOML.
