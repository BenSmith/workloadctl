# workloadctl command reference

Every command and flag, with its defaults, exit status and `--json` output.
The [manual](manual/README.md) explains when and why to use each one, and
each section below links to the chapter that does.

Commands that change a workload, or reach inside one, need `sudo`. The
read-only reports run as any user, though some see more as root: the egress
policy and record, for instance, are readable only by root and the workload
user.

## Commands

| Command | Description |
|---|---|
| [`backup`](#backup) | Archive a workload's `data/`, TOML and referenced secrets to a `.tar.zst` |
| [`build`](#build) | Build a container workload's image from its bundle build context |
| [`catalog`](#catalog) | List the bundles the package ships |
| [`cleanup`](#cleanup) | Find, and with `--apply` remove, users, directories and SELinux modules no TOML declares |
| [`cp`](#cp) | Copy files into or out of a running container |
| [`create`](#create) | Write a container workload's TOML from flags |
| [`diagnose`](#diagnose) | Run the host-setup checks for one workload, with a fix for each failure |
| [`disable`](#disable) | Stop a workload and stop it starting at boot; `--purge` removes its user and data |
| [`doctor`](#doctor) | One report: generator log, unit states, setup checks, drift, health, egress counters |
| [`drift`](#drift) | Diff the running units and loaded egress policies against what the TOML gives now |
| [`duplicate`](#duplicate-alias-clone) / `clone` | Copy a workload's TOML under a new name |
| [`edit`](#edit) | Edit the TOML, or override one of the bundle's control files |
| [`egress`](#egress) | Read a filtered workload's per-request egress record |
| [`enable`](#enable) | Provision a workload and start it, now and at every boot |
| [`exec`](#exec) | Run a command inside a container, or in a VM over SSH |
| [`health`](#health) | Liveness verdict for a workload; exits 0 or 1 |
| [`images`](#images) | List workload images, or prune unreferenced ones |
| [`incant`](#incant) | Run a raw podman command as the workload user, or a QMP command on a VM |
| [`info`](#info) | Show a workload's configuration, user, network, storage and service; `--files` for its control files |
| [`init`](#init) | Stamp a bundle, or a blank stub, into `/etc/workloads.d/` |
| [`install`](#install) | Copy a local workload directory into `/etc/workloads.d/` |
| [`list`](#list) | List every workload with its enabled and running state |
| [`logs`](#logs) | Show a workload's journal |
| [`pcap`](#pcap) | Capture a workload's packets from the host or guest vantage |
| [`reboot`](#reboot) | Soft-reboot the systemd inside a container or VM |
| [`recreate`](#recreate) | Regenerate a workload's units and restart it on them, applying TOML edits |
| [`restart`](#restart) | Restart a workload on its existing units, without applying TOML edits |
| [`restore`](#restore) | Restore a workload from a `backup` archive |
| [`rollback`](#rollback) | Go back to the previous container image or VM disk generation |
| [`rules`](#rules) | Report a filtered workload's effective egress rules |
| [`secret`](#secrets) | Manage sealed credentials: `create`, `list`, `show`, `rotate`, `delete`, `export`, `import` |
| [`shell`](#shell) | Open a shell in a container, or in a VM over SSH or its serial console |
| [`start`](#start) | Start a workload without changing whether it starts at boot |
| [`stats`](#stats) | Show CPU, memory and I/O usage |
| [`status`](#status) | Show a workload's systemd status, or every workload's |
| [`stop`](#stop) | Stop a workload without changing whether it starts at boot |
| [`update`](#update) | Pull new images, or rebuild a VM's system disk, and restart; containers roll back on failure |
| [`validate`](#validate) | Check a TOML against the schema and the host |

---

## Global options

```
workloadctl [-h] [--version] <command> [options]
```

`--version` prints the version and exits. `workloadctl <command> -h` prints
one command's options.

Exit status is 0 on success and 1 on failure. A command line the parser
rejects, such as an unknown flag or a missing argument, prints the usage and
exits 2. Exit statuses particular to one command are given under it.

## Naming a container

A multi-container workload ([Several containers in one
workload](manual/04-containers.md#several-containers-in-one-workload)) has
one name per container. These commands act on one container when you name
it as `<workload>/<container>`:

```bash
workloadctl logs blog            # every container, merged in time order
workloadctl logs blog/db         # one container
sudo workloadctl exec blog/db psql -U app
sudo workloadctl shell blog/web
sudo workloadctl cp blog/web:/etc/nginx/nginx.conf ./nginx.conf
sudo workloadctl health blog     # one row per container
```

`exec`, `shell` and `cp` need the container named when a workload has more
than one; a bare workload name is refused with the list of containers.
`logs` and `health` cover every container unless you name one. `pcap` needs
one only for a guest capture in `bridge` mode. Every other command acts on
the whole workload.

## Quiet and JSON output

`build`, `disable`, `enable`, `reboot`, `recreate`, `restart`, `rollback`,
`start`, `stop` and `update` print progress as they go, and take two flags
that change that:

| Flag | Effect |
|---|---|
| `-q`, `--quiet` | Drop the progress lines. Warnings and errors still print, on stderr. |
| `--json` | Print one JSON result object on stdout instead of the progress lines. |

Progress goes to stdout and warnings and errors to stderr, so
`workloadctl update --all >run.log 2>errors.log` keeps them apart. What a
command was asked to produce, such as a `--dry-run` plan or `rollback
--list`'s targets, is not progress: `--quiet` still prints it, and `--json`
puts it in the result object.

The report commands (`list`, `status`, `drift` and the rest) have a `--json`
of their own, which prints that report as JSON; its shape is given under
each command.

### The result object

Every one of those ten commands reports in the same shape:

```console
$ sudo workloadctl update --all --json
{
  "command": "update",
  "ok": true,
  "workloads": [
    {
      "workload": "web",
      "kind": "container",
      "result": "updated",
      "images": {
        "web": {
          "image": "docker.io/library/nginx:alpine",
          "old": "sha256:1f2e3d4c5b6a",
          "new": "sha256:9a8b7c6d5e4f"
        }
      },
      "verify": "healthy"
    },
    {
      "workload": "cache",
      "kind": "container",
      "result": "rolled-back",
      "verify": "crashed"
    },
    {
      "workload": "builder",
      "kind": "container",
      "result": "skipped",
      "reason": "builder uses pull=never (local image) — build it manually"
    }
  ],
  "summary": {
    "updated": 1, "rolled-back": 1, "skipped": 1, "failed": 0, "unchanged": 0
  }
}
```

- `ok` is the overall verdict and matches the exit status. A rollback is a
  handled outcome, not a failure: an update that rolled back leaves `ok:
  true` and exits 0. A failed pull, or a VM rebuild that did not come back,
  gives `ok: false` and exit 1.
- `result` is one of `enabled`, `already-running`, `disabled`, `purged`,
  `started`, `stopped`, `restarted`, `rebooted`, `recreated`, `built`,
  `updated`, `unchanged`, `skipped`, `failed`, `rolled-back`, `listed` or
  `dry-run`.
- Other keys on a row, where the command has them: `service`, the unit
  acted on; `reason`, why a row is `skipped` or `failed`; `errors`, the
  teardown steps `disable` could not complete; `verify`, the health verdict
  after an update's restart; `images`, each container's old and new image
  ID; `plan`, the steps of a `--dry-run`; `purge`, on a `disable --dry-run`;
  `targets`, on `rollback --list`.
- `summary` counts the rows by result, on `update --all` only.
- A command that fails before it can report, because it is not run as root,
  the workload does not exist or something unexpected went wrong, still
  prints the object, with `ok: false`, an empty `workloads` and an `error`
  string. The diagnostic itself is on stderr.

## The operations log

Every command that changes a workload appends one JSON line to
`/var/lib/workloads/<name>/operations.log`, with or without `--json`: the
command's result row for that workload, plus the time in UTC, the command,
whether it succeeded, and who ran it. The ten commands above write there,
and so do `create`, `init`, `duplicate`, `install`, `edit`, `backup`,
`restore` and a `cp` into a workload. A command that changed nothing writes
nothing. [The operations log](manual/09-operating.md#the-operations-log)
describes the fields and what the log is and is not.

---

## Creating workloads

### `catalog`

List the bundles under `/usr/share/workloadctl/workloads/`, each with its
substrate.

```
workloadctl catalog [--json]
```

`--json` prints a list of `{"bundle", "kind"}`, where `kind` is `container`
or `vm`.

[↑ top](#workloadctl-command-reference)

### `init`

Stamp a new workload into `/etc/workloads.d/<name>/workload.toml`.

```
sudo workloadctl init <bundle> [--as <name>]
sudo workloadctl init --scratch <name>
sudo workloadctl init --scratch-vm <name>
```

| Argument | Description |
|---|---|
| `<bundle>` | The bundle to copy (see `catalog`) |
| `--as NAME` | The instance's name (default: the bundle's name) |
| `--scratch NAME` | Write a container stub with no bundle behind it |
| `--scratch-vm NAME` | Write a VM stub with no bundle behind it |

Give exactly one of `<bundle>`, `--scratch` and `--scratch-vm`.

From a bundle, `init` copies only the TOML. The bundle's control files (its
`Containerfile`, `setup.sh`, `policy.cil` and the rest) stay under
`/usr/share/workloadctl/workloads/<bundle>/` and are read from there, so the
instance follows package upgrades; `edit <name> <file>` overrides one of
them. When the instance's name differs from the bundle's, `init` sets
`[workload] bundle` so the control files still resolve.

`--scratch` writes a `[container]` stub with `image = "CHANGE_ME"` for you
to fill in. `--scratch-vm` writes a VM stub that boots Fedora 44 Cloud Base
with `egress = "open"`, and a starter `cloud-init/user-data` beside it.
Neither has a bundle, so every control file comes from
`/etc/workloads.d/<name>/`.

Every form validates the new TOML, prints the result and the next steps,
and leaves the workload disabled. See [A shipped
bundle](manual/03-first-workloads.md#a-shipped-bundle).

[↑ top](#workloadctl-command-reference)

### `duplicate` (alias `clone`)

Copy a workload's TOML under a new name.

```
sudo workloadctl duplicate <source> <new>
```

The copy's `[workload] bundle` is the source's own bundle, so a copy of a
copy still reads the original bundle's control files. The copy is
validated and left disabled. `duplicate` warns, without refusing, about
settings two workloads cannot both hold or may not mean to share: published
host ports, absolute volume paths, an image another workload also runs, and
secrets the copy now reads too. Edit the copy before enabling it.

[↑ top](#workloadctl-command-reference)

### `install`

Copy a local workload directory into `/etc/workloads.d/<name>/`.

```
sudo workloadctl install <src>
```

| Argument | Description |
|---|---|
| `<src>` | A directory holding a `workload.toml` |

The name comes from `[workload] name` in the TOML, not from the directory.
The whole directory is copied with its file modes, except `.git`,
`__pycache__` and an `.enabled` marker, so the installed workload starts
disabled. `install` refuses a name that already exists and leaves the
source alone.

[↑ top](#workloadctl-command-reference)

### `create`

Write a container workload's TOML from flags.

```
sudo workloadctl create <name> --image IMAGE [options]
```

| Argument | Description |
|---|---|
| `<name>` | Workload name: starts with a letter; lowercase letters, digits and hyphens; at most 27 characters |
| `--image IMAGE` | Container image (required) |
| `--gpu SPEC` | `amd`, `nvidia`, `intel`, `auto`, `none`, or `nvidia:<index or UUID>` to pin one NVIDIA GPU |
| `--groups GROUP` | A supplementary group, such as `video`. Repeat per group |
| `--ports PORT` | A port mapping, such as `8080:80`. Repeat per port. Ignored with `--network host` or `none` |
| `--network MODE` | `pasta` (default), `host`, `none`, or the name of a podman network |
| `--volumes VOL` | A volume, such as `/srv/media:/media:ro`. Repeat per volume |
| `--device DEVICE` | A device to pass through, such as `/dev/ttyUSB0`. Repeat per device |
| `--input` | Pass through `/dev/input` and `/dev/uinput` |
| `--audio` | Pass through `/dev/snd` and mount the PulseAudio or PipeWire socket |
| `--systemd {always,true,false}` | Run the container with systemd as its init |
| `--shm-size SIZE` | Size of `/dev/shm`, such as `256m` (default: `64m`) |
| `--cpu-quota PERCENT` | CPU quota, such as `50%`, or `200%` for two cores |
| `--cpu-weight WEIGHT` | CPU weight, 1 to 10000 (default: 100) |
| `--memory-max SIZE` | Hard memory limit, such as `512M` |
| `--memory-high SIZE` | Memory level at which the workload is throttled |
| `--memory-swap-max SIZE` | Swap limit; `0` disables swap |
| `--io-weight WEIGHT` | I/O weight, 1 to 10000 (default: 100) |
| `--tasks-max NUM` | Maximum number of tasks |
| `--enable` | Enable and start the workload once the TOML is written |

```bash
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --memory-max 256M \
  --enable
```

`create` validates what it wrote. If validation fails it exits 1 without
enabling anything; fix the TOML with `edit`. Each flag sets the TOML key of
the same meaning, described in [Container
workloads](manual/04-containers.md#from-the-command-line) and the [schema
reference](schema-reference.toml).

[↑ top](#workloadctl-command-reference)

### `edit`

Edit a workload's TOML, or override one of its bundle's control files.

```
sudo workloadctl edit [-y] <workload>
sudo workloadctl edit <workload> <file>
```

| Option | Description |
|---|---|
| `<file>` | A control file to override, such as `Containerfile` or `rootfs/etc/app.conf` |
| `-y`, `--yes` | Apply the edited TOML without asking |

**The TOML.** `edit` opens the TOML in `$EDITOR` (`nano` if unset). If you
change nothing, it stops there. Otherwise it validates the file. On a
failure it asks whether to put the previous file back, keeping your edit
unless you answer `y`, and exits 1. On success it shows the change as a
diff and, for an enabled workload, asks whether to apply it; `-y` answers
yes. Applying regenerates the units and restarts the workload (for a VM,
its setup unit too, which renders a new seed). It does not run a
container's setup step; for a pet container, or a change that adds an
egress filter, a credential or a share, answer `n` and run `recreate`
([Applying a change](manual/09-operating.md#applying-a-change)).

**A control file.** `edit <workload> <file>` copies the shipped file from
the bundle to `/etc/workloads.d/<name>/<file>` (an empty file if the bundle
has none) and opens it. The override is kept only if you change it: one
left identical to the shipped file, or a new file left empty, is
discarded, so the file goes on following the package. A kept override
wins for `build`, `enable` and `recreate`. Paths may be nested; absolute
paths, `..` and symbolic links out of the directory are refused.
`info --files` lists what can be overridden, and deleting the override
returns to the shipped file. See [Changing a bundle's
files](manual/04-containers.md#changing-a-bundles-files).

[↑ top](#workloadctl-command-reference)

---

## Running workloads

### `enable`

Provision a workload and start it, now and at every boot.

```
sudo workloadctl enable [-q] [--json] <workload>
```

`enable` creates the workload's `.enabled` marker, runs the pre-flight
checks, runs its `[host] setup` script and loads its SELinux module if it
has them, generates its units, creates its user and directories, copies an image
built on the host into the workload's store, and starts it. If a step fails
before the start, it removes the marker again, so the workload is left
disabled.

`enable` is safe to run again. On a workload that is already running it
brings the units up to date without restarting it (result
`already-running`); `recreate` applies them. See [Enabling and
disabling](manual/09-operating.md#enabling-and-disabling).

[↑ top](#workloadctl-command-reference)

### `disable`

Stop a workload and stop it starting at boot.

```
sudo workloadctl disable [--purge] [--dry-run] [-q] [--json] <workload>
```

| Option | Description |
|---|---|
| `--purge` | Also delete the workload's user, ID ranges and everything under `/var/lib/workloads/<name>/` |
| `--dry-run` | Print what would be removed, and change nothing |

`disable` stops the workload's units, removes its generated unit files,
runs its `[host] setup` script with the argument `disable`, removes its
SELinux module, a VM's file-context rule and its share membership, removes
the `.enabled` marker and stops the workload user's systemd manager. The user,
its data and the TOML stay, for a later `enable`.

`--purge` also kills the workload user's processes and deletes its runtime
and decrypted-secret files, the user and its subordinate ID ranges,
`/var/lib/workloads/<name>/` (data, state and the operations log), its
egress CA and egress record, and for a VM its runtime directory and its
entries in the host's firewall sets. The TOML in `/etc/workloads.d/<name>/`
is never touched.

`--dry-run` lists exactly what is present to remove, with the size of the
data directory; what it does not list, `disable` does not touch. Teardown
carries on past a failed step; the failures are listed at the end, the
result row carries them as `errors`, and the exit status is 1.

[↑ top](#workloadctl-command-reference)

### `start`

Start a workload without changing whether it starts at boot.

```
sudo workloadctl start [-q] [--json] <workload>
```

[↑ top](#workloadctl-command-reference)

### `stop`

Stop a workload without changing whether it starts at boot.

```
sudo workloadctl stop [-q] [--json] <workload>
```

An enabled workload that is stopped starts again at the next boot.

[↑ top](#workloadctl-command-reference)

### `restart`

Restart a workload on the units it has.

```
sudo workloadctl restart [-q] [--json] <workload>
```

`restart` restarts the workload's main unit and nothing else. It does not
regenerate the units, so it does not apply TOML edits; use
[`recreate`](#recreate). What survives depends on the workload: a `cattle`
container is created afresh from its image and loses its writable layer,
as at every stop; a `pet` container keeps its writable layer; a VM is
power-cycled onto the same disks and the same cloud-init seed. See
[Starting, stopping and
restarting](manual/09-operating.md#starting-stopping-and-restarting).

[↑ top](#workloadctl-command-reference)

### `recreate`

Regenerate a workload's units and restart it on them.

```
sudo workloadctl recreate [-q] [--json] <workload>
```

`recreate` is how an edited TOML reaches a running workload. It regenerates
the units, clears any failed state, updates the workload's SELinux file
contexts and share membership, reruns its setup step, copies an image
built on the host into its store, and restarts it:

- a `cattle` container is created afresh from its image;
- a `pet` container's writable layer is first committed to
  `localhost/workload-snapshot/<name>:<timestamp>` (the newest
  `snapshot_keep`, default 3, are kept), then the container is replaced;
- a VM's setup unit renders a new cloud-init seed from the TOML and the VM
  is power-cycled onto it; its disks are kept.

`recreate` does not validate the TOML first: when the generator rejects
it, the old units stay and the workload restarts on them. Run `validate`
before it. `systemctl daemon-reload` is not a substitute, because it does
not regenerate a workload's units. See [Applying a
change](manual/09-operating.md#applying-a-change).

[↑ top](#workloadctl-command-reference)

### `reboot`

Soft-reboot the systemd inside a workload.

```
sudo workloadctl reboot [-q] [--json] <workload>
```

`reboot` runs `systemctl soft-reboot` inside the workload: every service
inside restarts, and the container or the VM's disk is kept. For a
container that works only when it runs systemd as its init (`[container]
systemd`). For a VM it goes over SSH and needs passwordless `sudo` in the
guest. Either way the workload needs systemd 254 or later inside.

[↑ top](#workloadctl-command-reference)

---

## Images and updates

### `build`

Build a container workload's image from its bundle build context.

```
sudo workloadctl build [-q] [--json] <workload>
```

`build` runs as root and builds into root's image store, from the merged
build context: the bundle's directory with any overrides from
`/etc/workloads.d/<name>/` laid over it, so an edited `Containerfile` or
`COPY`ed file takes effect. With `[build] script` set, it runs that script
against the same context instead. The image is tagged with the name the
TOML gives it; `enable`, `recreate` and `update` copy it into the
workload's own store.

A workload that only pulls published images has nothing to build, and
`build` says so. In a multi-container workload, each container built on
the host needs a `[containers.build]` block of its own. `build` refuses a
VM. After a build, `recreate` an enabled workload to run the new image.
See [Building your own
image](manual/04-containers.md#building-your-own-image).

[↑ top](#workloadctl-command-reference)

### `update`

Pull new images, or rebuild a VM's system disk, and restart.

```
sudo workloadctl update [--force] [--dry-run] [-q] [--json] <workload>
sudo workloadctl update --all [--force] [--dry-run] [-q] [--json]
```

| Option | Description |
|---|---|
| `--all` | Update every enabled workload, containers and VMs |
| `--force` | Restart a container workload even when no image changed |
| `--dry-run` | Print what would be pulled and restarted, and change nothing |

**Containers.** `update` pulls each container's image. If none changed,
it stops there (result `unchanged`). Otherwise it tags each previous image
as `localhost/workload-rollback/<name>:latest` (with `-<container>` after
the name in a multi-container workload), snapshots a `pet` container's
writable layer, and restarts the workload. It then waits for the longest
`start_period` plus `interval` among the health checks, at least 5
seconds, and checks every container's health, or that its service is
still running when it has no health check. A workload that fails is
rolled back to its previous images, when it had them, and restarted (result
`rolled-back`).
With `--all`, every workload is pulled and restarted first, then all are
checked after one shared wait. A workload whose images are all
`pull = "never"` is skipped by `--all`, and refused when named alone.

**VMs.** A `cattle` VM's system disk is rebuilt from its image source, the
old one kept as `system.qcow2.gen-N`, and the VM is restarted on the new
one. A `pet` VM is only restarted. Nothing checks the guest afterwards and
nothing rolls back on its own; check it, and use `rollback` if the new
disk is bad. `--force` makes no difference to a VM. A downloaded
`cloud_image_url` is cached under `/var/lib/workloads/<name>/.image-cache/`
against its checksum, so to move to a newer image, change both
`cloud_image_url` and `cloud_image_checksum`.

`--dry-run` names, per workload, the images it would pull with the image
each would roll back to, those it would skip, and what it would restart.
It does not contact the registry, so it cannot say whether a pull would
find anything new. With `--json`, each row is `dry-run` with a `plan`.

See [Updating container
images](manual/09-operating.md#updating-container-images) and, for VMs,
[Update and rollback](manual/05-vms.md#update-and-rollback).

[↑ top](#workloadctl-command-reference)

### `rollback`

Go back to the previous container image or VM disk generation.

```
sudo workloadctl rollback [--list] [-q] [--json] <workload>
```

| Option | Description |
|---|---|
| `--list` | List the rollback targets instead of rolling back |

**Containers.** `rollback` gives each container's saved rollback image the
name the TOML uses and restarts the workload. It does not check health
afterwards, and it exits 1 if `update` never saved a rollback image. Only
one earlier image is kept per container. A `pet` container restarts from
the container it already has, so run `recreate` afterwards to rebuild it
from the old image.

**VMs.** `rollback` stops the VM, swaps the newest `system.qcow2.gen-N`
in as `system.qcow2`, and starts it again. The disk it replaces becomes a
new generation, so a second `rollback` returns to it. `[vm] rollback_keep`
(default 2) older generations are kept beside the newest. A `pet` VM has
no generations.

With `--list --json`, the row is `listed` and carries `targets`. See
[Rolling back](manual/09-operating.md#rolling-back).

[↑ top](#workloadctl-command-reference)

---

## Inspecting workloads

### `list`

List every workload in `/etc/workloads.d/`, enabled or not.

```
workloadctl list [--json]
```

Each row has the workload's name, whether it is enabled, its state, image
ID, published ports and image. A VM whose setup or build unit failed shows
as `failed`, with a warning naming the unit. `--json` prints
`{"workloads": [...]}`, each entry with `name`, `kind`, `enabled`, `state`,
`mode`, `containers`, `image`, `image_id`, `ports`, `username` and `uid`.

[↑ top](#workloadctl-command-reference)

### `status`

Show a workload's systemd status.

```
workloadctl status [--json] [<workload>]
```

With a workload, `status` runs `systemctl status` on its main unit, on a
VM's setup and build units as well, and on every unit of a multi-container
workload. It first warns when the TOML is newer than the units, when the units came from
another workloadctl build, and when the workload runs in the host's user
namespace. Without a workload it is `list`.

`--json` prints `workload`, `service`, `state`, `enabled`, `active_since`,
`main_pid`, `memory_current`, `tasks_current`, `result`, `config_stale`,
`units_generated_by`, `host_userns` and `state_deployment`, and for a
multi-container workload `mode` and `containers`.

[↑ top](#workloadctl-command-reference)

### `info`

Show a workload's configuration and what it has on the host.

```
workloadctl info [--json] <workload>
workloadctl info --files [--json] <workload>
```

| Option | Description |
|---|---|
| `--files` | List the bundle's control files and which copy of each wins |
| `--json` | Print the same as a JSON object |

For a container workload, `info` shows its containers and images, its
user (UID, home, groups, subordinate ID ranges), its network mode, ports
and the addresses they answer on, the size of its home, and its service
state. For a VM it shows memory, vCPUs, image source, disks, rollback
generations, the guest's addresses as `qemu-guest-agent` reports them, and
QEMU's run state.

`--files` merges the control files shipped in the bundle with the
overrides in `/etc/workloads.d/<name>/` and tags each with where it comes
from: `override` (your copy), `shipped` (the bundle's), `absolute` (a
`[host] setup` given as an absolute path), `missing` (named but absent) or
`invalid`. Nested paths are included. Edit any of them with `edit
<workload> <file>`.

[↑ top](#workloadctl-command-reference)

### `logs`

Show a workload's journal.

```
workloadctl logs [-f] [-n N] [--since TIME] <workload>[/<container>] [journalctl args...]
```

| Option | Description |
|---|---|
| `-f`, `--follow` | Follow new entries |
| `-n N`, `--lines N` | Show the last N lines |
| `--since TIME` | Start at TIME, in `journalctl`'s format, such as `"1 hour ago"` |

Without `-f`, `-n`, `--since` or any `journalctl` argument, `logs` shows
the last 50 lines. Everything after the workload is passed to `journalctl`
unchanged, so `workloadctl logs web -b -p err` works, and `-f`, `-n` and
`--since` mean the same there. For a container workload `logs` selects
the unit's own lines, the containers' output and the entries a systemd
inside the container forwards; `podman logs` does not work. For a VM it
shows the VM unit's journal, which holds QEMU's messages, not the guest's.
See [Logs](manual/09-operating.md#logs).

[↑ top](#workloadctl-command-reference)

### `stats`

Show CPU, memory and I/O usage.

```
sudo workloadctl stats [--json] [-f] [<workload>]
```

| Option | Description |
|---|---|
| `-f`, `--follow` | Keep updating. Not with `--json`, and not for a VM |
| `--json` | Print `{"stats": [...]}` with raw numbers |

Without a workload, `stats` covers every enabled workload that is running,
and `-f` follows only the first. A container's figures are podman's. A
VM's come from QEMU's read-only monitor: CPU from the vCPU threads' time
over half a second, memory from the balloon against `[vm] memory`. A VM
has no network or block I/O figures, and `--json` gives them as `null`,
not 0. See [Resource usage](manual/09-operating.md#resource-usage).

[↑ top](#workloadctl-command-reference)

### `health`

Give a workload's liveness verdict, exiting 0 when healthy and 1 when not.

```
workloadctl health [--json] <workload>[/<container>]
```

For a single-container workload, `health` checks that the service is
active, the user exists, the container is running and passes its health
check, and each published port accepts a connection. For a multi-container
workload it checks each container's service and that it is running, and
`/<container>` narrows it to one. For a VM it checks that the service is
active and the user exists. `--json` prints `workload`, `overall` and
either `checks` or `containers`. See [Checking
health](manual/04-containers.md#checking-health).

[↑ top](#workloadctl-command-reference)

### `images`

List the images workloads run, or prune unreferenced ones.

```
sudo workloadctl images [--json] [list]
sudo workloadctl images prune
```

`list`, the default, shows each container workload's image per container,
with its size and when it was pulled; VMs have no images. `--json`, for
`list` only, prints `{"images": [...], "total": N}`, each entry with
`workload`, `container`, `image`, `size_bytes` and `created`.

`prune` removes every image no tag refers to from every workload user's
store. Rollback images and pet snapshots are tagged, so it keeps them.

[↑ top](#workloadctl-command-reference)

---

## Getting inside a workload

### `shell`

Open an interactive shell inside a workload.

```
sudo workloadctl shell [--console] <workload>[/<container>]
```

| Option | Description |
|---|---|
| `--console` | VM only: skip SSH and attach to the serial console |

**Containers.** `shell` runs `/bin/bash` in the container, or `/bin/sh` if
the image has no bash. If `[container.environment]` sets `CONTAINER_USER`
or `CONTAINER_UID`, the shell runs as that user; otherwise it runs as the
container's own user.

**VMs.** `shell` logs in over SSH, as [`exec`](#exec) does, so the guest's
terminal follows your window size and signals. If SSH cannot connect, it
falls back to the serial console. `--console` goes straight there, which
works at any point in boot and with the guest's network down. Press
`Ctrl+]` to detach.

[↑ top](#workloadctl-command-reference)

### `exec`

Run a command inside a workload and return its exit status.

```
sudo workloadctl exec <workload>[/<container>] [--] <command> [args...]
```

The `--` is optional. The arguments reach the process exactly as you wrote
them, with no second round of word splitting, so shell syntax needs an
explicit shell:

```bash
sudo workloadctl exec webserver nginx -t
sudo workloadctl exec myapp/db psql -U app
sudo workloadctl exec devbox -- sh -c 'dnf list --installed | wc -l'
```

**Containers.** The command runs in the container through the workload
user's podman.

**VMs.** The command runs over SSH as `[vm] user` (default `workload`),
with the workload's own key from `/var/lib/workloads/<name>/state/.ssh/`.
A VM on passt, the default, has no address of its own, so SSH goes to the
workload's management address: `127.128.0.0` plus the workload user's
offset from UID 10000, port 2222, reachable only from the host itself. A
VM on an
operator-provided `[vm.network] bridge` is reached at its LAN address on
port 22, which the host learns from three sources, most trusted first:

1. **qemu-guest-agent**, over the virtio-serial channel every VM has. Only
   the interface with the MAC address workloadctl gave the VM counts; the
   guest's container bridges and VPN tunnels are not addresses the host can
   reach. Install and enable `qemu-guest-agent` in the guest to use it.
2. **The host's neighbour table**, matched on that MAC address. It lists
   only a guest the host has talked to recently, so an idle VM can drop out
   of it.
3. **mDNS**, as `<name>.local`, when the host runs avahi and nss-mdns.

If none answers, `shell <name> --console` still reaches the guest. See
[Getting into the guest](manual/05-vms.md#getting-into-the-guest).

[↑ top](#workloadctl-command-reference)

### `cp`

Copy files into or out of a running container.

```
sudo workloadctl cp <workload>[/<container>]:<path> <host-path>
sudo workloadctl cp <host-path> <workload>[/<container>]:<path>
```

Exactly one side names the workload. The host side of the copy runs as
root, so a root-only source can be copied in, and a copy out lands where
you asked, owned by root. As with `docker cp`, copying out to an existing
directory puts the result inside it under its own name; otherwise the
destination path names it, replacing what is there. `cp` works on
containers only; for a VM, use `exec` or a shared directory.

```bash
sudo workloadctl cp webserver:/etc/nginx/nginx.conf ./nginx.conf
sudo workloadctl cp ./nginx.conf webserver:/etc/nginx/nginx.conf
```

[↑ top](#workloadctl-command-reference)

### `incant`

Run a raw command against a workload's runtime: its podman, or its QEMU
monitor.

```
sudo workloadctl incant <workload> [--] <command> [args...]
```

`incant` works around the TOML rather than through it: what it changes is
not recorded in the TOML or the operations log, and the next `recreate` or
reboot restores what the units describe. Prefer the purpose-built commands
where one fits, and use `exec` and `shell` for anything inside the
workload.

**Containers.** `incant` runs `podman <command>` as `_wl-<name>`, with the
runtime directory, home and session bus set.

**VMs.** The first word is a QMP command and each `key=value` after it
becomes an argument, passed as a string. `incant` prints QEMU's JSON reply
and exits 1 if it is an error.

```bash
sudo workloadctl incant webproxy -- network create mynet
sudo workloadctl incant webproxy -- volume ls
sudo workloadctl incant devbox -- query-status
sudo workloadctl incant devbox -- system_powerdown
```

**By hand.** The container form is `sudo -n -u _wl-<name>` with three
variables set: `XDG_RUNTIME_DIR=/run/user/<uid>`,
`HOME=/var/lib/workloads/<name>/state`, where the workload's image store
lives (pointed anywhere else, podman reads an empty store and reports
nothing), and `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus`,
without which `podman exec` later fails on `cgroup.procs: Permission
denied`. The VM form must answer QMP's greeting before any command, on a
socket in a `0750` directory owned by the workload user:

```bash
sudo sh -c 'printf "%s\n%s\n" \
    "{\"execute\":\"qmp_capabilities\"}" \
    "{\"execute\":\"query-status\"}" \
  | socat -t2 - UNIX-CONNECT:/run/workload-vm/devbox/qmp.sock'
```

See [Working in a workload's
podman](manual/09-operating.md#working-in-a-workloads-podman).

[↑ top](#workloadctl-command-reference)

---

## Checking and repairing

### `validate`

Check a workload's TOML against the schema and against the host.

```
workloadctl validate [--json] <workload>
workloadctl validate --all [--json]
```

| Option | Description |
|---|---|
| `--all` | Validate every workload in `/etc/workloads.d/` |
| `--json` | Print the results as JSON |

`validate` exits 1 if any workload fails. Some checks, such as whether the
secrets a TOML references exist, see more as root. `--json` prints
`workload`, `passed`, `errors`, `warnings` and `checks` (each `check`,
`passed`, `severity`, `message`); with `--all`, `{"validation_results":
[...], "all_passed": ...}`.

[↑ top](#workloadctl-command-reference)

### `drift`

Diff what is running against what the TOML gives now.

```
workloadctl drift [--json] [<workload>]
```

| Argument | Description |
|---|---|
| `<workload>` | Compare only this workload (default: every workload) |
| `--json` | Print the differences as JSON |

`drift` generates every workload's units into a scratch directory and
compares them with those in `/run/systemd/system/`. It also compares each
filtered workload's egress policy, as its inspector loaded it at start,
with the policy its TOML renders now, and for each that differs prints the
`systemctl restart workload-<name>-inspect.socket` that reloads it. It
prints a unified diff per difference and exits 1, or prints `No drift
detected` and exits 0. It changes nothing. Run it as root: the loaded
policies are readable only by root and the workload user, and a non-root
run skips them.

`--json` prints `{"drifted": ..., "units": [...], "documents": [...]}`,
where each unit is `{"unit", "drifted", "diff"}` and each policy is
`{"document", "drifted", "diff"}`. See [Drift](manual/09-operating.md#drift).

[↑ top](#workloadctl-command-reference)

### `diagnose`

Check a workload's setup on this host, with a fix for each failure.

```
sudo workloadctl diagnose [--json] <workload>
```

`diagnose` checks the workload's user, home and subordinate ID ranges, its
user manager and runtime directory, SELinux modules and labels, images,
units, volumes, shares and, for a filtered workload, that the filter is in
force. It prints `✓` or `✗` per check, with a `Fix:` line under each
failure and a numbered list of failures at the end, and exits 1 if any
check failed, with or without `--json`. A VM gets a narrower set: it has no
subordinate IDs or user manager, and has checks of its own for its runtime
directory, cloud-init and clock.

`--json` prints `{"workload", "passed", "checks_passed", "checks_total",
"checks"}`, each check with `check`, `passed`, `message` and, when it
failed, `fix`. [diagnose: what is wrong with this host's
setup](manual/10-troubleshooting.md#diagnose-what-is-wrong-with-this-hosts-setup)
lists every check and links to its remedy; [Is it in force:
diagnose](manual/06-networking.md#is-it-in-force-diagnose) covers the
egress checks.

[↑ top](#workloadctl-command-reference)

### `doctor`

Gather everything about one workload into one report.

```
sudo workloadctl doctor [--json] <workload>
```

`doctor` reports the generator's lines about the workload from this boot,
every unit's state with the last 15 journal lines of any that failed, is
stuck starting or has restarted, the `diagnose` failures, drift, health
and, for a filtered workload, the inspector's counters. The counters are
evidence and never count as a problem. It changes nothing. It exits 0 when
it finds no problem and 1 when it finds one, including a TOML that cannot
be loaded, which it explains in one line. A masked workload is reported as
such, with exit 0. `--json` prints the whole report as one object. See
[doctor: everything at
once](manual/10-troubleshooting.md#doctor-everything-at-once).

[↑ top](#workloadctl-command-reference)

### `cleanup`

Find state that no TOML in `/etc/workloads.d/` declares, and remove it.

```
sudo workloadctl cleanup [--apply] [--json]
```

| Option | Description |
|---|---|
| `--apply` | Remove what was found (default: only list it) |
| `--json` | Print the findings and removals as JSON |

An orphan is a `_wl-*` user, a directory under `/var/lib/workloads/`, or a
loaded `wl_*` SELinux module that no TOML declares. A workload that is only
disabled still has its TOML and is never touched, and the backups
directory is never an orphan. `--apply` removes each orphaned user with its
ID ranges, the user's whole directory under `/var/lib/workloads/` and its
egress CA, and each orphaned module. `cleanup` is for state that outlived
its TOML; to remove a workload you still have a TOML for, use `disable
--purge`, which also removes the egress record, the runtime files and a
VM's firewall set entries.

On a bootc host, state stamped with another deployment that still exists is
listed under "State from another deployment — not swept" and never
removed: after a `bootc rollback` it belongs to the deployment you left.
Boot that deployment and run `disable --purge` there to remove it. See
[State from another bootc
deployment](manual/09-operating.md#state-from-another-bootc-deployment) and
[ADR 005](adr/005-var-state-deployment-provenance.md).

`--json` prints `dry_run`, `orphan_users`, `orphan_dirs`,
`orphan_modules`, `skipped_other_deployment` (each `name`, `path`,
`deployment`), `removed_users`, `removed_dirs` and `removed_modules`.

[↑ top](#workloadctl-command-reference)

---

## Network traffic

`rules` says what a filtered workload may reach and `egress` what it
reached. Both work for a filtered VM and a filtered container alike, and
both need root or the workload's user. [Reading a
filter](manual/06-networking.md#reading-a-filter) explains them.

### `rules`

Report a filtered workload's effective egress rules.

```
sudo workloadctl rules [--json] <workload> [HOST]
```

| Argument | Description |
|---|---|
| `HOST` | A host name to ask about. Omit it to go through every literal name in the policy |
| `--json` | Print the report as JSON |

`rules` calls the inspector's own matcher, so its answer is what the filter
does, which reading the TOML is not: host patterns combine, and a host any
`policy` entry matches is governed by those entries alone. Asked about a
host, it answers even for a name the policy never mentions. Asked with no
host, it reports every literal name and how many wildcard patterns it did
not expand.

It reads the policy the inspector was given at its last start,
`/run/workload-vm/_policy/<name>/inspect.json`, or for a workload not
started this boot renders one from the TOML, and says which. Whether the
running inspector holds that policy is `diagnose`'s question. `--json`
prints `workload`, `origin` (`disk` or `config`), `path`,
`unreadable_policy_elements`, and either `query` or `literals` and
`wildcards`. `rules` exits 1 for a workload with no inspected egress or a
policy it cannot read.

[↑ top](#workloadctl-command-reference)

### `egress`

Read a filtered workload's per-request egress record.

```
sudo workloadctl egress [-n N] [-g] [--json] [--id ID] [--decision {forward,drop}]
                        [--mode {forward,terminate,splice}] [--plane {cleartext,tls}]
                        [--reason REASON] [--host PATTERN] [--method METHOD]
                        [--status STATUS] [--since TIME] [--until TIME] <workload>
```

| Option | Description |
|---|---|
| `-n N`, `--lines N` | Show the last N matching records; `0` for all (default: 50) |
| `-g`, `--group` | Group records by connection, showing each request's query, drop reason and upstream |
| `--json` | Print the records as JSON |
| `--id ID` | A connection id, as it appears in the journal |
| `--decision` | `forward` or `drop` |
| `--mode` | `forward`, `terminate` or `splice` |
| `--plane` | `cleartext` or `tls` |
| `--reason REASON` | A drop reason, or an unambiguous part of one |
| `--host PATTERN` | A host, as an fnmatch pattern |
| `--method METHOD` | An HTTP method |
| `--status STATUS` | A response status, such as `403`, or a class, such as `4xx` |
| `--since TIME`, `--until TIME` | A time window: `2h`, `30m ago`, or an ISO date and time such as `2026-10-28T09:00`, local unless it carries an offset |

Every filter except the time window can be repeated. The record has one
line per request, allowed or refused: time, connection id, decision, mode,
host, method and path, status and duration. It lives in
`/var/log/workloadctl/egress/<name>/`, is not in the journal and cannot be
read by the workload. Bodies are never recorded.

The record belongs to the workload, not to one container. Every container
in a `pod` or `bridge` workload runs as the same user, so a line says the
workload sent the request. When that distinction has to be structural, give
the container a workload of its own.

`--json` prints `{"workload", "generations", "limit", "truncated",
"records", "malformed"}`; `truncated` says that `-n` left records out.
`egress` exits 1 for a workload with no inspected egress or a record it
cannot read, and 2 for a filter value that cannot match anything.

[↑ top](#workloadctl-command-reference)

### `pcap`

Capture a workload's packets with tcpdump.

```
sudo workloadctl pcap [-i VANTAGE] [-Q {in,out,inout}] [-s SPEC] [-w PATH]
                      [--detach] [-c N] [-C N] [-W N] [-G N] [--duration D]
                      [--max-size S] [-n] [-q] [--json] [--dry-run]
                      <workload>[/<container>] [FILTER ...]
sudo workloadctl pcap -D <workload>
sudo workloadctl pcap --list
sudo workloadctl pcap --stop <workload>
```

| Option | Description |
|---|---|
| `-i`, `--interface VANTAGE` | `host` or `guest`. Repeat for both (default: `host`) |
| `-D`, `--list-interfaces` | List the workload's vantages, and why any is missing |
| `-Q`, `--direction` | `in`, `out` or `inout` (default: `inout`) |
| `-s`, `--snapshot-length SPEC` | Bytes kept per packet, or per vantage as `guest:1500,host:0`; `0` keeps whole packets (default: 1500) |
| `-w`, `--write PATH` | Write the capture to a file instead of decoding it; `-` is stdout; with two vantages, a directory |
| `--detach` | Start the capture and return; needs `-w` to a path |
| `-c`, `--packet-count N` | Stop after N packets |
| `-C`, `--rotate-size N` | Start a new file every N million bytes |
| `-W`, `--file-count N` | Keep at most N rotated files, reused as a ring |
| `-G`, `--rotate-seconds N` | Start a new file every N seconds |
| `--duration D` | Stop after D, such as `30s` or `1h`; `0` for no limit (default: `5m`) |
| `--max-size S` | Stop at S, such as `2G` (default: `100M`) |
| `-n` | Do not resolve addresses to names |
| `-q`, `--quiet` | Drop the progress lines; warnings and errors still print |
| `--json` | Print a JSON result object; needs `-w` to a path |
| `--dry-run` | Print the plan, including the firewall rule it would add, and change nothing |
| `--list` | List the captures running on this host |
| `--stop` | Stop the capture running on the workload |

`FILTER` is a tcpdump expression; everything after the workload is passed
on as it is. Only a container's guest vantage can apply one, and a VM's
guest vantage cannot honour `-Q` or rotation either; a request a vantage
cannot honour is refused rather than half applied.

The host vantage sees the host sockets opened on the workload's behalf,
which for a filtered workload shows ports 80 and 443 already redirected to
its inspector. The guest vantage sees the workload's own packets before
passt or pasta translated them. The capture runs as the transient unit
`workload-pcap-<name>.service`, which removes its firewall rule when it
stops; without `--detach`, `pcap` follows it until you press Ctrl-C. The
host vantage needs `tcpdump`. Starting and stopping a capture needs root;
`-D`, `--list` and `--dry-run` do not. See [Capturing
packets](manual/06-networking.md#capturing-packets).

[↑ top](#workloadctl-command-reference)

---

## Backup and restore

### `backup`

Archive a workload's `data/`, its TOML and the secrets it references.

```
sudo workloadctl backup [--json] [--consistency {cold,crash}] [-o PATH] <workload>
sudo workloadctl backup --all [--json] [--consistency {cold,crash}] [-o DIR]
```

| Option | Description |
|---|---|
| `--all` | Back up every workload in `/etc/workloads.d/`, enabled or not |
| `-o`, `--output PATH` | A file to write, or a directory to write into; with `--all`, a directory (default: `/var/lib/workloads/backups/`) |
| `--consistency {cold,crash}` | `cold` (default) stops the workload for the copy and starts it again; `crash` copies it running, pausing a VM's vCPUs through QMP for the copy |
| `--json` | Print the archives and their sizes as JSON instead of progress |

An archive is named `<name>-<YYYYmmdd-HHMMSS>.tar.zst` unless `--output`
names a file. It holds the TOML, the sealed secrets its TOML references,
and `data/`, which holds the `./` volumes and a VM's data disk. It never
holds `state/`: images, the podman store, a VM's system disk and its image
cache are rebuilt by `enable` and `update`, so a `pet` VM's changes to its
system disk are not in any backup. Credentials sealed for a workload's
broker are left out, and so is anything mounted under `data/`, with a
warning naming each mount.

`--json` prints `{"backups": [...]}`, each with `workload`, `archive` and
`size_bytes`, plus `failed` (each `workload` and `error`) when any failed.
One workload's failure does not stop `--all`; the exit status is 1 if any
failed. See [Backup and restore](manual/09-operating.md#backup-and-restore).

[↑ top](#workloadctl-command-reference)

### `restore`

Restore a workload from a `backup` archive.

```
sudo workloadctl restore [--force] [--enable] <archive>
```

| Option | Description |
|---|---|
| `--force` | Replace an existing TOML, secrets and `data/` |
| `--enable` | Run `enable` once the restore is done |

`restore` takes the workload's name from the TOML in the archive. It
refuses a workload that already exists unless you pass `--force`, stops the
workload, and writes the TOML, the secrets (skipping any that exist, unless
`--force`) and `data/`. An existing `data/` is merged into, or with
`--force` replaced. It refuses to write through anything mounted under
`data/`, through a symbolic link in the existing `data/`, or from an
archive whose links point outside it.

Sealed secrets open only on the host that sealed them, so on another host
restore without `--enable`, import each secret over the restored copy, then
validate and enable ([Restoring on another
host](manual/09-operating.md#restoring-on-another-host)). Re-seal a broker's
credentials with `secret create broker/<workload>/<name>`.

[↑ top](#workloadctl-command-reference)

---

## Secrets

`secret` manages credentials sealed with `systemd-creds` in
`/etc/credstore.encrypted/`. A name is letters, digits, `_` and `-`, or a
scoped name, `broker/<workload>/<name>`, for a credential a workload's
broker holds. A scoped credential is stored at
`/etc/credstore.encrypted/broker/<workload>/<name>` and sealed under the
name `broker-<workload>-<name>`, so a unit pointed at another workload's
file cannot decrypt it. Every subcommand takes either form. See
[Secrets](manual/07-secrets.md) and, for the broker, [Keeping API keys out
of the workload](manual/06-networking.md#keeping-api-keys-out-of-the-workload).

```
workloadctl secret {create,list,show,rotate,delete,export,import} ...
```

### `secret create`

Seal a new credential.

```
sudo workloadctl secret create [--key-type {tpm2,host,host+tpm2}] [--file FILE] [--force] <name>
```

| Option | Description |
|---|---|
| `--key-type` | What the seal is bound to (default: `tpm2`) |
| `--file FILE` | Seal this file's contents as they are |
| `--force` | Replace an existing credential |

Without `--file`, a value piped in is sealed byte for byte, with a warning
if it ends in a newline; at a terminal, `create` prompts twice with echo
off.

```bash
printf '%s' "$API_KEY" | sudo workloadctl secret create myapp-api-key
sudo workloadctl secret create myapp-tls-key --file ./key.pem
```

[↑ top](#workloadctl-command-reference)

### `secret list`

List the credentials, scoped ones included.

```
sudo workloadctl secret list [--json]
```

`--json` prints `{"credentials": [...]}`, each with `name`, `size` and
`modified` (Unix time).

[↑ top](#workloadctl-command-reference)

### `secret show`

Decrypt a credential and print it.

```
sudo workloadctl secret show <name>
```

[↑ top](#workloadctl-command-reference)

### `secret rotate`

Replace a credential's value and restart the workloads that use it.

```
sudo workloadctl secret rotate [--key-type {tpm2,host,host+tpm2}] <name>
```

`rotate` reads the new value as `create` does, seals it with `--key-type`
(default `tpm2`, whatever the old seal was), and restarts every workload
whose TOML references the name in `[secrets]` or a `${SECRET:...}` value.
See [Rotating a secret](manual/07-secrets.md#rotating-a-secret) for what it
does not find.

[↑ top](#workloadctl-command-reference)

### `secret delete`

Delete a credential.

```
sudo workloadctl secret delete [--force] <name>
```

| Option | Description |
|---|---|
| `--force` | Do not ask for confirmation |

[↑ top](#workloadctl-command-reference)

### `secret export`

Decrypt a credential and write it to a file protected by a passphrase, to
move it to another host.

```
sudo workloadctl secret export [-o FILE] [--passphrase-file PATH | --passphrase-stdin] <name>
```

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Where to write (default: `<name>.secret` in the current directory) |
| `--passphrase-file PATH` | Read the passphrase from PATH; `-` is stdin |
| `--passphrase-stdin` | Read the passphrase from stdin |

Without either passphrase option, `export` prompts twice. A passphrase is
one line; one trailing newline is dropped. The file uses format v2:
AES-256-CBC keyed by PBKDF2 (600,000 iterations), with an HMAC-SHA256 tag,
so `import` detects a tampered, truncated or wrongly unlocked file
([ADR 004](adr/004-secret-export-versioned-crypto.md)). Give `--output` for
a scoped name. See [Moving a secret to another
host](manual/07-secrets.md#moving-a-secret-to-another-host).

[↑ top](#workloadctl-command-reference)

### `secret import`

Unlock an exported file and seal its value on this host.

```
sudo workloadctl secret import [--force] [--key-type {tpm2,host,host+tpm2}]
                               [--passphrase-file PATH | --passphrase-stdin] <name> <file>
```

| Option | Description |
|---|---|
| `--force` | Replace an existing credential |
| `--key-type` | What the new seal is bound to (default: `tpm2`) |
| `--passphrase-file PATH` | Read the passphrase from PATH; `-` is stdin |
| `--passphrase-stdin` | Read the passphrase from stdin |

Without either passphrase option, `import` prompts once. It reads only the
v2 format `export` writes, and refuses a file without its header.

[↑ top](#workloadctl-command-reference)
