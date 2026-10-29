# 4. Container workloads

This chapter is about writing the TOML for a container workload: the image
and what it runs, its environment and storage, its network and devices, how
it reports its health, what it may consume, how several containers make one
workload, and how a workload brings its own image or host setup. It builds on
the container you ran in [First workloads](03-first-workloads.md).

Three topics have chapters of their own: [Networking](06-networking.md)
covers egress filtering, [Secrets](07-secrets.md) covers credentials, and
[Security](08-security.md) covers the `[security]` section. Every key is in
[the schema reference](../schema-reference.toml).

## The image and what it runs

The `[container]` section names the image and, optionally, what to run in
it:

```toml
[workload]
name = "notes"

[container]
image = "docker.io/library/python:3.13-slim"
command = ["python3", "-m", "http.server", "8080", "--directory", "/srv"]
```

`image` is any reference podman accepts. `command` is an array and replaces
the image's `CMD`; leave it out to run what the image would run. `user`
names the user the container runs as, by UID or name.

### When the image is pulled

`pull` decides when podman fetches the image:

- `"missing"` (the default) pulls only when the image is not already present;
- `"always"` pulls on every start of the service;
- `"newer"` pulls on every start when the registry has a newer image;
- `"never"` never pulls, so the image must already be on the host.

`validate` refuses any other value.

Keep `"missing"`. `"always"` and `"newer"` act at every service start,
boot included, so the image can change under a workload with nobody
watching and no way back. The deliberate path is `workloadctl update`,
which pulls the current tag whatever `pull` says (except `"never"`), checks
the workload's health afterwards and rolls back to the previous image if it
fails to come up. `"never"` is for images that exist only as local builds;
see [Building your own image](#building-your-own-image).

### Cattle or pet

A workload's `lifecycle` decides what happens to the container's own
filesystem (see [Concepts](01-concepts.md#state-and-data)). A `cattle`
container, the default, is created afresh at every start and removed when it
stops, so anything it writes outside a volume is lost. A `pet` container is
created once and then stopped and started, so its writable layer survives
restarts:

```toml
[workload]
name = "desktop"
lifecycle = "pet"
```

`update` and `recreate` still replace a pet's container, but first save its
writable layer as an image, `localhost/workload-snapshot/<name>:<timestamp>`,
and keep the newest three. `snapshot_keep` in `[workload]` changes how many.
Only a single-container workload can be a pet; a multi-container one runs as
cattle, and `validate` says so.

### Containers that run systemd

By default every container gets a small init process as PID 1, which reaps
orphaned processes and passes signals on to the main one. A container that
runs systemd as PID 1, or brings an init of its own, says so with `systemd`:

```toml
[container]
image = "registry.example.com/desktops/fedora:44"
systemd = "always"

[resources]
shm_size = "2g"
```

`"always"` runs the container in podman's systemd mode and is right for a
systemd image. `"true"` lets podman detect a systemd entry point itself.
`"false"` drops the init process without turning on systemd mode, for an
image with its own init. Any value removes the default init, and `"always"`
and `"true"` also stop the container with `SIGRTMIN+3`, the signal systemd
shuts down on. `validate` refuses any other value, and the generator skips
such a workload.

`sudo workloadctl reboot <name>` soft-reboots systemd inside the container
and keeps its writable layer. Desktop and browser images usually want more
shared memory than podman's default `/dev/shm` of 64 MB, which `shm_size`
in `[resources]` sets.

## Environment

`[container.environment]` sets environment variables in the container:

```toml
[container.environment]
TZ = "Etc/UTC"
LOG_LEVEL = "info"
API_TOKEN = "${SECRET:notes-api-token}"
```

Names must be valid shell variable names; the generator drops any other with
a warning. Plain values are written into the generated unit, so a change to
one takes `recreate`, not `restart`.

A value of the form `${SECRET:name}` is replaced at each start with the
decrypted contents of an encrypted credential, whose value never appears in
the unit or the TOML. [Secrets](07-secrets.md) covers creating them. Don't
paste a key into a plain value instead: the TOML is usually readable by every
account on the host, and `validate` warns when a value looks like a
credential.

Every container also gets `HOST_IP`, the address the host uses for its
default route, detected at boot and again whenever the workload is enabled
or recreated. Setting `HOST_IP` in `[container.environment]` overrides it.

## Volumes

`[storage]` lists the directories and files mounted into the container, each
as `host:container[:options]`:

```toml
[storage]
volumes = [
    "./site:/srv:ro",
    "@/cache:/var/cache/notes",
    "/var/mnt/media:/media:ro",
]
```

The host side says where the data lives:

- `./name` is `/var/lib/workloads/<workload>/data/name`, the workload's
  precious data, which `backup` captures;
- `@/name` is `/var/lib/workloads/<workload>/state/volumes/name`, for caches
  and scratch space that can be rebuilt, which `backup` skips;
- an absolute path is used as written.

workloadctl creates `./` and `@/` directories itself, owned by the workload
user and carrying the workload's own SELinux label, so they need no `:z` or
`:Z`. An absolute host path is yours to create: `enable` refuses a workload
whose absolute volume path does not exist, and `validate` reports it. The
names `data` and `state` are reserved for the anchors, so neither can be a
named volume, and a `..` that climbs out of an anchor is refused.

The common options are `ro` for a read-only mount, `rro` for one that is
read-only all the way down (below), and `Z` to relabel a host directory for
this workload's use. `Z` uses the workload's own SELinux level, which stays
the same across restarts and recreates. Never relabel a system directory such
as `/etc` or `/home`: the host's own services depend on its labels. For a
directory several workloads use, declare a share instead (below).

### Who owns the files

Under the default user namespace, the UID inside the container that matches
the workload's own is the workload user on the host. Files written as that
UID belong to the workload user; files written as any other UID, container
root included, belong to a subordinate ID. For an image that runs as a
fixed user, `userns` in `[security]` moves the workload user to that UID:

```toml
[security]
userns = "keep-id:uid=1000,gid=1000"
```

For an image that has to run as root, `[container] user = "0"` with
`[security] userns = "keep-id:uid=0,gid=0"` makes container root the workload
user, still inside a private user namespace. [Security](08-security.md) covers
user namespaces in full.

### Read-only all the way down

A volume mounted `ro` is read-only at its own mount point only. The mounts
beneath it keep their own flags, so `/:/host:ro` still shows `/host/proc`,
`/host/sys` and every home directory writable. `rro` makes every mount under
the volume read-only too:

```toml
[storage]
volumes = ["/:/host:rro"]
```

podman does not accept `rro` itself, so workloadctl mounts the volume `ro`
and a hook that runs before the container starts turns it into a recursive
read-only mount. If the hook fails, podman refuses to create the container.

The flag reaches only the mounts that exist when the container starts, so
`rro` requires private mount propagation, the default, and `validate`
refuses it beside `slave`, `rslave`, `shared` or `rshared`, under which a
mount the host made later would arrive writable. The cost is that the
container sees no mount made after it starts, and keeps those the host
removes, until it restarts. `workloadctl diagnose` and `doctor` read the
running container's mounts and fail `recursive_readonly` if anything under
an `rro` volume is writable.

### Host paths on other filesystems

A volume whose host path lies outside the workload's own directory can be
on a filesystem of its own. The workload's unit waits for that path's
mount (`RequiresMountsFor=`), so a filesystem that is missing or fails to
mount stops the workload rather than letting it start over an empty
directory. Unless the volume is `ro`, the path is also made writable in the
unit's otherwise read-only view of the host (`ReadWritePaths=`), without
which the container would get "read-only file system" errors on a writable
mount and nothing would be logged. Sockets, FIFOs and device nodes are left
off that list: they work through a read-only mount anyway, and naming a
socket there would stop the unit from starting.

A filesystem that cannot store SELinux labels, such as cifs or vfat, needs a
mount option. Every file on it gets one label from the SELinux policy, which
containers are not allowed to read, and the denial is one SELinux does not log
by default: the unit is healthy and the volume answers `Permission denied`.
`sudo semodule -DB` makes such denials visible in the audit log, and `sudo
semodule -B` hides them again. `restorecon` and podman's `:z` and `:Z` cannot
help, because there is nowhere to store a label. Give the label at mount time,
and the ownership with it:

```
//fileserver.example/share  /var/mnt/share  cifs  \
    context=system_u:object_r:container_file_t:s0,\
    uid=_wl-<name>,gid=_wl-<name>,forceuid,forcegid,file_mode=0700,dir_mode=0700,\
    mfsymlinks,sfu,guest  0 0
```

`context=` gives every file a type containers may use. Ownership by the
workload user with mode 0700 is the only thing that keeps other workloads
out: the label is the same for every container, so SELinux does not separate
them here. `mfsymlinks` and `sfu` let the container make symlinks and FIFOs,
which otherwise fail with "operation not supported". A VM's volumes need a
different label; see [VM workloads](05-vms.md).

### Files the workload needs first

Some images need a configuration file before they can start. `[setup]
required_files` names the files `enable` checks for:

```toml
[setup]
required_files = [
    { path = "./streamer.conf", hint = "/usr/share/doc/streamer/streamer.conf.example" },
]

[storage]
volumes = ["./streamer.conf:/etc/streamer.conf:ro"]
```

`path` takes the same `./` and `@/` anchors as a volume. When the file is
missing and `hint` is an absolute path to an existing file, `enable` copies
it into place as a starting point; otherwise `enable` lists what is missing
and stops. A required file inside the workload's directory is handed to the
workload user whenever the workload is set up (at boot, on `enable` and on
`recreate`), so a file you copied in as root stays readable to the
container. A volume whose host side is a required file is mounted as that
file rather than created as a directory.

### Sharing a directory between workloads

A share is a host directory that several workloads mount, some reading and
some writing, while every other workload stays out. Declare it once, in
`/etc/workloads.d/shares.toml`:

```toml
[shares.downloads]
path = "/var/mnt/downloads"
```

Then each workload that uses it joins it:

```toml
[[shares]]
name = "downloads"
target = "/media/downloads"
access = "read"
subpath = "complete"
```

`target` is where the containers see the share, `access` is `"read"` or
`"write"`, and `subpath`, if given, mounts one directory inside it. A
reader's mount is read-only.

The share's files carry an SELinux category of their own, which only its
members hold, so another workload is refused them whatever their file modes
say. On `enable`, workloadctl creates the directory if it is missing,
labels it, and gives it to the group `wl-share-<name>`, which writers join;
readers join `wl-share-<name>-ro`, which has read access. Share names follow
the workload-name rules, up to 20 characters. The category is derived from
the name; give a share `category = <300-1023>` if two would otherwise
collide. Shares may not overlap and may not live under `/var/lib/workloads`.

Shares are for container workloads. In a multi-container workload every
container mounts the share unless `containers = ["name", ...]` lists the
ones that should.

## Networking

`[network] mode` decides what network the container has:

- `"pasta"` (the default) gives the container its own network stack and
  publishes the ports you list on the host's address;
- `"host"` shares the host's network outright: no isolation and no port
  mapping, for software that needs the LAN directly, such as mDNS or UPnP
  discovery;
- `"none"` gives it no network at all;
- any other value names a podman network that must already exist in the
  workload user's podman.

`ports` lists what to publish, as `[[address:]hostPort:]containerPort[/protocol]`:

```toml
[network]
ports = ["8080:80", "8443:443/tcp", "192.0.2.10:9000:9000"]
```

The third entry listens on one host address instead of all of them.
`ports` applies to `"pasta"` and to a named network, and is ignored in host
and none modes. Under pasta a published port answers on the host's network
address, not on its loopback, as [First workloads](03-first-workloads.md)
showed. A workload binds its ports as an unprivileged user, so ports below
1024 need the host setting in [Installing](02-installing.md#ports-below-1024).

Each workload has a podman of its own, so a named network connects nothing
across workloads. Containers that need to find each other by name belong in
one workload in bridge mode ([Several containers in one
workload](#several-containers-in-one-workload)). A named network is created as
the workload user with `sudo workloadctl incant <name> -- network create
<network>`.

A container's outbound traffic is unrestricted until its `[network]` section
names the hosts it may reach. [Networking](06-networking.md) covers that
filtering. A host-mode container cannot be filtered, and `validate` refuses
a workload that asks for both.

## Devices and GPUs

### Device nodes

`[devices] devices` passes host device nodes into the container. Access to a
device is a matter of group membership, so list the groups that own the
nodes in `[security] extra_groups`:

```toml
[workload]
name = "homeassistant"

[container]
image = "ghcr.io/home-assistant/home-assistant:stable"

[devices]
devices = ["/dev/zigbee"]

[security]
extra_groups = ["dialout"]

[network]
mode = "host"

[storage]
volumes = ["./config:/config"]
```

The workload user joins each listed group on the host, and the group's ID is
carried into the container unchanged, so the kernel's permission check on
the device passes. Inside the container, `id` shows those groups as numbers:
the image's `/etc/group` does not name them. Every listed group must exist on
the host; `validate` and `enable` both refuse a workload that names one that
does not.

Each group is a real grant. `disk` reads and writes raw disks, `input` reads
every keystroke and can inject events, `video` and `render` give the GPU, and
`kvm` gives hardware virtualisation. Grant one only to software you would
trust with what it opens.

`devices` also takes CDI names such as `nvidia.com/gpu=0`. It is for single
device nodes: a device directory such as `/dev/snd` or `/dev/bus/usb`
belongs in `[storage] volumes` as `"/dev/snd:/dev/snd"`. Passed as a device,
a directory's contents are fixed when the container is created, and a pet
container breaks once the nodes are renumbered at a reboot; mounted as a
volume it tracks the host.

Paths such as `/dev/ttyUSB0` and `/dev/video0` can change between boots. A
udev rule gives a device a stable name to use instead:

```
# /etc/udev/rules.d/99-zigbee.rules (vendor and product IDs from lsusb)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6015", SYMLINK+="zigbee"
```

Load it with `sudo udevadm control --reload-rules` and `sudo udevadm
trigger`. A serial number (`ATTRS{serial}`) tells two identical sticks
apart.

### GPUs, input and audio

Three shortcuts in `[devices]` pass the usual sets of devices:

```toml
[devices]
gpu = "amd"
input = true

[security]
extra_groups = ["video", "render", "input"]
```

`gpu` takes:

- `"amd"`: `/dev/kfd` and `/dev/dri`, needing groups `video` and `render`;
- `"intel"`: `/dev/dri`;
- `"nvidia"`: every NVIDIA GPU through CDI, plus `/dev/dri`, needing group
  `video`;
- `"nvidia:<spec>"`: one NVIDIA GPU, named by its UUID (`GPU-...`) or index
  as `nvidia-ctk cdi list` shows them. Only that card's nodes appear in the
  container. Use the UUID: indices change when cards are added or moved;
- `"auto"`: whichever vendor the first GPU in `/sys/class/drm` belongs to,
  decided when the units are generated. With several GPUs the choice is
  arbitrary, and the generator warns.

An NVIDIA workload's unit depends on `nvidia-cdi-generator.service` and will
not start without the CDI specification at `/run/cdi/nvidia.yaml`.
workloadctl ships neither: the host needs the NVIDIA Container Toolkit and a
unit of that name that writes the specification.

`input = true` mounts `/dev/input` and passes `/dev/uinput`, for game
streaming and virtual controllers; it needs the `input` group. `audio = true`
mounts `/dev/snd` and the workload user's own PulseAudio and PipeWire
sockets, `/run/user/<uid>/pulse` and `/run/user/<uid>/pipewire-0`; it needs
the `audio` group. An image that runs its own sound server wants only
`/dev/snd`, as a volume.

### From the command line

`create` has the same shortcuts. Repeat a flag once per value:

```bash
sudo workloadctl create frigate \
  --image ghcr.io/blakeblackshear/frigate:stable \
  --device /dev/video0 --device /dev/video1 \
  --groups video \
  --ports 5000:5000 \
  --enable

sudo workloadctl create gaming \
  --image registry.example.com/gaming:latest \
  --gpu amd --input --audio \
  --groups video --groups render --groups input --groups audio \
  --network host
```

## Health checks

A health check is a command podman runs inside the container on a timer.
Declare one in `[container.health]`:

```toml
[container.health]
cmd = "wget -qO- http://127.0.0.1:8080/ > /dev/null || exit 1"
interval = "30s"
timeout = "5s"
retries = 3
start_period = "60s"
on_failure = "kill"
```

`cmd` turns the check on and is the only key you need. It runs through the
image's `/bin/sh`, so the image needs a shell and whatever tool the command
calls. A zero exit is healthy. `interval` is the time between checks (30s by
default), `timeout` how long one may take (30s), `retries` how many failures
in a row make the container unhealthy (3), and `start_period` a grace period
after start during which failures do not count (none), for software that is
slow to come up.

In a multi-container workload, each container's check goes in its own
`[containers.health]`.

Write each duration as a number and one unit, such as `30s`, `5m` or `1h`.
`update` reads `interval` and `start_period` to decide how long to wait, and
does not understand compound forms such as `1m30s`.

`on_failure` decides what happens when the container turns unhealthy:

- `"none"` (the default) only marks it unhealthy;
- `"kill"` kills the container. The unit then fails and systemd restarts it
  five seconds later, which counts in the unit's restart counter where
  monitoring can see it. This is the one to use;
- `"restart"` has podman restart the container in place, and the unit stays
  active;
- `"stop"` stops the container, and the unit stays down.

### Checking health

```bash
sudo workloadctl health web
```

For a single-container workload, `health` checks that the unit is active,
the workload user exists and its systemd manager is in the expected slice,
the container is running, the health check (if there is one) reports
healthy, and each published port accepts a TCP connection from the host,
probed where it answers ([The port answers from other machines but not
from the host](10-troubleshooting.md#the-port-answers-from-other-machines-but-not-from-the-host)).
It exits 0 when everything passes and 1 otherwise, so it serves as a
probe; `--json` prints the same as JSON.

For a multi-container workload, `health` reports each container's unit and
whether the container is running; `health myapp/db` reports one. To see each
container's health check result, ask podman directly:

```bash
sudo workloadctl incant myapp -- ps
```

Health checks also guard updates. After `update` restarts a workload it
waits out the longest `start_period` plus `interval`, and rolls the
workload back to its previous image unless every checked container reports
healthy. A workload without a check is only required to stay running.

## Resource limits

### How the limits bind

All of a workload's containers run under its user's own systemd manager,
`user@<uid>.service`, which workloadctl places in `workloads.slice`. The
limits in the top-level `[resources]` section are set on that manager, so
they bind everything the workload runs together: every container and
podman's helpers beside them.

In a multi-container workload, `[containers.resources]` limits one container
on top of that, through podman's own flags. In a single-container workload
the one `[resources]` table does both jobs: it limits the workload and its
container. The limits bind the same way in every topology; [ADR
001](../adr/001-container-cgroup-placement.md) records why the containers
live where they do.

```toml
[resources]
cpu_quota = "200%"
memory_max = "4G"
memory_high = "3G"
memory_swap_max = "0"
io_weight = 500
io_write_bandwidth_max = ["/dev/nvme0n1 100M"]
tasks_max = 512
```

| Key | Example | Effect | In `[containers.resources]` |
|---|---|---|---|
| `cpu_quota` | `"50%"` | Hard CPU limit, as a share of one core; `"200%"` is two cores | yes |
| `cpu_weight` | `500` | CPU priority under contention, 1-10000 (default 100) | no |
| `memory_max` | `"2G"` | Hard memory limit; processes are killed past it | yes |
| `memory_high` | `"1.5G"` | Soft limit; memory is reclaimed hard above it | no |
| `memory_swap_max` | `"0"` | Swap limit; `"0"` allows none | no |
| `io_weight` | `500` | Disk priority under contention, 1-10000 (default 100) | no |
| `io_read_bandwidth_max` | `["/dev/sda 50M"]` | Read bandwidth per device, per second | yes |
| `io_write_bandwidth_max` | `["/dev/sda 50M"]` | Write bandwidth per device, per second | yes |
| `tasks_max` | `100` | Processes and threads | yes |
| `shm_size` | `"2g"` | Size of `/dev/shm` (default 64m) | yes |

Set `memory_swap_max = "0"` beside `memory_max` when you mean the cap.
Without it the kernel swaps the overflow out, into zram on a default Fedora
install, instead of holding the workload to the limit. Set `memory_high` a
little below `memory_max`, around three quarters of it, so the workload is
slowed before it is killed. A per-container `memory_high` is ignored with a
warning, because podman has no way to set it.

Run `recreate` after changing a limit, so the regenerated units and the new
container both carry it.

### The workloads slice

`workloads.slice` holds every workload and limits them together, so that
workloads with no limits of their own still cannot starve the host:

| Setting | Value | Effect |
|---|---|---|
| `CPUWeight` | 80 | Workloads yield CPU to system services under contention |
| `MemoryMax` | 90% | All workloads together never exceed 90% of RAM |
| `MemoryHigh` | 85% | Reclaim starts before that limit is reached |
| `MemorySwapMax` | 90% | Overflow cannot vanish into swap without bound |
| `IOWeight` | 80 | System services get the disk first under contention |

Change these with a drop-in such as
`/etc/systemd/system/workloads.slice.d/override.conf`. `slice` in
`[resources]` places one workload in another slice instead, or in
`"system.slice"` to leave the shared limits altogether. The workload's
manager moves to the new slice when the workload is next recreated, or at
the next boot.

### Service type and timeouts

Four more `[resources]` keys configure the container's own unit:

- `timeout_start_sec` (default 300) is how long systemd lets the unit take
  to start before giving up on it.
- `timeout_stop_sec` (default 30) is how long the unit may take to stop.
  The container gets 10 seconds to exit before podman kills it; given in
  whole seconds, `timeout_stop_sec` raises that to its own value less five.
- `service_type` is the systemd service type, and the default, `exec`, is
  the right one. `notify` does not work: the unit hangs in "activating",
  because the readiness message comes from a process in the workload user's
  manager, which systemd does not credit to the workload's unit. For
  readiness, use a health check.
- `custom_directives` adds any other `[Service]` directive, verbatim.

```toml
[resources.custom_directives]
LimitNOFILE = "65536"
OOMScoreAdjust = "-500"
```

`custom_directives` is passed to systemd unchecked, so a typo fails the unit
rather than `validate`, though `validate` does warn when a directive
overrides one workloadctl manages itself. As a sub-table it has to come after
every other key in `[resources]`. These directives go on the unit that runs
podman, while the container's processes run under the workload user's
manager, so a cgroup limit written here does not reach the container: use
the keys above for those.

In a multi-container workload these four keys belong in each container's
`[containers.resources]`, since each container has a unit of its own.

`create` takes the common limits as flags: `--cpu-quota`, `--cpu-weight`,
`--memory-max`, `--memory-high`, `--memory-swap-max`, `--io-weight`,
`--tasks-max` and `--shm-size`. The rest need `edit`.

### Watching usage

```bash
sudo workloadctl stats
sudo workloadctl stats -f web
```

`stats` reports podman's figures for CPU, memory, network and disk use, for
every enabled workload or for one; `-f` follows one workload live. `systemctl
status workload-web` shows only the podman process, because the containers run
under the workload user's manager; `systemd-cgls /workloads.slice` shows the
whole tree. The workload-level limits are on that manager:

```bash
uid=$(id -u _wl-web)
systemctl show "user@$uid.service" -p MemoryMax -p TasksMax
cat "/sys/fs/cgroup/workloads.slice/user@$uid.service/memory.current"
```

VM workloads take the same `[resources]` keys, applied to the VM's QEMU
process; see [VM workloads](05-vms.md).

## Several containers in one workload

A workload can run several containers under its one user, sharing its
lifecycle, home and storage: a reverse proxy in front of an application, or
an application and its database. Instead of `[container]`, list them as
`[[containers]]`, each with a `name` and its own `[containers.container]`:

```toml
[workload]
name = "blog"
mode = "pod"

[network]
ports = ["8080:8080"]

[[containers]]
name = "proxy"

[containers.container]
image = "docker.io/library/caddy:2-alpine"
command = ["caddy", "reverse-proxy", "--from", ":8080", "--to", "localhost:3000"]

[[containers]]
name = "app"

[containers.container]
image = "registry.example.com/blog:1.4"

[containers.environment]
LISTEN_ADDR = "127.0.0.1:3000"
```

Container names follow the workload-name rules (lowercase letters, digits
and hyphens, starting with a letter, up to 27 characters) and must be unique
within the workload. A table such as `[containers.environment]` belongs to
the `[[containers]]` entry above it. A workload has either `[container]` or
`[[containers]]`, never both.

### Pod or bridge

`mode` decides how the containers share the network. It defaults to `"pod"`
when there are `[[containers]]`.

In **pod** mode the containers share one network namespace and reach each
other on `localhost`, as the proxy above reaches the application on port 3000.
Ports are published once, for the whole pod, in the top-level `[network]`. The
containers share one user namespace too, so `userns` and the ID maps go in the
top-level `[security]`; a container's own value is ignored with a warning.
Under the default `keep-id`, a container that names no `user` runs as the
workload user rather than its image's `USER`, unless the workload sets
`extra_groups` or explicit ID maps. Pod mode suits tightly coupled sidecars
behind one set of ports.

In **bridge** mode each container has its own network namespace, all joined
to a network workloadctl creates for the workload, and they find each other
by container name:

```toml
[workload]
name = "tracker"
mode = "bridge"

[resources]
memory_max = "2G"

[[containers]]
name = "db"

[containers.container]
image = "docker.io/library/postgres:16"

[containers.environment]
POSTGRES_USER = "tracker"
POSTGRES_PASSWORD = "${SECRET:tracker-db-password}"

[containers.storage]
volumes = ["./db:/var/lib/postgresql/data"]

[containers.health]
cmd = "pg_isready -U tracker"
start_period = "30s"
on_failure = "kill"

[[containers]]
name = "web"

[containers.container]
image = "registry.example.com/tracker:2.0"

[containers.environment]
DATABASE_URL = "postgres://tracker@db:5432/tracker"

[containers.network]
ports = ["8080:8080"]

[containers.resources]
memory_max = "1G"
```

Here `web` reaches the database at `db:5432`, and only `web` publishes a
port, in its own `[containers.network]`; a top-level `[network] ports` is
ignored in bridge mode, with a warning. Each container has its own user
namespace, so `userns` goes in `[containers.security]`. The top-level
`[resources]` caps the two containers together at 2 GB, and `web` alone at
1 GB. Bridge mode suits services that talk over the network, such as an
application and its database.

### What goes where

| Declared once, at the top level | Declared per container |
|---|---|
| `[workload]` | `[containers.container]`: image, command, pull, systemd, user |
| `[network]`: mode and ports in pod mode, egress filtering in both | `[containers.network]`: ports in bridge mode |
| `[security]`: extra_groups, privileged, selinux_policy; userns and ID maps in pod mode | `[containers.security]`: capabilities, security_opt; userns and ID maps in bridge mode |
| `[resources]`: workload-wide limits and `slice` | `[containers.resources]`: per-container limits, timeouts, service type, custom directives |
| `[[shares]]`, `[setup]`, `[host]` | `[containers.environment]`, `[containers.health]`, `[containers.storage]`, `[containers.devices]`, `[containers.secrets]`, `[containers.build]` |

`[build]` at the top level supplies build inputs that a container without
its own `[containers.build]` inherits; see
[Building your own image](#building-your-own-image).

### Units and the `<workload>/<container>` form

A multi-container workload generates more units than a single one. The
workload's own unit, `workload-<name>.service`, starts and stops everything:
it requires a unit that creates the pod (`workload-<name>-pod.service`) or
the network (`workload-<name>-net.service`), and one unit per container,
`workload-<name>-<container>.service`. Stopping it stops them all, and a
container that fails to start fails it too. The containers are named
`workload-<name>-<container>` in the workload user's podman.

Commands take a whole workload or one container:

```bash
workloadctl status tracker            # every unit and container
workloadctl logs tracker              # all containers, merged
workloadctl logs tracker/web          # one container
sudo workloadctl exec tracker/db psql -U tracker
sudo workloadctl shell tracker/web
sudo workloadctl health tracker
```

`exec` and `shell` need the `<workload>/<container>` form on a
multi-container workload; given the workload alone, they list its
containers. `logs`, `health`, `incant` and `pcap` take either. `enable`,
`disable`, `start`, `stop`, `restart`, `recreate`, `update` and `rollback`
always act on the whole workload: `update` pulls every container's image and
`rollback` reverts them all.

Two shipped bundles are worked examples:
[`webproxy-demo`](../../workloads/webproxy-demo/workload.toml), a Caddy proxy
in front of a small backend in bridge mode, needing nothing but public images;
and
[`example-multi-container`](../../workloads/example-multi-container/workload.toml),
Forgejo with PostgreSQL in bridge mode and an encrypted database password,
closer to a real stack.

## Host setup scripts

Some workloads need something on the host that a container cannot do for
itself: a kernel module, a udev rule, a service of its own beside the
container. `[host] setup` names a script that installs it:

```toml
[host]
setup = "setup.sh"
```

A relative name is looked up beside the workload's TOML in
`/etc/workloads.d/<name>/`, then in the bundle's local layer under
`/etc/workloadctl/bundles/`, then in its directory under
`/usr/share/workloadctl/workloads/`; an absolute path is used as written.
The script must be executable. It runs as root, with `enable` on `workloadctl
enable` and `disable` on `workloadctl disable`, and must be safe to run more
than once in either direction. If it fails on `enable`, the workload is not
started; a failure on `disable` is reported and the teardown carries on. On a
first enable the script runs before workloadctl creates the workload's user.

A script in a bundle serves every instance made from it, and an instance can
have a different name from its bundle (`init --as`). So the script is told
which instance it is acting for, in its environment:

| Variable | Value |
|---|---|
| `WORKLOAD_NAME` | the instance name |
| `WORKLOAD_BUNDLE` | the bundle it came from |
| `WORKLOAD_LOCAL_BUNDLE_DIR` | the bundle's local layer under `/etc/workloadctl/bundles/`, which may not exist |
| `WORKLOAD_BUNDLE_DIR` | the bundle's directory under `/usr/share/workloadctl/workloads/` |
| `WORKLOAD_USER` | `_wl-<name>` |
| `WORKLOAD_INSTANCE_DIR` | `/etc/workloads.d/<name>` |
| `WORKLOAD_ROOT_DIR` | `/var/lib/workloads/<name>` |
| `WORKLOAD_STATE_DIR` | `/var/lib/workloads/<name>/state` |
| `WORKLOAD_DATA_DIR` | `/var/lib/workloads/<name>/data` |

Treat them as required (`"${WORKLOAD_NAME:?}"`) and never default one to the
bundle's name. Name anything host-wide the script creates, such as a unit or
a udev rule, after `WORKLOAD_NAME`, or two instances of one bundle will
collide.

### Declaring what the script installs

`doctor`, `diagnose`, `drift` and `health` know a workload from the units
workloadctl generated. A service the script installed could fail for weeks
behind a clean report. So the script can declare what it installs: given
`artifacts`, it prints one line per item and exits 0:

```
unit  games-udev-relay.service
file  /etc/avahi/services/games-sunshine.service
cert  /etc/pki/games/server.crt
```

`unit` is a systemd unit, `file` an absolute path, and `cert` a certificate
whose expiry is checked as well as its presence. `doctor` and `diagnose`
check each one. The action runs from those report commands, so it must
change nothing, print nothing else, and answer within 15 seconds. Declare
only what `enable` actually installed on this host, and only what the
workload owns: a system-wide setting that other workloads also rely on would
have each of them report the others' teardown as its own fault. A script
without the action exits non-zero from its usage branch, which reads as
"undeclared"; only an empty answer with exit 0 means it installs nothing.

```bash
#!/bin/bash
set -euo pipefail

WORKLOAD_NAME="${WORKLOAD_NAME:?run via workloadctl enable/disable}"
RELAY_UNIT="${WORKLOAD_NAME}-udev-relay.service"

enable()    { : ; }   # install the module, rule or unit
disable()   { : ; }   # remove them again
artifacts() { echo "unit ${RELAY_UNIT}"; }

case "${1:-}" in
    enable)    enable ;;
    disable)   disable ;;
    artifacts) artifacts ;;
    *)         echo "Usage: $0 {enable|disable|artifacts}" >&2; exit 1 ;;
esac
```

## Building your own image

A workload can build its image on the host from a `Containerfile`, kept
beside its TOML in `/etc/workloads.d/<name>/` or shipped in its bundle.

```toml
[workload]
name = "tools"

[container]
image = "localhost/tools:latest"
pull = "never"
command = ["sleep", "infinity"]

[build]
args = { FEDORA_VERSION = "44" }
```

```bash
sudo workloadctl build tools
sudo workloadctl enable tools
```

`build` builds the image into root's image store, tagged exactly as
`[container] image`. `enable`, `recreate` and `update` then copy root's copy
into the workload user's store, so after a rebuild, `recreate` puts the
workload on the new image.

There are two ways to declare a built image. An image that exists only as a
local build has `pull = "never"` and needs no `[build]` table; a `localhost/`
name makes that plain to the reader. An image that is also published to a
registry keeps its registry name, `pull = "missing"` and a `[build]` table,
even an empty one: the table marks it as one you build. A local build of it
then takes precedence over the registry until you delete root's copy with
`sudo podman rmi <image>`, after which the next `update` pulls the published
one again. Images you do not build are never replaced this way.

`[build]` takes:

- `containerfile`: the file to build from, relative to the build directory
  (default `Containerfile`);
- `args`: fixed build arguments;
- `arg_env`: names of host environment variables to pass as build arguments
  when they are set, overriding `args`, as in `sudo GPU_TYPE=nvidia
  workloadctl build <name>`;
- `target`: the stage of a multi-stage build;
- `script`: a script to run instead of the built-in builder, for builds the
  keys above cannot express. It receives the build directory and the image
  tag as arguments, and as `WL_BUILD_CONTEXT`, `WL_TAG` and `WL_IMAGE` in its
  environment.

Build arguments are recorded in the image's history, so never pass a secret
through one. `http_proxy`, `https_proxy` and `no_proxy`, when set in the
environment `build` runs in, are passed on as build arguments too.

The build directory is the bundle's directory with the files in
`/etc/workloads.d/<name>/` laid over it, one file at a time, so an edited
`Containerfile` or asset takes effect. workloadctl's own files (the TOML,
`policy.cil`, `build.sh` and the setup script) are left out of it.

### Several images in one workload

`build` builds every distinct image a workload builds, once each, in the
order of the TOML. Give each container that builds its own image a
`[containers.build]`:

```toml
[[containers]]
name = "vpn"

[containers.container]
image = "localhost/stack-vpn:latest"
pull = "never"

[containers.build]
containerfile = "Containerfile.vpn"
```

A `[containers.build]` describes its image completely and does not merge
with the top-level `[build]`; a container without one inherits `[build]`
whole. `arg_env` is the exception: it stays top-level and applies to every
image. Every image builds from the same directory with its own
`Containerfile`, so copy specific paths in each (`COPY app/ /app/`), not the
whole directory, or one image picks up the others' files. Two containers may
share a built image only if they describe it identically; `validate` and
`build` refuse otherwise.

### Changing a bundle's files

A bundle's control files (its `Containerfile`, setup script and the rest)
live read-only under `/usr/share/workloadctl/workloads/<bundle>/`. To change
one for one instance, edit an override:

```bash
sudo workloadctl edit tools Containerfile
workloadctl info tools --files
sudo workloadctl build tools
sudo workloadctl recreate tools
```

`edit` copies the bundle's file into `/etc/workloads.d/tools/` on first use
and opens it; an override you leave identical to the bundle's file is
discarded. `info --files` shows, for each control file, whether the
override, a local copy or the shipped file wins. Files you have not touched
keep following the package. Instances of one bundle share its image name, so
give an instance with an edited `Containerfile` an `image` of its own.

To change a file for every instance of a bundle, put your copy in
`/etc/workloadctl/bundles/<bundle>/` instead, at the same relative path. An
instance's own override still wins over it.

## Remote development from an IDE

An IDE with a remote mode, such as JetBrains Remote Development or VS Code's
Remote - SSH, keeps its window on your machine and runs its server half
where the code is. A container workload can be that place without listening
on any port: your ssh client uses a ProxyCommand that logs into the host and
starts an sshd inside the workload over the connection.

```
Host myproj
    User dev
    ProxyCommand ssh -T -a -x admin@host.example sudo workloadctl exec myproj -- ide-sshd
```

`exec` runs as the container's own user, so the sshd, and everything the IDE
starts through it, runs as that user under the workload's confinement and
egress policy. The account on the host needs `sudo` without a password,
because a ProxyCommand has no terminal to ask for one on.

The workload needs three things. Its image needs an sshd to run once per
connection (`sshd -i`) with keys only, no agent or X11 forwarding, and local
forwarding allowed, which is how the IDE reaches its server half on the
workload's loopback. It needs a home directory on a volume, where the IDE
uploads its server half on first connection (a JetBrains backend is 5-6 GB
per build) and keeps its caches and settings. And a debugger needs `ptrace`,
which `[security] seccomp_allow` grants; see [Security](08-security.md).

The `remote-dev` bundle is all of this, with C/C++, Rust and Python
toolchains. Its [README](../../workloads/remote-dev/README.md) walks through
the setup:

```bash
sudo workloadctl init remote-dev --as myproj
```
