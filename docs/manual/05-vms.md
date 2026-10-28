# 5. VM workloads

A VM workload runs a whole guest operating system under QEMU and KVM, owned
by the workload's own user, with UEFI firmware, a system disk built from an
image, an optional data disk, and a cloud-init seed that provisions the
guest on its first boot. [First workloads](03-first-workloads.md#a-vm) took
one from `init` to `disable`. This chapter covers what you need to write and
run one: where its disks come from and what survives an update, how the
guest is provisioned, how you get into it, and how to share host
directories with it.

How a VM's traffic is filtered is in [Networking](06-networking.md), and the
SELinux side of its confinement is in [Security](08-security.md).

## Before you start

VM workloads need an x86_64 host with KVM and the `workloadctl-vm` package,
which brings QEMU, its UEFI firmware and virtiofsd:

```bash
sudo dnf install workloadctl-vm
ls -l /dev/kvm
```

`enable` checks the host first. If `qemu-system-x86_64`, `qemu-img`,
`socat`, the OVMF firmware or `/dev/kvm` is missing, it names what is
missing and leaves the workload disabled.

## Starting from a template

Two commands write an enable-ready VM into `/etc/workloads.d/`:

```bash
sudo workloadctl init --scratch-vm myvm
sudo workloadctl init vm-base --as myvm
```

Both give you the same settings: the current Fedora Cloud image by URL and
checksum, 2 vCPUs, 2 GiB of memory, a 20 GiB system disk, `user = "fedora"`,
`egress = "open"`, and a cloud-init seed that creates the login account,
installs the keys workloadctl needs and sets up the guest's clock. Both
validate what they wrote and print the result. Neither enables the workload.

They differ in who owns the seed. `--scratch-vm` writes a copy of it to
`/etc/workloads.d/myvm/cloud-init/user-data`, and that copy is yours to edit.
`vm-base --as` copies only the TOML: its `user_data_file` names the seed in
`/usr/share/workloadctl/workloads/vm-base/` by absolute path, so the instance
picks up the package's version of the seed when the package is upgraded.

Use `--scratch-vm` when you mean to write your own seed. To take over the
seed of a `vm-base` instance later, make the copy and point the TOML at it.
`edit` copies the shipped seed and opens it in your editor; make your change
there, because a copy saved unchanged is discarded:

```bash
sudo workloadctl edit myvm cloud-init/user-data
```

```toml
[vm.cloud_init]
user_data_file = "cloud-init/user-data"
```

Without the second change the copy is never read, because the absolute path
in the TOML still names the shipped file.

Then edit the TOML to taste and enable:

```bash
sudo workloadctl edit myvm
sudo workloadctl enable myvm
```

## The `[vm]` section

A `[vm]` section is what makes a workload a VM, and it cannot be combined
with `[container]` or `[[containers]]`. This one uses workloadctl's built-in
seed rather than a seed file, which is enough for a guest you reach with
`shell` and `exec`:

```toml
[workload]
name = "devbox"

[vm]
cloud_image_url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
cloud_image_checksum = "sha256:28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
vcpus = 2
memory = "4G"
system_disk_size = "20G"
data_disk_size = "50G"
user = "fedora"

[vm.network]
egress = "open"
```

`user` is the guest account that `shell` and `exec` log in as; it defaults
to `workload`. `[vm.network]` has to say something, because a VM's traffic
is filtered by default and a filtered VM must name where it may go.
`egress = "open"` is the shortest valid answer; the alternatives are in
[Networking](06-networking.md).

Every `[vm]` key is described in [the schema reference](../schema-reference.toml),
and [example-fedora-vm.toml](../examples/example-fedora-vm.toml) is a
complete example to copy.

### Image sources

A VM names exactly one source for its system disk:

| Keys | What the build does |
|---|---|
| `cloud_image_url` and `cloud_image_checksum` | Downloads the image once, checks it, and copies it to the system disk. |
| `local_image` | Copies a qcow2 file from the host, with no checksum. |
| `image` | Builds a disk from a bootc container image with `bootc-image-builder`. |

A downloaded image is cached in `/var/lib/workloads/<name>/.image-cache/`
under the file name from the URL. It is checked against
`cloud_image_checksum` every time it is used, and a cached file that no
longer matches is downloaded again. Only `sha256:` checksums are accepted.
`file://` URLs work and get the same check and cache, which is the
difference from `local_image`: that copies its file afresh at every build
and checks nothing. An image in a format other than qcow2 is converted with
`qemu-img`.

To move a VM to a newer image, change both the URL and the checksum, then
run `update` (below).

`image` needs `bootc-image-builder` installed on the host. Its first build
can take ten to thirty minutes, and the build step allows an hour.

## Disks

A VM's files on the host are split the same way a container's are, by
whether they can be rebuilt:

```
/var/lib/workloads/devbox/
├── state/                    rebuilt from the image; not backed up
│   ├── system.qcow2          the guest's root disk
│   ├── system.qcow2.gen-N    earlier system disks, for rollback
│   ├── nvram.fd              the VM's UEFI variables
│   └── .ssh/                 the workload's SSH key and the guest's pinned host key
├── data/                     kept; this is what backup captures
│   └── data.qcow2            the data disk, if data_disk_size is set
└── .image-cache/             downloaded cloud images
```

The cloud-init seed ISO and QEMU's sockets live in
`/run/workload-vm/<name>/`, on a tmpfs, and are recreated at every boot.

The system disk is the guest's root filesystem, and it is disposable: an
`update` replaces it. Anything the guest must keep belongs on the data disk
or on a shared directory, and that is also what keeps backups small, since
`backup` captures `data/` and nothing else.

### The data disk

`data_disk_size` creates an empty disk of that size, which the guest sees
as `/dev/vdb`. The built-in seed formats it as ext4 if it has no filesystem
yet, adds it to `/etc/fstab` and mounts it at `/data`. Each of those steps
is checked separately, so a data disk that comes back already formatted,
from a `restore` or after `update` has rebuilt the system disk, is mounted
rather than reformatted.

A seed file of your own, including the starter seed from `init`, does
none of this. Add the same block as an item of its `runcmd:` list:

```yaml
runcmd:
  - |
    if [ -b /dev/vdb ]; then
      blkid /dev/vdb | grep -q TYPE || mkfs.ext4 -L workload-data /dev/vdb
      mkdir -p /data
      grep -q '^LABEL=workload-data ' /etc/fstab || echo 'LABEL=workload-data /data ext4 defaults 0 2' >> /etc/fstab
      mountpoint -q /data || mount /data
    fi
```

The starter seed already ends with a `runcmd:` list; add this as a second
item there. A second `runcmd:` key does not add to the first, it replaces
it.

Decide on the data disk before the first `enable`. It is created when the
system disk is built, which happens at the first enable and when `update`
rebuilds a cattle VM, and changing `data_disk_size` later does not resize a
disk that already exists.

`system_disk_size` grows the system disk to that size each time it is
built, and cloud-init grows the root partition to fill it on first boot.
Without it the disk keeps the image's own size, about 5 GiB for Fedora
Cloud. Both sizes need a unit, such as `"20G"` or `"512M"`; a bare number is
refused.

## Update and rollback

```bash
sudo workloadctl update devbox
```

`update` rebuilds the system disk from the image source and restarts the VM
onto it. The current disk is renamed to `system.qcow2.gen-N` first, and the
VM keeps running on it while the new one is built.

The guest then boots a fresh disk. cloud-init runs its first-boot work
again from the same seed, the data disk and any shares are mounted again,
and anything that lived only on the old system disk is gone. That is what
an update is for: it proves the system disk can be rebuilt from the TOML,
the seed and the image.

If the build fails (a download error, a checksum mismatch, a failed bootc
build), the old disk is put back, the VM is left running on it, and
`update` exits non-zero.

`[vm].rollback_keep` (default 2) is the number of older generations kept
beside the one an update has just made, so by default there are at most
three `system.qcow2.gen-*` files.

A container's `update` watches its health check and rolls back on its own.
A VM's does not check the guest at all, so look before moving on:

```bash
workloadctl status devbox
sudo workloadctl shell devbox --console
```

If the new disk is bad, go back:

```bash
sudo workloadctl rollback devbox --list
sudo workloadctl rollback devbox
```

`rollback` stops the VM, swaps in the most recent earlier generation and
starts the VM again. It does not throw away the disk it replaces: that
becomes a new generation, so running `rollback` a second time takes you
back to where you were. Generations made this way are pruned by
`rollback_keep` like any other.

`update --dry-run` prints what would happen without doing it, and
`update --all` updates every enabled workload, VMs included.

## Pet and cattle

A VM is cattle unless its TOML says otherwise: its system disk is rebuilt by
every `update`, and generations give you a way back. A pet VM keeps its
system disk:

```toml
[workload]
name = "devbox"
lifecycle = "pet"
```

For a pet, `update` neither rebuilds nor rotates the system disk; it
restarts the VM. `rollback` refuses, because there are no generations to
roll back to. `backup` still captures only `data/`, for a pet as for
cattle, so a pet's system disk is not in its backups. Keep anything you
cannot lose on the data disk or a share, or back it up from inside the
guest.

Cattle suits a VM whose configuration lives in its seed, such as a CI runner
or an appliance. Pet suits a VM you administer by hand, such as a
development machine you install packages into.

## Provisioning the guest with cloud-init

Every VM boots with a cloud-init seed: a small ISO holding the guest's
user-data and an instance ID. workloadctl builds it on the host before QEMU
starts.

### The built-in seed

Without a `[vm.cloud_init]` section, the seed is generated from the TOML. It
sets the guest's hostname to the workload name, and creates `[vm].user`
with UID 1000, passwordless sudo and the workload's SSH key. It installs the
guest's SSH host key, which the host has already pinned, and mounts every
shared directory. It formats and mounts the data disk, sets up the guest's
clock, and for a filtered VM installs the egress CA. It installs no
packages and upgrades nothing.

### A seed of your own

For anything more, write your own `#cloud-config` and name it:

```toml
[vm.cloud_init]
user_data_file = "cloud-init/user-data"

[vm.cloud_init.template_vars]
REPO_URL = "https://git.example.com/me/project.git"
VERSION = "1.4.2"
```

A relative path is resolved against the directory holding the TOML. The
file is the guest's entire user-data: workloadctl does not parse it or merge
anything into it. It only substitutes placeholders as plain text, and adds
the `#cloud-config` header if the file lacks one.

| Placeholder | Replaced with |
|---|---|
| `${VAR}` | The value from `template_vars`, else from the environment of the step that builds the seed. Unresolved, the build fails. |
| `${SECRET:name}` | The decrypted credential `/etc/credstore.encrypted/<name>`, or `/etc/credstore/<name>`. Missing, the build fails. |
| `${SECRET?name}` | The same, but an empty string if the credential is missing. |
| `$$` | A literal `$`; write `$${name}` to keep `${name}` in the output. |

Substitution runs over the whole file, comments included, so a placeholder
mentioned in a comment has to be written `$${...}`. Keep values in
`template_vars` rather than the environment: the seed is rebuilt at every
boot by a systemd unit, whose environment is not your shell's.

workloadctl supplies these variables to every seed file:

| Variable | Value |
|---|---|
| `WORKLOADCTL_SSH_KEY` | The workload's SSH public key. Put it in the login user's `ssh_authorized_keys`. |
| `WORKLOADCTL_WORKLOAD_NAME` | The workload name. |
| `WORKLOADCTL_VM_USER` | `[vm].user`. Create the login account from it rather than repeating the name. |
| `WORKLOADCTL_VM_HOST_KEY_B64` | The guest's SSH host private key, base64-encoded on one line. |
| `WORKLOADCTL_VM_HOST_PUBKEY` | The matching public key. |
| `WORKLOADCTL_VM_HOST_KEY` | The private key as PEM, for an `ssh_keys:` block. |
| `WORKLOADCTL_VM_EGRESS_CA_B64`, `WORKLOADCTL_VM_EGRESS_CA` | A filtered VM's egress CA, base64 and PEM; empty for an open VM. See [Networking](06-networking.md). |
| `WORKLOADCTL_VM_INSPECT_ADDR` | The VM's own address on the host, for reaching a host service (see [The guest's network](#the-guests-network)). Not set for a bridged VM. |

The starter seed from `init` uses most of these and is the place to start
from: [workloads/vm-base/cloud-init/user-data](../../workloads/vm-base/cloud-init/user-data).

### What a seed file must carry

A seed file replaces the built-in seed, so the things the built-in seed did
for you become yours to do. workloadctl checks four of them when it builds
the seed, and refuses to build one that misses any, naming what is missing.
`enable` prints the reason. After `recreate`, which reports only that the
setup step failed, read it with
`journalctl -u workload-<name>-setup.service`.

**The host key.** `shell` and `exec` verify the guest against a host key
pinned in advance, with no trust on first use, so the seed must install that
key. Either use an `ssh_keys:` block carrying `${WORKLOADCTL_VM_HOST_KEY}`,
or write the key with `write_files` and turn off cloud-init's host key
regeneration:

```yaml
ssh_deletekeys: false

write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${WORKLOADCTL_VM_HOST_KEY_B64}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    permissions: '0644'
    owner: root:root
    content: ${WORKLOADCTL_VM_HOST_PUBKEY}
```

`ssh_deletekeys: false` is required with `write_files`, because cloud-init's
SSH module runs after `write_files` and otherwise deletes the key and makes
a new one, which then fails the pin.

**Every shared directory mounted.** An unmounted share leaves its guest path
as an ordinary directory on the system disk, and what the guest writes there
is lost at the next `update`. See [Sharing host
directories](#sharing-host-directories).

**The SELinux context on a share over the guest's home.** See
[A share over the guest's home](#a-share-over-the-guests-home).

**The egress CA, for a filtered VM.** See [Networking](06-networking.md).

If the guest image already does one of these itself, for instance with a
mount in its own `/etc/fstab`, declare it with
`seed_provides = ["mounts"]`, `["home_context"]` or `["ca"]` in
`[vm.cloud_init]`. That turns the check off; it does not do the work.

Three more things are not checked but matter: create `[vm].user` with UID
1000 if the VM has shared directories, set up the data disk if it has one
(above), and copy the clock block from the starter seed (see
[The guest's clock](#the-guests-clock)).

### When the seed changes

The seed is rebuilt whenever the VM's setup step runs: at every host boot,
at `enable`, and at `recreate`. A plain `restart` does not run it. When the
rendered seed is the same as last time, the guest keeps its instance ID and
cloud-init does nothing new. When anything in it changes, whether the file,
a template variable or a secret's value, the guest gets a new instance ID and
cloud-init runs its per-instance work again on the existing disk on the
next boot: users, `write_files`, `runcmd`. Write `runcmd` so it can run
twice.

To apply an edited seed:

```bash
sudo workloadctl recreate devbox
```

If cloud-init reports that its run failed, the next setup step (`recreate`,
`enable` or a host boot) gives the guest a new instance ID once, so the
failed modules run again. `workloadctl diagnose` reports what the last run
recorded.

### Secrets in the seed

Store a secret as a credential, then name it in the seed:

```bash
sudo workloadctl secret create runner-token
```

```yaml
runcmd:
  - [ /usr/local/bin/register-runner, "${SECRET:runner-token}" ]
```

The credential is decrypted when the seed is built, and the seed ISO is
written to the tmpfs under `/run/workload-vm/<name>/`, readable by the
workload's user, so the plain value never rests on the host's disks. It is
decrypted again at each boot. Inside the guest, whatever the seed writes is
on the guest's own disk.

After changing a secret a VM's seed uses, run `recreate`. `secret rotate`
restarts the workloads whose TOML names the secret, which neither finds a
reference that lives only in a seed nor rebuilds a VM's seed. Credentials
are covered in [Secrets](07-secrets.md).

The `forgejo-runner` bundle is a complete worked example: a Fedora VM that
installs its tools and registers itself as a CI runner from its seed. See
[its README](../../workloads/forgejo-runner/README.md).

## Sizing

`vcpus` is a whole number and defaults to 2. `memory` is in QEMU's notation,
a number of MiB or a value such as `"2048M"` or `"4G"`, at least 256 MiB,
and defaults to 2048 MiB.

By default every VM has a memory balloon device with free-page reporting: when the
guest frees memory, it tells the host, and the host takes the pages back,
so an idle guest settles near its working set rather than holding all it
has ever touched. Only freed pages are returned, not the guest's page cache.
It needs the `virtio_balloon` driver in the guest, which Fedora Cloud has.
For a guest that must never have its memory reclaimed under it, turn it
off:

```toml
[vm]
balloon = false
```

The `[resources]` table applies to a VM's service unit, which holds QEMU and
its network helper, with the same keys and meanings as for a container
([Container workloads](04-containers.md)). A memory limit there must leave
room above `memory` for QEMU's own use.

Changes to sizing, like any other change to the TOML, take effect at
`recreate`.

## Running the VM

The lifecycle commands mean the same as for a container, with VM details:

- `stop` asks the guest to power off and waits up to 80 seconds for it.
  systemd kills QEMU at 90.
- `restart` power-cycles the VM onto the same disks and the same seed. It
  does not apply TOML edits.
- `recreate` regenerates the units, rebuilds the seed and restarts the VM.
  It does not touch the disks.
- `update` rebuilds the system disk (above) and restarts the VM.
- `reboot` soft-reboots the guest's userspace over SSH, which needs
  passwordless sudo and systemd 254 or later in the guest.

QEMU runs with `-no-reboot`, so a guest reboot and a guest power-off both
end the QEMU process. `[vm].restart` says what happens then:

| `restart` | After a guest reboot | After a guest power-off | After a crash |
|---|---|---|---|
| `"always"` (default) | starts again | starts again | starts again |
| `"on-failure"` | stays down | stays down | starts again |
| `"on-reboot"` | starts again | stays down | starts again |

With the default, `poweroff` inside the guest brings it back ten seconds
later; use `workloadctl stop` to stop it. systemd allows three starts in
five minutes, so a VM that keeps crashing is left down after the third;
`recreate` clears that.

`workloadctl logs` shows the VM unit's journal: QEMU's messages and
workloadctl's, not the guest's. Read the guest's own journal inside it:

```bash
sudo workloadctl exec devbox -- journalctl -b
```

## Getting into the guest

```bash
sudo workloadctl shell devbox
sudo workloadctl shell devbox --console
sudo workloadctl exec devbox -- dnf upgrade -y
```

`shell` logs in over SSH as `[vm].user`, with the workload's own key,
checking the guest's host key against the pinned one. If SSH cannot connect
at all, it falls back to the serial console. `--console` goes straight to
the console, which works at any stage of boot and with the guest's network
down; press `Ctrl+]` to detach.

`exec` runs one command over SSH and returns its exit status. Arguments
reach the guest exactly as you typed them, so
`exec devbox -- sh -c 'cd /data && ls'` does what it would do locally. The
`--` is optional.

Both need `sudo`, because the key lives in the workload's home directory.

The guest has no address on your network, so SSH reaches it on a
**management address**: `127.128.0.0` plus the workload user's offset from
UID 10000, port 2222, which forwards to the guest's port 22. The address is
derived from the workload's UID, is reachable only from the host itself,
cannot be configured, and cannot be claimed by another VM's published
ports. `workloadctl diagnose <name>` prints it.

`workloadctl info` lists the guest's own addresses as `qemu-guest-agent`
reports them, when the guest runs it. For raw access to QEMU's monitor,
`incant` sends one QMP command, `key=value` arguments and all:

```bash
sudo workloadctl incant devbox query-status
```

## The guest's network

A VM's network runs through passt, which ends the guest's network stack in
user space on the host and sends its traffic on as ordinary connections
owned by the workload's user. Three things follow:

- **The guest takes the host's address.** It has no identity of its own on
  your network, so nothing there can reach it except through ports you
  publish.
- **The guest cannot reach services on its own host.** The host's loopback
  is not mapped into the guest, and the host's main address is the guest's
  own address, so traffic to it never leaves the guest. Another address the
  host has, on a second interface say, is an ordinary destination and is
  reachable.
- **Its traffic is the workload user's traffic.** That is what lets the host
  police it.

There is one deliberate way in to the host: the VM's own derived address,
which `WORKLOADCTL_VM_INSPECT_ADDR` gives to the seed. It is added to the
host while the VM runs, so a host service published on it is reachable from
an open VM's guest. The `forgejo-runner` bundle uses it to reach a forge
running on the same host.

A VM is in one of three stances: **filtered** (the default), where it can
reach only what its policy names; **open**, where it is not policed; or
**bridged**, where it has a real address on a LAN bridge you provide.
[Networking](06-networking.md) covers all three, the guest's DNS, and how to
write a filter policy.

### Publishing ports

Ports are published from the guest onto the host the same way a container's
are:

```toml
[vm.network]
egress = "open"
ports = ["8080:80", "5353:53/udp", "127.0.0.1:9090:9090"]
```

Each entry is `[address:]hostport[:guestport][/udp]`. Without an address
the port is published on all of the host's addresses. Three address ranges
are refused because workloadctl uses them itself: `127.128.0.0/9` for
management addresses, and `198.18.0.0/16` and `2001:2::/48` for its
per-workload addresses. The rest of `127.0.0.0/8`, `127.0.0.1` included, is fine.

`shell` and `exec` need no published port. A bridged VM publishes nothing:
it has its own address, so you reach its services there.

## Sharing host directories

`[vm].volumes` shares host directories into the guest over virtiofs:

```toml
[vm]
volumes = ["./projects:/home/fedora/projects", "/srv/media:/mnt/media:ro"]
```

Each entry is `host:guest[:options]`, the same shape a container's volumes
take. A host path starting with `./` is under the workload's `data/`, so it
is backed up; `@/` is under `state/volumes/`, which is not. workloadctl
creates those directories for you. Any other absolute path is used as it is
and must already exist. A single path with no colon is shared at the same
path in the guest.

The options are the guest's mount options, `rw` by default. `ro` makes the
guest mount the share read-only, but `virtiofsd` on the host does not
enforce it, so it guards against mistakes in the guest, not against the
guest's root user.

Each share is served by a `virtiofsd` process of its own, in a unit named
`workload-<name>-virtiofs-<tag>.service` that starts before the VM and stops
with it. The tag is derived from the guest path: slashes become dashes and it
is cut to 36 characters, so `/home/fedora/projects` is `home-fedora-projects`;
other punctuation becomes a dash too, and two shares whose tags would clash
get a numeric suffix. A seed file must mount each tag, for example with
cloud-init's `mounts:` key:

```yaml
mounts:
  - [ "home-fedora-projects", "/home/fedora/projects", "virtiofs", "rw", "0", "0" ]
  - [ "mnt-media", "/mnt/media", "virtiofs", "ro", "0", "0" ]
```

The built-in seed does this itself.

### Who owns the files

Every file in a share belongs to the workload's user on the host, whatever
the guest does. The guest's UID 1000, which is the login user the built-in
seed creates, maps to the workload user in both directions, so that user
reads its own files back as itself. Every other guest ID, root included, is
mapped one way onto the same host user:

| File | Owner seen in the guest | Owner on the host |
|---|---|---|
| created by the guest's UID 1000 | that user | `_wl-<name>` |
| created by the guest's root | UID 1000 | `_wl-<name>` |
| `chown`ed to any other ID in the guest | UID 1000 | `_wl-<name>` |

This stops a guest from choosing who owns files on the host, for instance
by planting a setuid-root binary that `backup` would then carry wherever
the archive is restored. The cost is that a guest with several users does
not see per-user ownership in a share. If you need that, use the data disk,
which the guest formats and owns outright.

### A share over the guest's home

A share mounted at the login user's home, such as `./home:/home/fedora` with
`user = "fedora"`, would hide the SSH key cloud-init writes there, because
cloud-init writes the key before it mounts shares. workloadctl handles this:
before the seed is built, at every `enable`, `recreate` and boot, it adds
the workload's key to `.ssh/authorized_keys` inside the share on the host.
It adds to the file rather than replacing it, so keys you put there
yourself stay. A share mounted at `/home` gets the key in `<user>/` inside
it. A share whose host path is outside the workload's own directory is
skipped with a warning that names the file to put the key in yourself.

The guest must also mount that share with an SELinux context sshd can read,
or key logins fail. They fail not at once but at the first boot after the
guest's own SELinux policy is updated. The built-in seed adds
`context="system_u:object_r:user_home_t:s0"` to the mount itself. A seed
file must add it, and the seed check refuses one that mounts a share over
the home without a `context=` naming `user_home_t` or `ssh_home_t`. The
starter seed has a commented example to copy.

### A host path outside the workload's directory

The workload's own directory carries an SELinux type the share's
`virtiofsd` is allowed to use, so shares under it need nothing
more. A host path elsewhere keeps the label it already has, which the
sidecar is refused, and the share appears empty in the guest.
`workloadctl diagnose` reports the denial. Give the path a label the sidecar
may use:

```bash
sudo semanage fcontext -a -t svirt_image_t '/srv/media(/.*)?'
sudo restorecon -RF /srv/media
```

A filesystem that cannot store labels, such as CIFS, NFS or vfat, takes its
label from the mount instead; `semanage` and `restorecon` appear to work and
change nothing. Mount it with a `context=` option, and use ownership and
mode to keep other workloads out, since on such a mount SELinux cannot tell
two workloads apart. An `/etc/fstab` line for an SMB share used by the
`devbox` VM, as one line:

```
//files.example.com/share  /srv/agentic  cifs  context=system_u:object_r:svirt_image_t:s0,uid=_wl-devbox,gid=_wl-devbox,forceuid,forcegid,file_mode=0700,dir_mode=0700,mfsymlinks,sfu,credentials=/etc/samba/devbox.cred,seal  0 0
```

`mfsymlinks,sfu` lets the guest create symlinks, FIFOs and sockets on SMB;
without them those fail with `EOPNOTSUPP`.

When the label is wrong, `virtiofsd` exits with
`<path> does not exist` even though the path is mounted and full. That
message is what any failure to read the directory produces; look in the
audit log for the denial:

```bash
sudo grep 'avc:.*wlvfsd_t' /var/log/audit/audit.log
```

### A filesystem mounted inside a share

If another filesystem is mounted beneath a share in the workload's
directory, say a CIFS mount at `./home/netmnt` inside a `./home` share,
name it so the sidecar starts after it is mounted:

```toml
[vm]
volumes = ["./home:/home/fedora"]
after_mounts = ["./home/netmnt"]
```

This orders the sidecar after the mount and nothing more, so the VM still
starts when the remote filesystem is unreachable. A share whose own root is
outside the workload's directory is waited for automatically.
`announce_submounts` (default true) tells the guest where such a mount
begins, so it gets a device number of its own; leave it on unless the
guest's kernel lacks virtiofs submount support.

### What breaks a share

Do not add `NoNewPrivileges=` or `DynamicUser=` to a sidecar or VM unit in a
drop-in. Either stops the unit from entering its SELinux domain, and it
fails to start with `203/EXEC` and "Permission denied" on a binary that is
plainly executable.

The common symptoms:

| What you see | Cause |
|---|---|
| The guest sees an empty directory | The share is unlabelled (above), or the seed never mounted it; check `stat -f -c %T <path>` in the guest. |
| `virtiofsd` reports `<path> does not exist` on a mounted path | A label the sidecar is refused; on CIFS or NFS, a missing `context=` mount option. |
| `ln -s` or `mkfifo` fails with `EOPNOTSUPP` on an SMB share | The `mfsymlinks,sfu` mount options are missing. |
| `ls -l` in the guest shows UID 1000 for a file root created | Expected; see [Who owns the files](#who-owns-the-files). |
| The VM is healthy but `shell` and `exec` cannot log in | A share over the guest's home without the right `context=`, or one outside the workload's directory with no key in it. |
| The sidecar fails `203/EXEC`, "Permission denied" | `NoNewPrivileges=` or `DynamicUser=` in a drop-in. |
| `Error creating pid file … Permission denied` | A stale file in `/run`; the sidecar removes it at every start, so restart the VM. |

[Troubleshooting](10-troubleshooting.md) has more.

## The guest's clock

A guest's clock stops while its vCPUs are paused and resumes behind by the
length of the pause, for good. `backup --consistency crash`,
`incant <vm> stop` and a host suspend all pause a VM. A filtered VM more
than an hour behind rejects the certificates its egress inspector issues for
names it has not visited before, and any guest far enough out fails TLS
against real servers.

Two things put the clock back. In the guest, the seed loads the `ptp_kvm`
driver and points chrony at it, so the guest reads the host's clock directly
and corrects itself within about half a minute, with no network. The built-in
seed and the starter seed carry this; a seed of your own must copy the block
from the starter seed. It works only when the host's own clocksource is the
TSC:

```bash
cat /sys/devices/system/clocksource/clocksource0/current_clocksource
```

On the host, a timer checks each VM's clock once a minute through
`qemu-guest-agent` and sets it when it is more than five minutes out. That
needs `qemu-guest-agent` running in the guest. `workloadctl diagnose`
reports a guest whose agent does not answer or whose clock is out. To check
the guest side:

```bash
sudo workloadctl exec devbox -- sh -c 'chronyc sources | cat'    # expect PHC0, marked #*
```

The `| cat` matters. The guest's SELinux policy does not let `chronyc` write
to sshd's pipes, so without it the command prints nothing and still exits 0.

## Where next

- [Networking](06-networking.md): filtered, open and bridged VMs, the
  guest's DNS, and egress policy.
- [Secrets](07-secrets.md): credentials for seeds.
- [Security](08-security.md): how a VM is confined, and SELinux on hosts
  with local policy modules.
- [Operating](09-operating.md): backup, restore and day-to-day work.
- [The VM runtime](../dev/vm-runtime.md), for maintainers: how the units,
  helpers and policy fit together.
