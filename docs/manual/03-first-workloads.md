# 3. First workloads

This chapter runs one container workload and one VM workload from start to
finish: write the configuration, start it, look at what workloadctl built,
change it, and remove it again. It assumes the package is installed
([Installing](02-installing.md)), and the VM half needs `workloadctl-vm` and
`/dev/kvm`.

Read-only commands such as `status`, `logs` and `validate` work as any user.
Anything that changes a workload, or reaches inside one, needs `sudo`.

## A container

### Write the configuration

A workload is a directory under `/etc/workloads.d/` with a `workload.toml`
in it. This one runs nginx, publishing its port 8080 on the host's port
8080:

```bash
sudo mkdir -p /etc/workloads.d/hello
sudo tee /etc/workloads.d/hello/workload.toml <<'EOF'
[workload]
name = "hello"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
EOF
```

The image is nginx's unprivileged build, which listens on 8080 rather than
80 inside the container. A workload runs as an ordinary user, and an image
that expects to bind port 80 as root is the most common reason a first
workload fails to start.

Check the file before enabling it:

```bash
workloadctl validate hello
```

### Enable it

```bash
sudo workloadctl enable hello
```

`enable` creates the workload's user, `_wl-hello`, and its directories under
`/var/lib/workloads/hello/`, pulls the image, generates the systemd units,
marks the workload to start at boot and starts it. Check on it:

```bash
workloadctl status hello
workloadctl logs hello
```

The port is published on the host's network address, not on its loopback,
so test it from another machine or with the host's own address:

```bash
curl http://<host-address>:8080/
```

`curl http://localhost:8080/` from the host itself is refused even when the
workload is healthy. That is how pasta publishes ports, not a fault.

### Look around

```bash
workloadctl info hello
id _wl-hello
sudo workloadctl exec hello nginx -v
```

`info` shows the workload's container and image, its user, UID and home
directory, and its published ports. `exec` runs a command inside the container
as the workload sees it; `sudo workloadctl shell hello` opens an interactive
shell there.

### Change it

Move the published port from 8080 to 8081. `edit` opens the TOML in your
editor:

```bash
sudo workloadctl edit hello
```

```toml
[network]
ports = ["8081:8080"]
```

When you save, `edit` validates the file, shows the change as a diff, and
asks whether to apply it and restart the workload. Answer `n` this time.

The edit is now on disk, but nothing running has changed. `drift` shows the
difference between the units that are running and the ones the TOML now
describes:

```bash
workloadctl drift hello
```

A plain `restart` would bring back the old configuration, because it
restarts the units that exist. `recreate` regenerates them from the TOML and
replaces the container:

```bash
sudo workloadctl recreate hello
curl http://<host-address>:8081/
```

Answering `y` at the `edit` prompt applies the change in one step: it
regenerates the units and restarts the workload on them.

### Remove it

```bash
sudo workloadctl disable hello --purge --dry-run
sudo workloadctl disable hello --purge
```

The first command prints what would be removed; the second removes it: the
units, the user, its subordinate ID ranges and everything under
`/var/lib/workloads/hello/`. Without `--purge`, `disable` only stops the
workload and stops it starting at boot, keeping its user and data for a
later `enable`.

Either way the configuration in `/etc/workloads.d/hello/` is left alone. To
forget the workload entirely, delete that directory too.

### The shortcut

`create` writes the TOML from flags, and `--enable` enables it in the same
step:

```bash
sudo workloadctl create hello \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable
```

## A shipped bundle

The package ships ready-made workloads. List them, then stamp one into
`/etc/workloads.d/` as an instance:

```bash
workloadctl catalog
sudo workloadctl init <bundle>
```

Most bundles need a setting or two before they are useful; their TOML says
which. Edit, then enable as before:

```bash
sudo workloadctl edit <bundle>
sudo workloadctl enable <bundle>
```

A bundle whose image is built on the host has a `Containerfile`; run `sudo
workloadctl build <bundle>` before `enable`. To run a second copy of a
bundle under another name, use `init <bundle> --as <name>`.

## A VM

### Stamp it

The `vm-base` bundle is a minimal Fedora Cloud virtual machine. Make an
instance of it called `myvm`:

```bash
sudo workloadctl init vm-base --as myvm
```

Open `/etc/workloads.d/myvm/workload.toml`. The `[vm]` section names the
Fedora Cloud image by URL and checksum, and sets the VM's size and the
account the CLI logs in as:

```toml
[vm]
cloud_image_url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
cloud_image_checksum = "sha256:28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
vcpus = 2
memory = "2G"
system_disk_size = "20G"
user = "fedora"

[vm.network]
egress = "open"
```

`egress = "open"` lets the guest reach anything, which a freshly installed
system needs while it fetches packages. A VM's traffic is filtered by
default, and a filtered VM must list what it may reach.

### Enable it

```bash
sudo workloadctl enable myvm
```

`enable` first checks that QEMU, its firmware and `/dev/kvm` are present
and names whatever is missing. Then it downloads the image and checks its
checksum, builds the VM's system disk from it, writes a cloud-init seed
carrying an SSH key made for this workload, and boots the VM. The download
happens once; later rebuilds reuse it.

The first boot runs cloud-init inside the guest. Wait for it to finish:

```bash
workloadctl status myvm
sudo workloadctl exec myvm -- cloud-init status --wait
```

### Get in

```bash
sudo workloadctl shell myvm
```

`shell` logs in over SSH as the `user` the TOML names, using the
workload's own key. The VM has no address on your network; workloadctl
reaches it through a private address on the host that nothing else can
use. If SSH is not up yet, or the guest's network is broken,
`sudo workloadctl shell myvm --console` attaches to its serial console
instead. Press `Ctrl+]` to detach.

### Remove it

```bash
sudo workloadctl disable myvm --purge
```

This stops the VM and deletes its disks, its key and its user. As with the
container, delete `/etc/workloads.d/myvm/` as well to forget it entirely.

## Where next

- [Container workloads](04-containers.md) and [VM workloads](05-vms.md)
  cover each substrate in full;
- [Networking and egress](06-networking.md) covers filtering what a workload
  may reach;
- [Troubleshooting](10-troubleshooting.md) covers what to do when something
  goes wrong;
- every command and flag is in [the CLI reference](../cli.md), and every key
  in [the schema reference](../schema-reference.toml).
