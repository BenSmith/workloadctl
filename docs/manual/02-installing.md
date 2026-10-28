# 2. Installing

workloadctl is an RPM for Fedora 43 and later. It runs on an ordinary
installed Fedora host and needs no particular image or immutable OS, though
it is built to be baked into a bootc image as well.

## Requirements

- Fedora 43 or later, with systemd. workloadctl is built and tested with
  SELinux enforcing, and installs policy modules of its own.
- Python 3.14 and podman 5.3 or later, which Fedora 43 and 44 both ship.
- For VM workloads: an x86_64 host with KVM (`/dev/kvm`).

The package pulls in everything else it runs: passt, nftables, openssl, the
SELinux tooling, and moatery, which provides the egress inspector, the
credential broker and the DNS responder that filtered workloads run behind.

## Installing from Copr

workloadctl and moatery are published from two Copr projects. Enable both,
then install:

```bash
sudo dnf copr enable benjamin-coder-smith/moatery
sudo dnf copr enable benjamin-coder-smith/workloadctl
sudo dnf install workloadctl
```

VM workloads need the `workloadctl-vm` package as well, which brings QEMU,
its UEFI firmware, virtiofsd and the tools around them:

```bash
sudo dnf install workloadctl-vm
```

Two optional packages are worth knowing about: `tcpdump`, which `workloadctl
pcap` needs to capture traffic, and `udica`, which helps write SELinux policy
for a workload that needs rights beyond the default container domain.

Check the install:

```bash
workloadctl --version
workloadctl catalog
```

`catalog` lists the bundles the package ships. If it prints them, the CLI and
its bundle tree are in place.

## Ports below 1024

A workload binds its ports as its own unprivileged user, so by default it
cannot listen below port 1024. To let workloads serve DNS on 53 or HTTPS on
443 directly, lower the unprivileged port floor for the host:

```bash
echo 'net.ipv4.ip_unprivileged_port_start = 0' | sudo tee /etc/sysctl.d/50-privileged-ports.conf
sudo sysctl --system
```

This applies to every user on the host, not only to workloads. On a host
with no interactive users that is usually fine; on a shared machine, leave
the floor alone and publish services on high ports instead.

## Upgrading

`sudo dnf upgrade workloadctl` replaces the CLI and the generator, but a
workload that is already running keeps the units the previous version
generated until it is recreated or the host reboots.
`workloadctl status` and `workloadctl doctor` report a workload whose units
came from an older build, and `sudo workloadctl recreate <name>` regenerates
them and restarts the workload on them.

## In a bootc image

To ship workloads in a bootc image, install the workloadctl and moatery
RPMs in the image's Containerfile and copy the workload directories into
`/etc/workloads.d/`:

```dockerfile
COPY workloads.d/ /etc/workloads.d/
```

A workload directory that carries an `.enabled` marker is provisioned on the
first boot of the image, user and all.

A sealed secret opens only on the host that sealed it, so an image names
its workloads' secrets and each host seals its own. See [Secrets in a bootc
image](07-secrets.md#secrets-in-a-bootc-image).

## From a source checkout

With moatery installed, `just rpm-install` in a workloadctl checkout builds
the RPM from the working tree, the same way Copr builds a release, and
installs it.
