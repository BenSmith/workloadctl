# workloadctl

Declarative workload manager for Linux. Drop a TOML file into
`/etc/workloads.d/<name>/`, and workloadctl provisions everything underneath
it: a dedicated system user, systemd units, storage, secrets, networking and
lifecycle.

A workload is either a **container** (rootless podman) or a **VM** (KVM/QEMU,
declared with a `[vm]` section). Both share one TOML model, one command
surface, and one isolation rule: **one workload, one unprivileged system
user**. `status`, `logs`, `update`, `rollback` and `backup` mean the same
thing whichever substrate a workload runs on.

That user is the handle everything else holds. Storage is owned by it,
outbound network policy matches on it, and because the host assigns it,
nothing inside the workload can forge it. So a VM's outbound traffic can be
filtered by host name without the guest's cooperation, and a sandboxed
workload can call an authenticated API through a host-side credential broker
without ever holding the key.

Stdlib Python, packaged as an RPM. No virtualenv and no daemon of its own.

## Install

```bash
sudo dnf copr enable benjamin-coder-smith/moatery
sudo dnf copr enable benjamin-coder-smith/workloadctl
sudo dnf install workloadctl            # and workloadctl-vm for VM workloads
```

Fedora 43 or later. [Installing](docs/manual/02-installing.md) covers the
requirements, ports below 1024, upgrades and bootc images.

## Five minutes

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

workloadctl validate hello
sudo workloadctl enable hello
workloadctl status hello
curl http://<host-address>:8080/
```

`enable` created the user `_wl-hello`, pulled the image, generated the units
and started the container; it starts again at every boot. The port answers
on the host's network address rather than on `localhost`. To remove it all:

```bash
sudo workloadctl disable hello --purge
```

[First workloads](docs/manual/03-first-workloads.md) walks through this
properly, and does the same for a VM.

## Documentation

- [The manual](docs/manual/README.md): concepts, installing, first
  workloads, containers, VMs, networking and egress, secrets, security,
  operating, troubleshooting, and reference
- [CLI reference](docs/cli.md) and [schema reference](docs/schema-reference.toml)
- [Design decisions](docs/adr/README.md): the ADRs
- [Developer guide](docs/dev/boot-and-generation.md): how the pieces are wired

## Development

```bash
just test       # the unit suite; MOATERY_CHECKOUT=../moatery without the moatery RPM
just lint
just rpm-build
```

Scripts run against the system `python3`, and `lib/` has no third-party
dependencies beyond moatery. [Testing](docs/dev/testing.md) describes how the
suite is organised.

## License

MIT; see [LICENSE](LICENSE).
