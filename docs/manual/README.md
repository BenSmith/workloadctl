# The workloadctl manual

> **Disclaimer:** This documentation and the software it describes are
> provided as-is, without warranty of fitness for any particular purpose.
> The implementation is largely AI-assisted. Validate behaviour against your
> own requirements before relying on it in production.

workloadctl turns a TOML file into a running service: a rootless container
or a KVM virtual machine, each under a system user of its own, started at
boot and managed with one set of commands. The manual is meant to be read in
order the first time; after that, each chapter stands on its own.

1. [Concepts](01-concepts.md): workloads, substrates, the per-workload user,
   bundles, and where everything lives.
2. [Installing](02-installing.md): packages, ports below 1024, upgrades,
   and bootc images.
3. [First workloads](03-first-workloads.md): a container and a VM, from
   configuration to removal.
4. [Container workloads](04-containers.md): images, environment, volumes,
   devices, health checks, resource limits, multi-container workloads, host
   setup scripts and building your own image.
5. [VM workloads](05-vms.md): image sources, disks and rollback, cloud-init,
   getting into the guest, shared directories and the guest's clock.
6. [Networking and egress](06-networking.md): the three VM stances,
   filtering by host name, DNS, TLS inspection, the credential broker, and
   reading what a filter did.
7. [Secrets](07-secrets.md): creating, using, rotating and moving secrets.
8. [Security and confinement](08-security.md): the threat model, user
   namespaces, capabilities, seccomp, SELinux and image trust.
9. [Operating](09-operating.md): day-to-day lifecycle, updates and
   rollback, backup and restore, logs, metrics and cleanup.
10. [Troubleshooting](10-troubleshooting.md): what you see, what causes it,
    and what to do.
11. [Reference](11-reference.md): every command, the files and units on a
    host, exit codes, variables, and the bundle catalogue.

Two references sit beside the manual: [the CLI reference](../cli.md) gives
every command's flags, and [the schema reference](../schema-reference.toml)
every TOML key.

## For maintainers

The developer guide describes the wiring the code cannot show in one place:
what starts what, who reads which file, and the path a request takes.

- [Boot and generation](../dev/boot-and-generation.md): how a TOML becomes
  units, the files a workload owns, the setup unit, and the CLI's layers.
- [The egress plane](../dev/egress.md): the inspector, responder and broker,
  the nftables objects they arm, and the path a request takes.
- [The VM runtime](../dev/vm-runtime.md): QEMU and passt, the runtime
  directory, the virtiofs sidecar, the clock keeper, disks and SELinux.
- [Testing](../dev/testing.md): the standard the test suite is held to.
- [CI and the image supply chain](../dev/ci.md): what this repository's CI
  does for the images the bundles run.
