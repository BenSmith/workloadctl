# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**workloadctl** — a standalone, RPM-packaged Python tool that turns
`/etc/workloads.d/<name>/workload.toml` bundles into isolated rootless-podman
container workloads *and* KVM/QEMU VMs. It requires **moatery** (the egress
inspector, credential broker and DNS responder), published from its own Copr
project. The bootc hypervisor image (`BenSmith/bootc-hypervisor`) is one
consumer: it installs this package's RPM, but nothing here depends on it.

## Common commands

```bash
just test                 # all unit tests (unittest discover)
just test-unit            # fast subset (lib, generator, write-env, metrics)
just test-integration     # tests.test_integration only
just lint                 # py_compile syntax check of all scripts
just rpm-build            # the RPM, from a tarball of the working tree
just rpm-install          # build + dnf install/upgrade locally

# a single test module / case (no PYTHONPATH needed)
python3 -m unittest tests.test_workloads -v
python3 -m unittest tests.test_workloads.SomeClass.test_method

# the suite imports moatery: installed (its RPM), or a checkout named by
# MOATERY_CHECKOUT, whose libexec/ then stands in for /usr/libexec/moatery
MOATERY_CHECKOUT=../moatery just test
just moatery-rpm          # moatery's newest RPM from Copr, signature checked

# runtime rung (boots a harness-owned VM, runs runtime checks)
just test-runtime                      # WLRT_MODE=dev (default): Fedora Cloud image + local RPM
WLRT_MODE=gate just test-runtime       # gate: the hypervisor bootc image via bootc-image-builder + swtpm
                                       # both skip cleanly without /dev/kvm + QEMU
```

**Before adding or editing a check in `tests/manual/`, read that directory's
README preamble ("Writing a row here").** It is the accumulated list of ways a
rig row goes green while measuring nothing.

There is no Python package manager / venv — scripts run against the system
`python3` (3.14; Fedora 43 and 44 both ship it). `lib/` has no third-party
deps; everything is stdlib + `tomllib`.

`lib/` is a flat set of top-level modules, not a package. On a host the RPM
installs every entrypoint (the CLI, generator, and libexec helpers) *into*
`/usr/libexec/workloadctl` alongside the modules, so each finds them via its
own `sys.path[0]`. The CLI reaches PATH through a thin `%{_bindir}/workloadctl`
exec wrapper into that private dir. In the test suite, `tests/__init__.py`
puts `lib/` on `sys.path` (and provides `load_script()` for the extension-less
entrypoints and `script_env()` for subprocess launches). Nothing under `bin/`,
`lib/`, `libexec/` or `generators/` touches `sys.path`.

## Architecture

The hard-won design rationale lives in `llms.txt` and `docs/` — read those before changing boot/generator/secret behavior. Key points:

- **Boot flow is split deliberately.** A tiny *shell* systemd generator (`generators/workload-generator`) emits one oneshot, `workload-generate.service`, which runs the *Python* `generators/workload-generate` during early boot (`After=sysinit.target Before=basic.target`) to write sysusers configs + per-workload unit files into `/run/systemd/system/`. Python is kept out of generator context on purpose — generators must be fast/minimal and Python import overhead blows the systemd 258+ budget. Both layers always exit 0 so a failure never blocks boot. The generate step is read-only w.r.t. `/var`.
- **All `/var` work is deferred** to `libexec/workload-ensure-user`, run as `ExecStartPre` of each workload service (subuid/subgid ranges, home + volume dirs, EnvironmentFile, linger).
- **One dedicated locked-down system user per workload** (`_wl-<name>`, UID 10000+, `/usr/sbin/nologin`), each with its own rootless podman instance. No privileged containers.
- **Default service type is `Type=exec`.** `Type=notify`/`--sdnotify=conmon` is broken when linger is active (conmon migrates cgroups and the `READY=1` is dropped) — don't switch the default. See the comment block on `_base_run_args` in `lib/container_run_args.py`.
- **`lib/podman.py`** is the typed podman wrapper: it parses `podman inspect --format=json` into structured data. Use it rather than shelling out with go-template format strings.
- **Reading workload container logs:** units run `--log-driver=passthrough`, so `podman logs` fails (`cannot read logs: this container is not logging output`). Use `workloadctl logs <name>` — it wraps journalctl OR-ing `_SYSTEMD_UNIT=`/`UNIT=` with `SYSLOG_IDENTIFIER=`, because journald attributes passthrough app output to the rootless user manager's cgroup (`user@<uid>.service`), not the workload unit — a unit-only filter shows just systemd's start/stop lines. Raw per-container output: `journalctl -t workload-<name>-<container>` (add `-f` to tail).

### Code layout

- `bin/workloadctl` — the CLI (argparse). One `cmd_<name>(args, manager)` function per subcommand, wired up in `main()`. Mutating commands call `require_root()`.
- `lib/workloadctl_core.py` — `WorkloadConfig` / `WorkloadManager`. `lib/workload_lib.py` — TOML loading, paths, naming; `lib/workload_uid.py` — uid allocation and subid math; `lib/run_files.py` — the per-workload run-file list. VM-specific constants live in `lib/vm_defs.py`, and the uid-derived addresses in `lib/workload_addr.py`.
- `generators/`, `libexec/` — boot-time and helper scripts (also the `workload-vm-*` VM helpers and `workload-exporter` for Prometheus metrics). The egress inspector, the credential broker and the DNS responder are not here: they are moatery's programs (`/usr/libexec/moatery/`), a package the spec requires — see below.
- `workloads/<name>/` — the shipped bundles. Each is a directory with `workload.toml` at minimum, plus optional extras it needs: a `Containerfile` for self-built images, `README.md`, `cloud-init/`, additional unit files. `docs/schema-reference.toml` is the annotated full schema.
- `tests/` — `test_*.py` unittest modules.

### Workload topologies

`workload.mode` selects how a TOML maps to units: `single` (one `[container]`), `pod` (multiple `[[containers]]` sharing a netns, talk on localhost), `bridge` (per-container netns on an auto-created `workload-<name>-net`, resolve by container name). The generator's `normalize_containers()` collapses single/multi shapes so single-container TOMLs produce byte-identical units. Container-targeted CLI commands accept `<workload>/<container>`. `workloads/webproxy-demo/` is the smallest bridge-mode example.

### VM workloads

A TOML with a `[vm]` section (mutually exclusive with `[container]`/`[[containers]]`) runs as raw QEMU/KVM instead of a container — UEFI/OVMF, split `system.qcow2`/`data.qcow2` with generational rollback (`system.qcow2.gen-N`), virtiofs volumes, cloud-init seed, per-workload SSH key. CLI VM paths use SSH/QMP (`_vm_*` helpers, `libexec/workload-vm-*`) instead of podman. `workloads/forgejo-runner/` is the live example; see `docs/schema-reference.toml` `[vm]` section.

Networking is **passt, not a bridge** (ADR 006, `docs/adr/006-vm-networking-passt-not-managed-bridge.md`). There is no `_workload-br`, no `workload-bridge.service` and no dnsmasq of ours — passt terminates the guest's stack in userspace and re-originates its traffic as host sockets owned by `_wl-<name>`, which is what makes the workload uid an unforgeable selector for `meta skuid` egress policy. Consequences that catch people out: the guest has **no LAN identity of its own** (it is assigned the host's address), `workloadctl exec`/`shell` reach it on a uid-derived management address (`127.128.x.y:2222`, never routable, never configurable), and inbound otherwise needs an explicit `[vm.network].ports`. `[vm.network].bridge` is an escape hatch for a VM that needs a real LAN address; the operator provisions that bridge, workloadctl does not.

Virtiofs volumes have their own design doc, `docs/vm-virtiofs.md` — every guest id squashes to the workload user on the host, the sidecar runs unprivileged with an empty capability bounding set, and the unit must never gain `NoNewPrivileges=` (it breaks the SELinux domain transition and fails with a bare `203/EXEC`).

### The credential broker

The broker holds a provider API key that a sandboxed workload -- a
coding-agent VM or a filtered container -- is never given, and attaches it to
outbound requests that workload makes through it.
It is moatery's `moat-broker`, shipped by the moatery RPM beside the egress
inspector, `moat-inspect`; workloadctl's spec requires it, its units run
both from `/usr/libexec/moatery/`, and it imports the modules it needs from
the `moatery` package. The generator side is `lib/broker_config.py` (which
workloads get an instance, and `broker_command`, the argv the unit carries).
Callers are identified by the uid owning the far end of the connection,
compared to the one uid the instance was started for.

**One instance per workload, and the workload is never told where it is.**
One mechanism on both substrates: a VM declaring `[[vm.network.credential]]`
and a container declaring `[[network.credential]]` get the same generated
unit, the same command line and the same binary. A declaring workload
gets `workload-<name>-broker.service` — written by the generator, `DynamicUser=yes`,
bound to `broker_listen_address(uid)` (`127.129.0.0` + the uid offset), and
told everything else on its `ExecStart=`: `--name`, `--listen`, `--caller-uid`,
one `--host HOST=CREDENTIAL` per credentialed policy entry, and each
credential's `--placeholder`/`--auth-header`/`--auth-format`. There is no
config file, no `ExecStartPre` and no TOML in the broker's process
(moatery's closure test; `tests/test_moatery_seam.py` holds the command to the
program's flags).
Its only caller is that workload's own egress inspector, which recognises a
host whose policy entry names a `credential` and sends that request to the
broker instead of to the origin. So a workload cannot name the broker, cannot
choose to use it, and cannot be pointed at another workload's.
`tests/test_broker.py` covers the generator half and the seam.

There was a host-wide `agent-broker.service` reached by every guest at an
advertised `192.0.2.1:8081` through a uid-keyed nft map. All of it is deleted —
the unit, the map, the skeleton, `WORKLOAD_BROKER_URL`, and `[vm.network].broker`,
which is now a validation error naming `credential` as the replacement. Design,
threat model and operating instructions: `docs/agent-broker.md`.

**The end-to-end seam is proven for this shape, and it took five fixes to get
there.** The rig that proved the old shape (`broker_rig.py`, 18/18 on
2026-08-14) was built around the advertised endpoint and was deleted with it;
its replacement runs on two throwaway workloads and was 35/35 on a KVM host
under enforcing on 2026-09-02. Every defect it found had passed the whole unit
suite, and two of them made the brokered path inert on a real guest: the
terminated session seeded the upstream pool with the ORIGIN connection, so a
brokered request was handed that socket and the broker was never dialled; and
the broker's own 127.129.x.y address is inside `wl_internal4`, so once it WAS
dialled the packet was dropped by the rule that stops a guest reaching the LAN.
The other three: the generated config could not name a provider's
`auth_header`/`auth_format`, so any provider wanting `Authorization: Bearer`
got a 401 on a fully authorised request; two policy entries for one host
rendered a `broker.toml` TOML refused; and a brokered host was dialled at the
origin and never written to, making the origin's reachability a prerequisite
for a request that goes to loopback. None is visible without a real packet
([[unit-gates-dont-see-the-seam]]). See `tests/manual/README.md`.

**The container shape is proven too, and it cost a sixth fix of the same
kind.** `container_egress_rig.py` grew a broker arm -- 19/19 inside a 123/123
run on a bare-metal host under enforcing on 2026-09-06, ending in a real
request that left a container holding a placeholder and reached the provider
carrying the sealed key. The defect it found was that NOTHING STARTED THE
BROKER: the unit was generated, ordered ahead of the right unit, given its
`IPAddressAllow=` and its internal-set exemption, and pulled in by nothing.
`Before=` orders a unit; it does not start one. Forty-five unit rows passed
with it in place because each of them reads the broker unit's own text and the
missing half lived in a different unit.

## Docs policy: tracked files may not cite untracked docs

A citation has to be followable from a clean checkout. `docs/wip/` is
gitignored, so nothing tracked may point into it — and don't cite a doc you
intend to write later; write it, or state the fact inline instead.
`tests/test_doc_citations.py` enforces this repo-wide and runs in the normal
`just test`. A doc in another repository is cited by URL.

## Releasing

`VERSION` and the spec's `Version:` move together (a unit test holds them
equal). Commit, tag `vX.Y.Z` (annotated), push main and the tag, then publish
a GitHub *release* for the tag: Packit builds the RPM in the Copr project
`benjamin-coder-smith/workloadctl` on a release, not on a bare tag. Pull
requests get a Copr test build. `just rpm-build` builds the way Copr does,
from a `git archive` of the working tree. `packit srpm` builds the source RPM
Copr would, and rewrites `rpm/workloadctl.spec` in place (Release, Source0,
`%autosetup -n`, a changelog entry): restore it before committing.

## CI

- `.github/workflows/test.yml` — **PR gate**: lint + `just test` in a Fedora
  container with moatery from Copr, as a non-root user. No VM, no secrets.
- `.forgejo/workflows/test.yml` — the same suite plus an RPM build on the
  Forgejo `native` runner, against main's moatery from the forge's RPM
  registry (`.forgejo/scripts/forge-moatery-rpm`, signature checked against
  `.forgejo/rpm-registry.gpg`). A push to main publishes the RPMs to the forge's
  RPM registry (the `PKG_PUBLISH_TOKEN` secret, a token with package write
  access), which the homelab's hypervisor images install from. A clean
  checkout's RPM names its commit in the `VCS` tag.
- `.forgejo/workflows/runtime-dev.yml` — **cadence gate**: `just
  test-runtime` in `dev` mode (this checkout's RPM in a Fedora Cloud VM,
  beside main's moatery from the forge's RPM registry),
  weekly (Tue 03:00) and on dispatch; skips cleanly without `/dev/kvm`.
- The `gate` mode, against the shipped hypervisor image, is the hypervisor
  repository's CI (its `runtime-gate.yml`, Tue 11:00 UTC), which checks this
  repository out at the release the image pins. It shares the runner with
  `runtime-dev.yml`, and the two can run side by side: `reap_stale_runs`
  leaves a run whose harness is alive.
- `.forgejo/workflows/build-workload-images.yml` — the self-built bundles'
  images: built with `lib/imagebuild.py` (`.forgejo/scripts/ci-workload-images.py`),
  scanned by grype (a fixable critical not accepted in
  `.forgejo/cve-allowlist.txt` stops the push), pushed to
  `registry.local/workloads/<name>` and signed with the runner's sealed key
  (the hypervisor repository's `seal-signing-key.yml` seals it;
  `.forgejo/cosign.pub` is its public half, and must change with it). On a
  push to main it rebuilds the bundles that changed; every bundle weekly (Sun
  03:00 UTC) and on dispatch. Its helpers' tests run in it, not in `just
  test`: importing the helper repoints the bundle paths at module scope.
- `.forgejo/workflows/scan-images.yml` — report-only daily grype scan (12:00
  UTC) of every image the bundles run, upstream ones included.
