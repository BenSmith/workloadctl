# CLAUDE.md

workloadctl turns `/etc/workloads.d/<name>/workload.toml` bundles into
rootless-podman containers and KVM/QEMU VMs, with one locked-down
`_wl-<name>` user per workload. It is stdlib Python, packaged as an RPM. It
requires moatery, whose programs (`moat-inspect`, `moat-broker` and
`moat-resolve`, in `/usr/libexec/moatery/`) its units run.

`llms.txt` maps the docs. Before changing boot, generator, egress or VM
behaviour, read the matching `docs/dev/` guide and ADR. User-facing
behaviour is documented in `docs/manual/`; keep it true when you change it.

## Commands

```bash
just test                 # all unit tests
just test-unit            # fast subset
just lint                 # py_compile every script
just rpm-build            # the RPM, from a git archive of the working tree
python3 -m unittest tests.test_workloads.SomeClass.test_method

# without the moatery RPM installed, name a checkout
MOATERY_CHECKOUT=../moatery just test

just test-runtime                  # boots a VM (dev mode); skips without /dev/kvm
WLRT_MODE=gate just test-runtime   # against the hypervisor bootc image
```

Before adding or editing a check in `tests/manual/`, read that README's
"Writing a row here".

## Layout

- `bin/workloadctl` is a `main()` over `lib/cli_main.py`; each verb is
  `lib/cmd_<verb>.py`. Mutating verbs require root.
- `lib/` is flat modules, not a package. The RPM installs every entrypoint
  into `/usr/libexec/workloadctl` beside them; `tests/__init__.py` puts
  `lib/` on `sys.path` (`load_script()`, `script_env()`). Nothing under
  `bin/`, `lib/`, `libexec/` or `generators/` touches `sys.path`.
- `generators/` and `libexec/` hold `main()` shims over `lib/` modules.
- `workloads/<name>/` holds the shipped bundles; the annotated schema is
  `docs/schema-reference.toml`.

## Rules the code doesn't show

- Python never runs in generator context, both generator layers exit 0, and
  generation never writes `/var`.
- `Type=exec` stays the default: `Type=notify` can't work under rootless +
  linger (ADR 001).
- Only `bin/workloadctl` and `lib/cmd_*.py` may `sys.exit`
  (`tests/test_layering.py`).
- Use `lib/podman.py` (inspect JSON), not go-template format strings.
- Units log with `--log-driver=passthrough`, so `podman logs` fails. Use
  `workloadctl logs <name>` or `journalctl -t workload-<name>-<container>`.
- VM networking is passt, not a bridge (ADR 006). A guest has no LAN
  identity; `exec` reaches it at `127.128.x.y:2222`.
- No unit that transitions into an SELinux domain of ours may set
  `NoNewPrivileges=`.
- moatery's programs derive nothing: the generator writes every value onto
  `ExecStart=`. `tests/test_moatery_seam.py` holds workloadctl's side of
  that interface.
- Unit tests don't see the seam. Anything with more than one part needs a
  `tests/manual/` rig on a real host, under enforcing.
- Tracked files may not cite untracked docs (`docs/wip/` is gitignored);
  `tests/test_doc_citations.py` enforces it. Cite another repo's doc by URL.

## Releasing

`VERSION` and the spec's `Version:` move together (a test holds them
equal). A tag `vX.Y.Z` and a GitHub release make Packit build into Copr
`benjamin-coder-smith/workloadctl`. `packit srpm` rewrites
`rpm/workloadctl.spec` in place; restore it before committing.

## CI

- `.github/workflows/test.yml`: lint and `just test`, with moatery from
  Copr.
- `.forgejo/workflows/test.yml`: the same plus an RPM build, with main's
  moatery from the forge's RPM registry; a push to main publishes there.
- `.forgejo/workflows/runtime-dev.yml`: `just test-runtime` weekly. Gate
  mode runs in the hypervisor repository.
- `.forgejo/workflows/build-workload-images.yml` builds, scans, pushes and
  signs the self-built bundle images. Its helpers' tests run there, not in
  `just test`. `scan-images.yml` is a daily report-only scan.
