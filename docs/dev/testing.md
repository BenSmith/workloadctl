# Testing

The standard this suite is held to, and how to decide what a new test should
look like. Cite this page when adding or reviewing tests.

## The rung model

| Rung | Proves | Fails when | Where it runs |
|---|---|---|---|
| 1, logic | parsing, UIDs, tags, volumes, secrets, quoting, run-file sets | a logic bug | `just test-unit`, in-process |
| 2, generation | the generator writes the right unit text | an intended change, or a bug | `just test`, in-process |
| 3, runtime | the unit boots and the workload runs | podman, systemd or pasta changed underneath | `just test-runtime`, in a VM the harness owns (`--target=vm:dev\|gate`) |

Rung 2 is the cheapest to write and the easiest to over-populate. It holds
the most tests and the least value per test, because most rung-2 assertions
prove only that a string did not change, not that it is right.

Rung 3 catches the world moving under the tool: a Fedora update to systemd,
podman or pasta that breaks an invariant such as cgroup placement or the
stale-pause cleanup. Its checks are the `runtime`-marked
`tests/cli_surface/test_runtime_*.py`, which boot a fresh VM the harness
owns, in **dev** mode (a cached Fedora Cloud image and the local RPM) or
**gate** mode (the real bootc image under swtpm). The guest is thrown away
after each run, which is what keeps these checks honest: they run tight
enable and purge sequences that would trip over state a long-lived host
keeps, such as recycled UIDs and stale runtime directories.

Know which rung a new test proves, and do not let rung 2 stand in for
rung 3.

`tests/manual/` is outside the model. Its checks need root and boot VMs of
their own, so nothing automatic runs them; see that directory's README. They
are not a fourth rung but an admission that the rung-3 harness cannot reach
everything: `inspect_rig.py` drives a real guest through nftables and a
real inspector under enforcing SELinux. Write one only when a harness-owned
VM cannot prove the property, and record when it last ran, because nothing
else notices it rotting.

## The deletion question

Before writing or keeping a test, ask what real bug reaches production if
the test is deleted.

- If you can name one (a wrong UID, a missing `ExecStartPre`, a secret on
  `/proc/*/cmdline`), the test is a **contract** and earns its place.
- If the honest answer is that an intended edit would pass without updating
  the assertion, the test is a **change detector**. It protects the current
  wording of the generator's output, not a behaviour anyone relies on, and
  is a candidate for deletion or for folding into a structural oracle.
- A test that a warning fires for a configuration mistake is a contract,
  even though it checks a string: the warning is the behaviour the operator
  depends on.

When in doubt, keep it. One extra assertion costs little; losing real
coverage without noticing costs more.

## Contract, oracle and snapshot

Three shapes of assertion, for three jobs:

- A **contract test** asserts one documented behaviour that an operator or
  another part of the system relies on, such as "`userns = "host"` emits a
  warning" or "a `[vm]` configuration never emits `[container]`
  directives". Write these by hand, one per behaviour.
- A **structural oracle** is one parametrised test that checks shape across
  a matrix of configurations: the unit parses as systemd, has the required
  sections, and carries no generator-owned directive the configuration did
  not ask for. It replaces a pile of near-identical `assertIn` change
  detectors with one assertion that still catches the same class of bug,
  without breaking on every change of wording.
- A **snapshot test** pins exact output for a small, chosen set of
  configurations. Use it only where the literal text is what is under test,
  such as locking in a specific fix. It is the most brittle of the three and
  the easiest to accumulate as change-detector mass.

Reach for a contract or an oracle by default.

### Render a baseline instead of committing units

Byte-for-byte renderings of the shipped bundles do not belong in the tree.
The output is regenerable in a fraction of a second, byte for byte, from the
same TOMLs, so committing it buys nothing a command cannot. And an
exhaustive corpus goes stale if it only warns on drift, or turns every
intended generator change into a two-step ritual if it fails on drift.

What such a corpus is for, making a large generator refactor reviewable,
needs nothing committed, because a baseline renders at any commit:

```bash
just snapshot-baseline /tmp/before     # on the commit before the refactor
# ...refactor...
just snapshot-baseline /tmp/after
diff -ru /tmp/before/units /tmp/after/units
```

`normalize_baseline` in `tests/test_shipped_bundles.py` masks the allocated
UID, the render directory and the configuration directory, so two baselines
differ only where behaviour does, wherever they were rendered.

The shipped bundles still get a test, `tests/test_shipped_bundles.py`, which
asserts existence rather than text: the generator exits 0 with every bundle
enabled at once, and each bundle gets its sysusers file and every unit its
mode implies. It is the only test that runs the generator over the real
bundles. The fixture matrix in `test_generator_snapshot.py` is synthetic, so
it cannot catch a shipped TOML that crashes the generator or drops a
per-container unit.

Unit shape is held by the structural oracle, `test_unit_oracle.py`, and
`test_generator_snapshot.py` passes every fixture through `systemd-analyze
verify`. Neither commits golden files.

## Ground rules

- **Stdlib only for shipped code.** `lib/`, `bin/`, `generators/`,
  `libexec/` and the `unittest` suites under `tests/` depend on the standard
  library and moatery, and nothing else. The acceptance harness in
  `tests/cli_surface/` is the one exception: it is pytest, because it never
  ships in the RPM.
- **No GPU or TPM assumed.** The suite must pass on a plain development
  machine. Gate an assertion that needs hardware behind a capability check
  (`shutil.which`, `/dev/kvm`, a TPM2) and skip cleanly when it is absent.
