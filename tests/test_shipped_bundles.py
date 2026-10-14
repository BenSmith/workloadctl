#!/usr/bin/env python3
"""The generator handles every shipped bundle: exits clean, emits every unit.

This is the only test that runs the generator over the *real* `workloads/`
bundles rather than synthetic fixtures. `test_generator_snapshot.py`'s 20-fixture
matrix covers the topology axes deliberately and gates on `systemd-analyze
verify`, but a fixture matrix cannot catch a shipped TOML that crashes the
generator or silently drops a per-container unit — only the shipped TOMLs can.

What it asserts, all shipped bundles in one generator invocation:

  - the generator exits 0 with every bundle enabled at once (so a cross-workload
    branch — `requires`/`after` resolution, UID allocation across 30+ workloads —
    is exercised, not just one config at a time);
  - each bundle gets its sysusers `workload-<name>.conf`;
  - each bundle gets every unit its mode implies (main, setup, pod/net head,
    per-container members).

Deliberately *not* asserted: the unit text. Rendered units are not committed —
they regenerate from these TOMLs in ~0.2s, so a refactor diffs two baselines from
`just snapshot-baseline` instead. See `docs/testing.md`.

The generator allocates UIDs by scanning /etc/passwd, so its output is
host-dependent; nothing here depends on the allocated value.
"""
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from tests import REPO_ROOT as ROOT, script_env

GENERATOR = ROOT / "generators" / "workload-generate"
WORKLOADS_DIR = ROOT / "workloads"

from config_parser import infer_workload_mode
from workload_lib import normalize_containers  # noqa: E402
from workload_seccomp import (  # noqa: E402
    ARCH_X86_64, SUBARCHES_32BIT, derived_profile_name,
)


def expected_units(stem: str, toml_text: str) -> list[str]:
    """Unit file names the generator must emit for one workload.

    Mode drives the set: every workload gets a main + setup unit; pod and bridge
    additionally get a head unit and one unit per container.
    """
    config = tomllib.loads(toml_text)
    mode = infer_workload_mode(config)
    units = [f"workload-{stem}.service", f"workload-{stem}-setup.service"]
    if mode == "pod":
        units.append(f"workload-{stem}-pod.service")
    elif mode == "bridge":
        units.append(f"workload-{stem}-net.service")
    if mode != "single":
        units += [
            f"workload-{stem}-{c['name']}.service"
            for c in normalize_containers(config)
        ]
    return units


def generate_all(dest: Path) -> tuple[list[Path], Path, Path]:
    """Run the generator over every shipped bundle into `dest`.

    Returns (bundle TOML paths, sysusers dir, config dir). `dest` receives the
    units.
    """
    cfg = dest.parent / "cfg"
    sys_d = dest.parent / "sys"
    cfg.mkdir(exist_ok=True)
    sys_d.mkdir(exist_ok=True)

    tomls = sorted(WORKLOADS_DIR.glob("*/workload.toml"))
    for src in tomls:
        inst = cfg / src.parent.name
        inst.mkdir(exist_ok=True)
        (inst / "workload.toml").write_text(src.read_text())
        # The generator skips a workload without this marker.
        (inst / ".enabled").touch()

    env = script_env(WORKLOAD_CONFIG_DIR=cfg, SYSUSERS_DIR=sys_d)
    # Pin GPU auto-resolution: the generator otherwise reads the host's PCI
    # vendor IDs, so `gpu = "auto"` bundles would behave differently on an NVIDIA
    # dev box than on a GPU-less CI runner. NVIDIA is the deployment target.
    env["WORKLOAD_GPU_OVERRIDE"] = "nvidia"
    r = subprocess.run(
        [sys.executable, str(GENERATOR), str(dest)],
        capture_output=True, text=True, env=env,
    )
    if r.returncode != 0:
        raise AssertionError(
            f"generator exited {r.returncode} over the shipped bundles:\n{r.stderr}"
        )
    return tomls, sys_d, cfg


# sysusers 'u' line: `u <name> <uid> "<gecos>" <home>`
_SYSUSERS_UID_RE = re.compile(r'^u\s+\S+\s+(\d+)\s', re.M)


def normalize_baseline(units_dir: Path, sys_dir: Path, cfg_dir: Path) -> int:
    """Rewrite a rendered baseline in place so two renders are comparable.

    Masks the three things that differ between renders without any behavior
    differing, all of which the diff would otherwise be swamped by:

    - **the allocated UID** → ``__UID__``. The generator picks UIDs by scanning
      /etc/passwd for free slots, so the value reaches the sysusers conf,
      ``ReadWritePaths=…/run/user/<uid>``, and ``--uidmap/--gidmap @<uid>``. It
      shifts whenever the workload set or the host's user table changes — i.e.
      exactly when you are taking two baselines.
    - **the render dir** → ``__SVCDIR__``. The setup unit's ``systemd-sysusers``
      ExecStart names an absolute path under it, so baselines taken into two
      different directories differ on that line in every workload.
    - **the config dir** → ``__CFGDIR__``, which a ``${WORKLOAD_INSTANCE_DIR}``
      token in ``security_opt`` expands to.

    Returns the number of files rewritten.
    """
    subs: list[tuple[re.Pattern, str]] = [
        (re.compile(re.escape(str(units_dir))), "__SVCDIR__"),
        (re.compile(re.escape(str(cfg_dir))), "__CFGDIR__"),
    ]
    for conf in sorted(sys_dir.glob("workload-*.conf")):
        m = _SYSUSERS_UID_RE.search(conf.read_text())
        if m:  # range-form allocation carries no literal UID
            subs.append(
                (re.compile(rf'(?<!\d){re.escape(m.group(1))}(?!\d)'), "__UID__")
            )

    touched = 0
    for path in sorted([*units_dir.glob("*.service"), *sys_dir.glob("*.conf")]):
        text = original = path.read_text()
        for pat, repl in subs:
            text = pat.sub(repl, text)
        if text != original:
            path.write_text(text)
            touched += 1
    return touched


class TestShippedBundlesGenerate(unittest.TestCase):
    def test_every_bundle_generates_its_full_unit_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            tomls, sys_d, _ = generate_all(svc)
            self.assertGreater(len(tomls), 0, "no workload TOMLs found")

            for src in tomls:
                stem = src.parent.name
                with self.subTest(workload=stem):
                    conf = sys_d / f"workload-{stem}.conf"
                    self.assertTrue(
                        conf.is_file(),
                        f"no sysusers config emitted for {stem}",
                    )
                    for unit in expected_units(stem, src.read_text()):
                        self.assertTrue(
                            (svc / unit).is_file(),
                            f"generator did not emit {unit} for {stem}",
                        )


class TestShippedBundlesMapEachHostIdOnce(unittest.TestCase):
    """A host id takes one container id; podman keeps the last map naming
    it. The desktops once mapped container root and uid 1000 both onto the
    workload's uid, and uid 1000 silently became a subordinate id (audit
    F6)."""

    def test_no_unit_maps_a_host_id_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            generate_all(svc)
            units = sorted(svc.glob("*.service"))
            self.assertGreater(len(units), 0)
            for unit in units:
                for line in unit.read_text().splitlines():
                    for kind in ("uid", "gid"):
                        hosts = re.findall(
                            rf"--{kind}map \+?\d+:@?(\d+):1\b", line)
                        with self.subTest(unit=unit.name, kind=kind):
                            self.assertEqual(
                                len(hosts), len(set(hosts)), line)


class TestShippedServicesAskForALogin(unittest.TestCase):
    """A shipped service that serves anything to whoever reaches it is a
    finding, not a default.

    The 2026-10-11 security audit (F32): otel-lgtm's Grafana, on a port the
    bundle tells the operator to open to the LAN, served every host's logs
    with no login, because the grafana/otel-lgtm image enables anonymous
    access and the bundle did not turn it off. Checked in the rendered unit,
    where the setting has to arrive to mean anything.
    """

    def test_otel_lgtm_grafana_is_not_anonymous(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            generate_all(svc)
            unit = (svc / "workload-otel-lgtm.service").read_text()
        self.assertRegex(unit, r'GF_AUTH_ANONYMOUS_ENABLED="?false"?(\s|$)')

    def test_caddy_admin_api_is_off_the_host_loopback(self):
        """Audit F10: caddy runs on the host network, so its default admin
        listener, localhost:2019, is the host's loopback, where every
        host-network workload could load a new config. Checked 2026-10-11
        with the bundle's own image: with CADDY_ADMIN on a unix socket,
        TCP 2019 is refused and `caddy reload` still works."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            generate_all(svc)
            unit = (svc / "workload-caddy.service").read_text()
        self.assertRegex(unit, r'CADDY_ADMIN="?unix//')


class TestTheHostJournalSocket(unittest.TestCase):
    """A container given the host's journal socket writes entries under any
    identifier, at any priority (audit F13, measured 2026-10-11); journald
    still stamps the sender's uid and unit. The bundles that run systemd as
    PID 1 forward their own journal there and keep it; the rest log to
    stdout, where the journal names the container."""

    @staticmethod
    def _volumes(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "volumes" and isinstance(value, list):
                    yield from value
                else:
                    yield from TestTheHostJournalSocket._volumes(value)
        elif isinstance(node, list):
            for value in node:
                yield from TestTheHostJournalSocket._volumes(value)

    def test_only_a_bundle_forwarding_its_own_journal_mounts_it(self):
        mounting = []
        for toml_path in sorted(WORKLOADS_DIR.glob("*/workload.toml")):
            config = tomllib.loads(toml_path.read_text())
            for volume in self._volumes(config):
                source, _, rest = volume.partition(":")
                if source != "/run/systemd/journal/socket":
                    continue
                bundle = toml_path.parent
                mounting.append(bundle.name)
                target = rest.split(":")[0]
                containerfile = bundle / "Containerfile"
                with self.subTest(bundle=bundle.name):
                    self.assertTrue(containerfile.exists())
                    self.assertIn(f"ForwardToSocket={target}",
                                  containerfile.read_text())
        self.assertGreater(len(mounting), 0)

    def test_smb_server_logs_to_stdout(self):
        bundle = WORKLOADS_DIR / "smb-server"
        self.assertRegex((bundle / "entrypoint.sh").read_text(),
                         r"exec smbd .*--debug-stdout")
        self.assertNotRegex((bundle / "smb.conf").read_text(),
                            r"(?m)^\s*logging\s*=\s*systemd")

    def test_alloy_labels_an_entry_with_its_unit_and_uid(self):
        """Checked 2026-10-14 with the bundle's image: an entry a rootless
        container sent as sshd arrived labelled with its uid and
        user@<uid>.service; without the rules, with neither."""
        text = (WORKLOADS_DIR / "alloy" / "alloy-config.alloy").read_text()
        source = re.search(r'loki\.source\.journal "system" \{(.*?)\n\}',
                           text, re.S)
        self.assertIsNotNone(source)
        rules = re.search(
            r"relabel_rules\s*=\s*loki\.relabel\.(\w+)\.rules",
            source.group(1))
        self.assertIsNotNone(rules)
        relabel = re.search(
            rf'loki\.relabel "{rules.group(1)}" \{{(.*?)\n\}}', text, re.S)
        self.assertIsNotNone(relabel)
        for field, label in (("__journal__systemd_unit", "unit"),
                             ("__journal__uid", "uid")):
            with self.subTest(field=field):
                self.assertRegex(
                    relabel.group(1),
                    rf'source_labels = \["{field}"\]\s*'
                    rf'target_label\s*=\s*"{label}"')


class TestTheSteamBundlesOptOutOfTheBaseline(unittest.TestCase):
    """Steam's client is a 32-bit program, and its runtime starts games in
    bwrap. The baseline kills a 32-bit syscall and refuses bwrap's mounts
    and namespaces, so a Steam bundle that lost either opt-in would generate
    and start, and then lose Steam at run time, with nothing else in the
    suite failing. Checked in the rendered profile and unit, where the
    opt-ins have to arrive."""

    BUNDLES = ("sunshine-streaming", "wolf-game-streaming")
    BWRAP = {"clone", "mount", "pivot_root", "umount2", "unshare"}

    def test_each_runs_32bit_code_and_bwrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = Path(tmp) / "svc"
            svc.mkdir()
            generate_all(svc)
            for name in self.BUNDLES:
                with self.subTest(name=name):
                    profile_name = derived_profile_name(name)
                    profile = json.loads((svc / profile_name).read_text())
                    subarches = {a["architecture"]: a["subArchitectures"]
                                 for a in profile["archMap"]}
                    self.assertEqual(subarches[ARCH_X86_64], SUBARCHES_32BIT)
                    allowed = {n for e in profile["syscalls"]
                               if e["action"] == "SCMP_ACT_ALLOW"
                               and not e.get("args") and not e.get("includes")
                               for n in e["names"]}
                    self.assertLessEqual(self.BWRAP, allowed)
                    unit = (svc / f"workload-{name}.service").read_text()
                    self.assertIn("seccomp=", unit)
                    self.assertIn(profile_name, unit)


class TestBaselineIsComparable(unittest.TestCase):
    """`just snapshot-baseline` is only useful if two renders differ *only* where
    behavior differs — otherwise a refactor diff drowns in noise and stops being
    read, which is the failure mode that removing the committed fixtures was meant
    to avoid. Nothing else covers `normalize_baseline`, so this is what keeps it
    honest when the generator learns to emit a new host-dependent value.
    """

    def _render(self, root: Path) -> dict[str, str]:
        units = root / "units"
        units.mkdir(parents=True)
        _, sys_d, cfg = generate_all(units)
        masked = normalize_baseline(units, sys_d, cfg)
        self.assertGreater(masked, 0, "normalize_baseline rewrote nothing")
        return {
            p.name: p.read_text()
            for p in [*units.glob("*.service"), *sys_d.glob("*.conf")]
        }

    def test_two_renders_in_different_dirs_are_identical(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = self._render(Path(a))
            second = self._render(Path(b))

        self.assertEqual(
            sorted(first), sorted(second), "renders disagree on which files exist"
        )
        differing = [name for name in first if first[name] != second[name]]
        self.assertEqual(
            differing, [],
            "these files differ between two renders of identical input, so "
            f"normalize_baseline is missing a host-dependent value: {differing[:5]}",
        )

    def test_normalized_baseline_names_no_local_path(self):
        """No baseline text may name this checkout or this tmp dir.

        Distinct from the comparison above, which only catches values that differ
        *between* two renders on one machine. A path that is stable locally — the
        checkout root, embedded because someone resolved a bundle path against the
        source tree — compares clean here and still makes a baseline untransferable
        between machines or worktrees. The masked tokens are the whole point: what
        is left should be the units as a host would see them.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered = self._render(root)

        for local, label in ((str(ROOT), "checkout root"), (tmp, "tmp dir")):
            # Anchored, so a checkout at e.g. /workloadctl doesn't match the
            # substring inside /usr/libexec/workloadctl: an occurrence preceded
            # by a path character is a different path that merely ends the same.
            ref = re.compile(rf'(?<![\w.\-/]){re.escape(local)}(?![\w.\-])')
            offenders = sorted(n for n, t in rendered.items() if ref.search(t))
            self.assertEqual(
                offenders, [],
                f"{label} {local} survives normalization in: {offenders[:5]}",
            )


if __name__ == "__main__":
    unittest.main()
