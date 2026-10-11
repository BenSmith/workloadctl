#!/usr/bin/env python3
"""The shipped seccomp baseline, as an artifact.

Every non-privileged workload runs under this profile, so a malformed or
self-contradicting file breaks every container on the host at once — and it fails
at `podman run` time, far from the edit that caused it. Nothing else in the suite
looks at the file's contents. A workload's [security] seccomp_allow derives
a profile from it, and the same checks hold every derived one.
"""
import json
import re
import unittest

from tests import REPO_ROOT
from workload_seccomp import derived_profile

PROFILE = REPO_ROOT / "seccomp-workload-baseline.json"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"
TROUBLESHOOTING = REPO_ROOT.parent / "docs" / "TROUBLESHOOTING.md"
WORKLOADS = REPO_ROOT / "docs" / "workloads.md"

ENOSYS_TEXT = "Function not implemented"
EPERM_TEXT = "Operation not permitted"

# The futex2 syscalls. glibc currently probes and falls back to `futex` when
# these are denied, which is why blocking them was invisible; a release that
# stops falling back would turn it into an EPERM with no recovery.
FUTEX2 = {"futex_requeue", "futex_wait", "futex_waitv", "futex_wake"}

ALLOW = "allow"
EPERM, EINVAL, ENOSYS = 1, 22, 38
MASK64 = (1 << 64) - 1
# What a container holds when its workload adds none: podman's default.
PODMAN_CAPS = {f"CAP_{c}" for c in (
    "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE",
    "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT")}
CLONE_NEW = (0x00020000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
             0x20000000, 0x40000000)
CLONE_NEWTIME = 0x80
CLONE_THREAD = 0x10000
SIGCHLD = 17
AF_NETLINK, NETLINK_AUDIT, AF_VSOCK = 16, 9, 40
MOUNTS = ("fsconfig", "fsmount", "fsopen", "fspick", "mount",
          "mount_setattr", "move_mount", "open_tree", "open_tree_attr",
          "pivot_root", "umount", "umount2")


def _holds(cmp, args):
    value = args[cmp["index"]] & MASK64
    op = cmp["op"].removeprefix("SCMP_CMP_")
    if op == "MASKED_EQ":
        return value & cmp["value"] == cmp["valueTwo"]
    return {"EQ": value == cmp["value"], "NE": value != cmp["value"],
            "LT": value < cmp["value"], "LE": value <= cmp["value"],
            "GT": value > cmp["value"], "GE": value >= cmp["value"]}[op]


def _applies(entry, arch, caps):
    """Whether podman hands `entry` to the runtime: every capability it
    includes held, none it excludes, and the architecture's."""
    inc, exc = entry.get("includes") or {}, entry.get("excludes") or {}
    return (set(inc.get("caps", ())) <= caps
            and not set(exc.get("caps", ())) & caps
            and ("arches" not in inc or arch in inc["arches"])
            and arch not in exc.get("arches", ()))


def decide(profile, name, *args, arch="amd64", caps=PODMAN_CAPS):
    """What the filter does with the call: allowed, or the errno. Every
    entry that matches must agree: libseccomp does not choose between
    them by their order, and of two that overlap the one with fewer
    conditions wins."""
    args = (*args, *(0,) * (6 - len(args)))
    found = {ALLOW if e["action"] == "SCMP_ACT_ALLOW"
             else e.get("errnoRet", profile["defaultErrnoRet"])
             for e in profile["syscalls"]
             if name in e["names"] and _applies(e, arch, caps)
             and all(_holds(c, args) for c in e.get("args") or ())}
    if len(found) > 1:
        raise AssertionError(f"{name}{args[:3]}: entries disagree, {found}")
    return found.pop() if found else profile["defaultErrnoRet"]


# Arguments the filtered entries are tried with: namespace flags and not,
# upper bits, families and protocols around each block's edges.
CLONE_FLAGS = [0, SIGCHLD, CLONE_THREAD, *CLONE_NEW, CLONE_NEWTIME,
               sum(CLONE_NEW) | CLONE_NEWTIME, CLONE_THREAD | CLONE_NEW[4],
               (1 << 32) | CLONE_NEW[6], (1 << 32) | SIGCHLD]
FAMILIES = [*range(70), (1 << 32) | AF_VSOCK, (1 << 32) | 2,
            (1 << 63) | 1, MASK64]
PROTOCOLS = [*range(34), (1 << 32) | NETLINK_AUDIT, MASK64]


class ProfileChecks:
    """What every profile a workload runs under must hold: the baseline, and
    each derived from it by [security] seccomp_allow."""

    def _entries(self, action):
        return [s for s in self.profile["syscalls"] if s["action"] == action]

    def _ungated_allow_names(self):
        """Names allowed unconditionally — no includes/excludes gating, no
        argument filter.

        A name allowed only under `includes` (a capability, an arch) is not
        allowed for an ordinary workload, so gated entries cannot be treated as
        equivalent to a plain allow; nor can one allowed for some arguments.
        """
        names = set()
        for s in self._entries("SCMP_ACT_ALLOW"):
            if not s.get("includes") and not s.get("excludes") \
                    and not s.get("args"):
                names.update(s["names"])
        return names

    def test_profile_is_valid_json_with_the_expected_shape(self):
        self.assertEqual(self.profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertTrue(self.profile["syscalls"])
        for s in self.profile["syscalls"]:
            self.assertIn("action", s)
            self.assertTrue(s.get("names"), "a syscalls entry has no names")

    def test_no_syscall_is_both_ungated_allowed_and_ungated_denied(self):
        """The failure mode this guards: adding a name to the allow list while
        leaving it in a deny entry. Which rule wins is a libseccomp ordering
        detail, so the profile must not depend on it."""
        allowed = self._ungated_allow_names()
        for s in self.profile["syscalls"]:
            if s["action"] == "SCMP_ACT_ALLOW":
                continue
            if s.get("includes") or s.get("excludes"):
                continue
            overlap = allowed & set(s["names"])
            self.assertEqual(
                overlap, set(),
                f"{sorted(overlap)} appear in both the allow list and a "
                f"{s['action']} entry")

    def test_capability_gated_denials_are_not_quietly_undone(self):
        """A name in the plain allow list wins over the cap-gated deny that was
        meant to restrict it — measured, not assumed: with `setns` in both, a
        container under this profile got EBADF from `setns(-1, 0)` rather than
        the EPERM the gate implies. So an overlap silently disables the gate."""
        allowed = self._ungated_allow_names()
        undone = set()
        for s in self.profile["syscalls"]:
            if s["action"] == "SCMP_ACT_ALLOW":
                continue
            if not (s.get("includes") or s.get("excludes") or s.get("args")):
                continue
            undone |= allowed & set(s["names"])
        self.assertEqual(undone, set())

    def test_no_entry_names_an_argument_twice(self):
        """libseccomp reads such a rule as matching every call: measured on
        a Fedora 44 host (2026-10-04, podman 5.8.7, crun 1.28, libseccomp
        2.6.1), a rule of family > 16 and != 40 let a vsock through."""
        for s in self.profile["syscalls"]:
            indexes = [c["index"] for c in s.get("args") or ()]
            with self.subTest(names=s["names"][:3]):
                self.assertEqual(len(indexes), len(set(indexes)))

    def test_matching_entries_agree_for_every_argument_tried(self):
        """decide() raises where they do not. Measured as above, the rule
        with fewer conditions won whatever the order: an allow of family
        != 40 overruled a refusal of the audit socket."""
        for arch in ("amd64", "arm64", "s390x"):
            for caps in (PODMAN_CAPS, PODMAN_CAPS | {"CAP_AUDIT_WRITE"}):
                for flags in CLONE_FLAGS:
                    decide(self.profile, "clone", flags, arch=arch, caps=caps)
                    decide(self.profile, "clone", 0, flags, arch=arch,
                           caps=caps)
                    decide(self.profile, "unshare", flags, arch=arch,
                           caps=caps)
                for family in FAMILIES:
                    for protocol in PROTOCOLS:
                        decide(self.profile, "socket", family, 1, protocol,
                               arch=arch, caps=caps)

    def test_socket_has_no_refusal_of_its_family_beside_its_allows(self):
        """Measured as above, such a refusal failed to load: crun's
        "seccomp_rule_add_array: File exists". The audit refusal names the
        protocol as well, and loads."""
        for s in self._entries("SCMP_ACT_ERRNO"):
            if "socket" in s["names"]:
                self.assertEqual({c["index"] for c in s["args"]}, {0, 2})

    def test_futex2_family_is_allowed(self):
        """Denying futex2 while allowing `futex` gains nothing — the same
        synchronisation capability is already reachable — and diverges from
        upstream containers-common."""
        allowed = self._ungated_allow_names()
        self.assertLessEqual(FUTEX2, allowed)
        self.assertIn("futex", allowed)
        self.assertIn("futex_time64", allowed)

    def test_names_within_each_entry_are_sorted(self):
        """These lists are maintained by hand and diffed against upstream;
        sorted order is what keeps that diff readable."""
        for s in self.profile["syscalls"]:
            names = s["names"]
            self.assertEqual(names, sorted(names),
                             f"unsorted names in a {s['action']} entry")


class TestSeccompBaseline(ProfileChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads(PROFILE.read_text())

    def test_setns_is_only_reachable_with_cap_sys_admin(self):
        """This profile is deliberately stricter than upstream containers-common
        here: upstream lists `setns` in both the plain allow list and the
        deny-unless-CAP_SYS_ADMIN entry, which leaves it reachable by every
        rootless container. `setns` joins an existing namespace given an fd — the
        one syscall in that gated set most worth denying — and no shipped
        workload grants CAP_SYS_ADMIN, so the gate costs us nothing."""
        self.assertNotIn("setns", self._ungated_allow_names())
        gated = [s for s in self.profile["syscalls"]
                 if "setns" in s["names"]]
        self.assertEqual(len(gated), 2, "expected only the includes/excludes pair")
        for s in gated:
            self.assertTrue(s.get("includes") or s.get("excludes"))

    def test_no_namespace_is_made(self):
        """In one the workload's user is root, and reaches the mount calls
        and the rest of the kernel that root in a namespace does."""
        for flag in (*CLONE_NEW, CLONE_NEWTIME):
            self.assertEqual(decide(self.profile, "unshare", flag), EPERM)
        for flag in CLONE_NEW:
            self.assertEqual(decide(self.profile, "clone", flag | SIGCHLD),
                             EPERM)
            self.assertEqual(decide(self.profile, "clone", 0, flag | SIGCHLD,
                                    arch="s390x"), EPERM)
        # Its flags are behind a pointer the filter cannot read: glibc
        # falls back to clone on ENOSYS.
        self.assertEqual(decide(self.profile, "clone3"), ENOSYS)

    def test_a_thread_and_a_child_are_made(self):
        threads = 0x3d0f00
        self.assertEqual(decide(self.profile, "clone", threads), ALLOW)
        self.assertEqual(decide(self.profile, "clone", SIGCHLD), ALLOW)
        self.assertEqual(decide(self.profile, "clone", 0, SIGCHLD,
                                arch="s390x"), ALLOW)
        self.assertEqual(decide(self.profile, "unshare", 0x200), ALLOW)

    def test_nothing_is_mounted(self):
        for call in MOUNTS:
            self.assertEqual(decide(self.profile, call), EPERM, call)

    def test_the_kernels_log_is_not_read_whatever_the_host_allows(self):
        self.assertEqual(decide(self.profile, "syslog", 3, 0, 0), EPERM)

    def test_reaching_into_another_process_is_not_implemented(self):
        for call in ("pidfd_getfd", "process_vm_readv", "process_vm_writev",
                     "ptrace"):
            self.assertEqual(decide(self.profile, call), ENOSYS, call)

    def test_a_vsock_is_refused_however_its_family_is_written(self):
        """A vsock reaches the host, or a VM's hypervisor, around the
        network namespace and whatever filters it. The kernel reads the
        family as an int: podman's default refuses family 40 alone, and
        socket((1 << 32) | 40, ...) returned a vsock under it (measured as
        above)."""
        for caps in (PODMAN_CAPS, PODMAN_CAPS | {"CAP_AUDIT_WRITE"}):
            for family in (AF_VSOCK, (1 << 32) | AF_VSOCK,
                           (1 << 63) | AF_VSOCK):
                self.assertEqual(
                    decide(self.profile, "socket", family, 1, 0, caps=caps),
                    ENOSYS)
        # Nor through 32-bit x86's multiplexer, whose family is behind a
        # pointer.
        self.assertEqual(decide(self.profile, "socketcall", 1), ENOSYS)

    def test_the_other_families_are_allowed_and_upper_bits_are_not(self):
        for family in range(64):
            if family != AF_VSOCK:
                self.assertEqual(
                    decide(self.profile, "socket", family, 1, 0), ALLOW,
                    family)
                self.assertEqual(
                    decide(self.profile, "socket", (1 << 32) | family, 1, 0),
                    ENOSYS, family)

    def test_the_audit_socket_fails_as_on_a_kernel_without_audit(self):
        """EINVAL, which sudo takes as no audit, unless the workload holds
        CAP_AUDIT_WRITE to use it."""
        self.assertEqual(
            decide(self.profile, "socket", AF_NETLINK, 3, NETLINK_AUDIT),
            EINVAL)
        self.assertEqual(decide(self.profile, "socket", AF_NETLINK, 3, 0),
                         ALLOW)
        self.assertEqual(
            decide(self.profile, "socket", AF_NETLINK, 3, NETLINK_AUDIT,
                   caps=PODMAN_CAPS | {"CAP_AUDIT_WRITE"}), ALLOW)

    def test_cap_sys_admin_gate_covers_the_same_names_both_ways(self):
        """The CAP_SYS_ADMIN gate is a *pair* of entries — allow-when-included,
        ERRNO-when-excluded — and the two name lists must match exactly.

        A name only in the excludes half is denied unconditionally, which is
        stricter than the gate reads and silently diverges from the upstream
        profile we vendored. `perf_event_open` was missing from the allow half
        for exactly that reason: harmless in effect, but it dated our copy and
        made the pair look like two unrelated entries rather than one gate.
        """
        halves = {}
        for s in self.profile["syscalls"]:
            caps = (s.get("includes", {}).get("caps")
                    or s.get("excludes", {}).get("caps") or [])
            if caps != ["CAP_SYS_ADMIN"]:
                continue
            side = "includes" if s.get("includes", {}).get("caps") else "excludes"
            halves.setdefault(side, set()).update(s["names"])
        self.assertEqual(sorted(halves), ["excludes", "includes"],
                         "expected both halves of the CAP_SYS_ADMIN gate")
        self.assertEqual(halves["includes"], halves["excludes"])

    def test_generator_and_rpm_agree_on_where_it_lands(self):
        """The generator points every unit at an absolute path; the spec is what
        puts the file there. A rename that touches one and not the other yields
        units referencing a profile that does not exist."""
        # Imported, not scanned for. This used to regex the generator's source
        # by path; when the container generators moved to gen_container the
        # regex found nothing, which is the same reading it would give for a
        # constant that had genuinely been deleted.
        from workload_seccomp import SECCOMP_BASELINE as baseline
        self.assertEqual(baseline.rsplit("/", 1)[-1], PROFILE.name)
        spec = SPEC.read_text()
        installed = baseline.replace("/usr/share", "%{_datadir}")
        self.assertIn(installed, spec,
                      f"{installed} is not installed by the spec")

    @unittest.skipUnless(
        TROUBLESHOOTING.is_file(),
        "image half not present (standalone workloadctl checkout)")
    def test_the_docs_name_the_error_each_blocked_syscall_gives(self):
        """A syscall the baseline never names falls to defaultErrnoRet, 38:
        gdb in a stock workload prints 'ptrace: Function not implemented',
        and docs promising 'Operation not permitted' send the reader looking
        for the wrong layer. Measured 2026-10-04, a container per profile on
        a Fedora 44 host, each syscall called with an argument the kernel
        itself rejects, so the errno tells which layer refused:

            syscall            podman default    baseline   baseline + ptrace
            ptrace             ESRCH (kernel)    ENOSYS     ESRCH (kernel)
            process_vm_readv   0 (kernel)        ENOSYS     0 (kernel)
            keyctl             EOPNOTSUPP        ENOSYS     ENOSYS
            setns(-1, 0)       EBADF (kernel)    EPERM      EPERM
        """
        doc = _section(TROUBLESHOOTING.read_text(),
                       "### 9. Syscall blocked by seccomp profile")
        listed = re.search(r"The blocked syscalls are: (.*)", doc).group(1)
        names = re.findall(r"`([a-z0-9_]+)`", listed)
        self.assertTrue(names, "TROUBLESHOOTING.md §9 lists no syscalls")
        guide = _section(WORKLOADS.read_text(), "### Seccomp Filtering")
        for n in names:
            errno = _errno_for_an_uncapable_container(self.profile, n)
            with self.subTest(syscall=n, errno=errno):
                self.assertIn(errno, (1, 38), "allowed, yet listed as blocked")
                text = ENOSYS_TEXT if errno == 38 else EPERM_TEXT
                self.assertIn(text, doc)
                row = re.search(rf"^\| `{n[:10]}.*$", guide, re.M)
                self.assertIsNotNone(row, f"workloads.md has no row for {n}")
                self.assertIn(text, row.group(0))


def _errno_for_an_uncapable_container(profile, name):
    """The errno the profile returns for `name` in a container with no
    added capabilities, or None if it is allowed: an ungated entry decides
    first, then a capability gate's deny half, then the default."""
    for s in profile["syscalls"]:
        if name in s["names"] and not s.get("includes") \
                and not s.get("excludes") and not s.get("args"):
            if s["action"] == "SCMP_ACT_ALLOW":
                return None
            return s.get("errnoRet", profile["defaultErrnoRet"])
    for s in profile["syscalls"]:
        if name in s["names"] and s.get("excludes") \
                and s["action"] == "SCMP_ACT_ERRNO":
            return s.get("errnoRet", profile["defaultErrnoRet"])
    return profile["defaultErrnoRet"]


def _section(text, heading):
    """From `heading` to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading)
    rest = text[start + len(heading):]
    end = re.search(rf"^#{{1,{level}}} ", rest, re.M)
    return text[start:start + len(heading) + (end.start() if end else
                                              len(rest))]


def _restricted_names(profile):
    """Every name an entry of `profile` restricts: in a deny, behind a gate
    or an argument filter."""
    return sorted({n for s in profile["syscalls"]
                   if s["action"] != "SCMP_ACT_ALLOW" or s.get("includes")
                   or s.get("excludes") or s.get("args")
                   for n in s["names"]})


class TestAProfileAllowingEveryRestrictedName(ProfileChecks,
                                              unittest.TestCase):
    """The hardest seccomp_allow: every name the baseline denies, gates or
    filters by argument, at once. Each must come out of its entries, gate
    pairs included, or the derived profile breaks a check above."""

    @classmethod
    def setUpClass(cls):
        baseline = json.loads(PROFILE.read_text())
        cls.profile = derived_profile(baseline, _restricted_names(baseline))


class TestAProfileAllowingTheDebuggersCalls(ProfileChecks,
                                            unittest.TestCase):
    """What a debugger needs: ptrace and process_vm_*, which the baseline
    leaves to its default errno."""

    @classmethod
    def setUpClass(cls):
        baseline = json.loads(PROFILE.read_text())
        cls.profile = derived_profile(
            baseline, ["process_vm_readv", "process_vm_writev", "ptrace"])


class TestDerivedProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(PROFILE.read_text())

    def test_each_restricted_name_is_allowed_by_one_entry_alone(self):
        """One name at a time: it appears in exactly one entry, an
        unconditional allow, and every other name keeps its entries."""
        for name in _restricted_names(self.baseline):
            with self.subTest(name=name):
                profile = derived_profile(self.baseline, [name])
                holding = [s for s in profile["syscalls"]
                           if name in s["names"]]
                self.assertEqual(holding, [{"names": [name],
                                            "action": "SCMP_ACT_ALLOW"}])
                rest = [dict(s, names=[n for n in s["names"] if n != name])
                        for s in self.baseline["syscalls"]]
                self.assertEqual(profile["syscalls"][:-1],
                                 [s for s in rest if s["names"]])

    def test_everything_but_the_syscalls_is_the_baselines(self):
        profile = derived_profile(self.baseline, ["ptrace"])
        self.assertEqual({k: v for k, v in profile.items()
                          if k != "syscalls"},
                         {k: v for k, v in self.baseline.items()
                          if k != "syscalls"})

    def test_the_baseline_is_not_changed(self):
        before = json.dumps(self.baseline)
        derived_profile(self.baseline, _restricted_names(self.baseline))
        self.assertEqual(json.dumps(self.baseline), before)


if __name__ == "__main__":
    unittest.main()
