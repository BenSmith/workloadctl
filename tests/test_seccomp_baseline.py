#!/usr/bin/env python3
"""The shipped seccomp baseline, as an artifact.

Every non-privileged workload runs under this profile, so a malformed or
self-contradicting file breaks every container on the host at once — and it fails
at `podman run` time, far from the edit that caused it. Nothing else in the suite
looks at the file's contents. A workload's [security] seccomp_allow derives
a profile from it, and the same checks hold every derived one.
"""
import errno
import json
import re
import unittest

from tests import REPO_ROOT
from workload_seccomp import NETLINK_PROTOCOLS, derived_profile

PROFILE = REPO_ROOT / "seccomp-workload-baseline.json"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"
SECURITY = REPO_ROOT / "docs" / "manual" / "08-security.md"
TROUBLESHOOTING = REPO_ROOT / "docs" / "manual" / "10-troubleshooting.md"

ENOSYS_TEXT = "Function not implemented"
EPERM_TEXT = "Operation not permitted"

# The futex2 syscalls. glibc currently probes and falls back to `futex` when
# these are denied, which is why blocking them was invisible; a release that
# stops falling back would turn it into an EPERM with no recovery.
FUTEX2 = {"futex_requeue", "futex_wait", "futex_waitv", "futex_wake"}

ALLOW = "allow"
LOG = "log"
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

# The socket families in three tiers (audit F4's workload side). Allowed:
# what workloads use. Refused: uncommon families with a record of kernel
# bugs, and vsock. Logged, then allowed: the rest, until their use is known.
ALLOWED_FAMILIES = {1, 2, 10}                     # unix, inet, inet6
REFUSED_FAMILIES = {
    38,                                           # AF_ALG
    9, 3, 6, 11, 8, 20, 24, 36, 39, 37, 35, 34,   # X.25 .. ISDN
    21, 30, 26, 41, 33, 42, 43, 45,               # RDS .. MCTP
    AF_VSOCK,
}
# inet's and inet6's L2TP, SCTP and SMC, each a module of its own; the
# kernel refuses a protocol from IPPROTO_MAX.
REFUSED_IPPROTOS = {115, 132, 256}
IPPROTO_MAX = 263
# netlink: route, netfilter, uevent.
ALLOWED_NETLINK = {0, 12, 15}
# xfrm, crypto, rdma, iscsi, scsitransport; sock_diag and generic, whose
# requests load the module they name; audit is its own rule.
REFUSED_NETLINK = {6, 21, 20, 8, 18, 4, 16}
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
             else LOG if e["action"] == "SCMP_ACT_LOG"
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
PROTOCOLS = [*range(34), 115, 132, 255, 256, 262, 263,
             (1 << 32) | NETLINK_AUDIT, (1 << 32) | 6, MASK64]


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

    def test_the_baseline_drops_the_32bit_subarchitectures(self):
        """x86_64 carries no 32-bit sub-arch, so the x86 socketcall fold that
        bypasses the family refusals never exists and no 32-bit syscall runs.
        A bundle that runs 32-bit code opts them back with seccomp_32bit; the
        built filter is measured in TestTheBaselineUnderLibseccomp."""
        x86_64 = next(e for e in self.profile["archMap"]
                      if e["architecture"] == "SCMP_ARCH_X86_64")
        self.assertEqual(x86_64["subArchitectures"], [])

    def test_each_family_is_in_its_tier(self):
        for family in range(64):
            if family == AF_NETLINK:
                continue
            want = (ALLOW if family in ALLOWED_FAMILIES
                    else ENOSYS if family in REFUSED_FAMILIES else LOG)
            self.assertEqual(decide(self.profile, "socket", family, 1, 0),
                             want, family)

    def test_upper_bits_are_refused_not_taken_for_another_family(self):
        for family in range(64):
            for high in (1 << 32, 1 << 63):
                self.assertEqual(
                    decide(self.profile, "socket", high | family, 1, 0),
                    ENOSYS, family)

    def test_each_inet_protocol_is_in_its_tier(self):
        """MPTCP, the last protocol the kernel takes, is built in."""
        for family in (2, 10):
            for protocol in range(IPPROTO_MAX + 3):
                want = (ENOSYS if protocol in REFUSED_IPPROTOS
                        or protocol >= IPPROTO_MAX else ALLOW)
                self.assertEqual(
                    decide(self.profile, "socket", family, 1, protocol),
                    want, (family, protocol))
                self.assertEqual(
                    decide(self.profile, "socket", family, 1,
                           (1 << 32) | protocol), ENOSYS, (family, protocol))

    def test_each_netlink_protocol_is_in_its_tier(self):
        for caps in (PODMAN_CAPS, PODMAN_CAPS | {"CAP_AUDIT_WRITE"}):
            for protocol in range(34):
                if protocol == NETLINK_AUDIT:
                    continue
                want = (ALLOW if protocol in ALLOWED_NETLINK
                        else ENOSYS if protocol in REFUSED_NETLINK
                        or protocol >= 32 else LOG)
                self.assertEqual(
                    decide(self.profile, "socket", AF_NETLINK, 3, protocol,
                           caps=caps), want, (protocol, len(caps)))
                self.assertEqual(
                    decide(self.profile, "socket", AF_NETLINK, 3,
                           (1 << 32) | protocol, caps=caps), ENOSYS)

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
        doc = _section(SECURITY.read_text(), "### What the baseline refuses")
        expected = {}
        for cell, fails_with in re.findall(
                r"^\| (.*?) \| .*? \| (.*?) \|$", doc, re.M):
            # Rows naming plain syscalls only; "socket with ..." and the
            # namespace-flag rows are argument filters this cannot probe.
            if not re.fullmatch(r"`[a-z0-9_]+`(, `[a-z0-9_]+`)*", cell):
                continue
            errno = 38 if "ENOSYS" in fails_with else 1 if "EPERM" in fails_with else None
            for n in re.findall(r"`([a-z0-9_]+)`", cell):
                expected[n] = errno
        self.assertTrue(expected, "08-security.md's table lists no syscalls")
        for n, want in expected.items():
            with self.subTest(syscall=n):
                self.assertEqual(
                    _errno_for_an_uncapable_container(self.profile, n), want)
        prose = " ".join(doc.split())
        self.assertIn(ENOSYS_TEXT, prose)
        self.assertIn(EPERM_TEXT, prose)
        symptoms = " ".join(
            _section(TROUBLESHOOTING.read_text(), "## seccomp").split())
        self.assertIn(ENOSYS_TEXT, symptoms)
        self.assertIn(EPERM_TEXT, symptoms)


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


class TestAProfileTakingBackEveryNetlinkProtocol(ProfileChecks,
                                                  unittest.TestCase):
    """Every protocol seccomp_netlink names, beside a seccomp_allow: the
    added socket() rules must agree with every baseline entry they meet."""

    @classmethod
    def setUpClass(cls):
        baseline = json.loads(PROFILE.read_text())
        cls.profile = derived_profile(baseline, ["ptrace"],
                                      netlink=list(NETLINK_PROTOCOLS))


class TestDerivedProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(PROFILE.read_text())

    def test_the_netlink_protocols_offered_are_ones_the_baseline_refuses(self):
        """A protocol the baseline already allows or logs needs no taking
        back, and an allow beside its log entry would disagree."""
        for name, protocol in NETLINK_PROTOCOLS.items():
            with self.subTest(name=name):
                self.assertEqual(decide(self.baseline, "socket", AF_NETLINK,
                                        3, protocol), ENOSYS)

    def test_a_netlink_protocol_taken_back_is_allowed_and_no_other(self):
        for name, protocol in NETLINK_PROTOCOLS.items():
            with self.subTest(name=name):
                profile = derived_profile(self.baseline, [], netlink=[name])
                for p in range(34):
                    want = (ALLOW if p == protocol
                            else decide(self.baseline, "socket", AF_NETLINK,
                                        3, p))
                    self.assertEqual(decide(profile, "socket", AF_NETLINK,
                                            3, p), want, p)
                self.assertEqual(decide(profile, "socket", AF_NETLINK, 3,
                                        (1 << 32) | protocol), ENOSYS)
                self.assertEqual(decide(profile, "socket", 2, 1, protocol),
                                 ALLOW)

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



def _libseccomp():
    try:
        import seccomp
    except ImportError:
        return None
    return seccomp


@unittest.skipUnless(_libseccomp(), "libseccomp's Python binding absent")
class TestTheBaselineUnderLibseccomp(unittest.TestCase):
    """decide() models libseccomp; this asks it. The profile is built rule
    by rule as crun builds it, loaded in a child, and socket() called
    there. Only calls the filter refuses, or families the kernel has built
    in, are made: a logged family would be allowed, and could make the
    kernel load its module.

    The child also runs under every filter this process already has (a
    container's runtime installs one), and the kernel answers with the most
    restrictive; of two refusals, the filter loaded last. So the profile is
    built refusing with MARK where it says its default errno, and only MARK
    reads as its refusal: an earlier filter's refusal cannot pass for ours.
    A call the profile allows that an earlier filter refuses cannot be
    measured in this process, and its row is skipped rather than passed."""

    OPS = ("EQ", "NE", "LT", "LE", "GT", "GE", "MASKED_EQ")
    # No runtime filter refuses with it, and socket() never returns it.
    MARK = errno.EHWPOISON
    # The profile's default errno, from a filter other than ours.
    REFUSED_EARLIER = "refused by a filter loaded before ours"

    def _build(self, profile, default=None):
        sc = _libseccomp()
        ops = {f"SCMP_CMP_{op}": getattr(sc, op) for op in self.OPS}
        default = profile["defaultErrnoRet"] if default is None else default
        flt = sc.SyscallFilter(sc.ERRNO(default))
        # And x86_64's sub-architectures, as podman hands crun them: on x86,
        # libseccomp folds a socket rule onto socketcall, and two folded
        # rules with different actions fail the load with EEXIST, which a
        # native-only filter never sees (dev host, 2026-10-14: every container
        # workload failed to start).
        for entry in profile["archMap"]:
            if entry["architecture"] == "SCMP_ARCH_X86_64":
                for sub in entry["subArchitectures"]:
                    flt.add_arch(getattr(sc.Arch, sub.removeprefix(
                        "SCMP_ARCH_")))
        for e in profile["syscalls"]:
            if not _applies(e, "amd64", PODMAN_CAPS):
                continue
            action = {"SCMP_ACT_ALLOW": sc.ALLOW, "SCMP_ACT_LOG": sc.LOG}.get(
                e["action"]) or sc.ERRNO(e.get("errnoRet", default))
            args = [sc.Arg(c["index"], ops[c["op"]], c["value"],
                           c["valueTwo"]) for c in e.get("args") or ()]
            for name in e["names"]:
                try:
                    sc.resolve_syscall(sc.Arch.NATIVE, name)
                except (ValueError, RuntimeError):
                    continue
                flt.add_rule(action, name, *args)
        return flt

    def _sockets(self, calls, profile=None, filtered=True):
        """What each socket() call gives in a child under the profile's
        filter, its refusals told apart from an earlier filter's (MARK), or
        under no filter of ours when not `filtered`."""
        import ctypes
        import os
        profile = profile or json.loads(PROFILE.read_text())
        flt = self._build(profile, default=self.MARK) if filtered else None
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            if flt is not None:
                flt.load()
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
            out = []
            for family, kind, protocol in calls:
                fd = libc.syscall(41, ctypes.c_long(family),
                                  ctypes.c_long(kind), ctypes.c_long(protocol))
                if fd >= 0:
                    os.close(fd)
                out.append(ALLOW if fd >= 0 else ctypes.get_errno())
            os.write(write, json.dumps(out).encode())
            os._exit(0)
        os.close(write)
        data = os.read(read, 65536)
        os.waitpid(pid, 0)
        default = profile["defaultErrnoRet"]
        return [default if got == self.MARK
                else self.REFUSED_EARLIER if filtered and got == default
                else got for got in json.loads(data)]

    def _assert_sockets(self, calls, profile=None):
        """Each call gives the outcome `calls` names for it under the
        profile. A call it allows that this process refuses before any
        filter of ours loads is skipped: nothing here can measure it. One
        the profile itself refused is not retried: that refusal is ours."""
        profile = profile or json.loads(PROFILE.read_text())
        got = dict(zip(calls, self._sockets(list(calls), profile)))
        retry = [c for c, want in calls.items() if want == ALLOW
                 and got[c] not in (ALLOW, profile["defaultErrnoRet"])]
        refused_anyway = {c for c, bare in zip(
            retry, self._sockets(retry, profile, filtered=False))
            if bare != ALLOW}
        for call, want in calls.items():
            with self.subTest(socket=call):
                if call in refused_anyway:
                    self.skipTest("this process refuses it before any filter "
                                  "of ours loads (a runtime's own seccomp "
                                  "filter)")
                self.assertEqual(got[call], want)

    def test_it_builds_for_every_architecture_crun_adds(self):
        self._build(json.loads(PROFILE.read_text()))

    def test_the_baseline_has_no_32bit_arch_and_no_socketcall(self):
        """The hole closed: with x86 and x32 dropped the built filter is the
        native arch alone. libseccomp folds every socket rule onto x86's
        socketcall with the family behind a pointer, so a socketcall(SYS_
        SOCKET) there reaches any family (vsock included) past the refusals,
        and no rule can refuse it without colliding with the fold the allows
        need. Without the sub-arch there is no socketcall at all, and a
        32-bit syscall hits the filter's bad-architecture KILL."""
        import re
        import tempfile
        flt = self._build(json.loads(PROFILE.read_text()))
        with tempfile.TemporaryFile("w+") as f:
            flt.export_pfc(f)
            f.seek(0)
            pfc = f.read()
        arches = re.findall(r"# filter for arch (\S+) \(", pfc)
        self.assertEqual([a for a in arches if a in ("x86", "x32")], [])
        self.assertNotIn('"socketcall"', pfc)

    def test_a_32bit_bundle_restores_the_arches_and_still_builds(self):
        """seccomp_32bit puts x86 and x32 back on the derived profile. It
        builds — the logged families' always-true protocol condition keeps
        them off socketcall, so the allows' fold has no differing action
        beside it (two would fail the load with EEXIST) — and socketcall is
        back: the family-blind multiplexer, the accepted cost for a workload
        that runs 32-bit code."""
        import re
        import tempfile
        from workload_seccomp import derived_profile
        profile = derived_profile(
            json.loads(PROFILE.read_text()),
            ["clone", "mount", "pivot_root", "umount2", "unshare"],
            allow_32bit=True)
        flt = self._build(profile)
        with tempfile.TemporaryFile("w+") as f:
            flt.export_pfc(f)
            f.seek(0)
            pfc = f.read()
        arches = re.findall(r"# filter for arch (\S+) \(", pfc)
        self.assertIn("x86", arches)
        self.assertIn('"socketcall"', pfc)

    def test_it_loads_and_the_tiers_hold(self):
        calls = {(1, 1, 0): ALLOW, (2, 1, 0): ALLOW, (10, 2, 0): ALLOW,
                 (38, 5, 0): ENOSYS, (AF_VSOCK, 1, 0): ENOSYS,
                 ((1 << 32) | AF_VSOCK, 1, 0): ENOSYS,
                 ((1 << 32) | 1, 1, 0): ENOSYS,
                 (AF_NETLINK, 3, 0): ALLOW, (AF_NETLINK, 3, 16): ENOSYS,
                 (AF_NETLINK, 3, 4): ENOSYS,
                 (AF_NETLINK, 3, 6): ENOSYS, (AF_NETLINK, 3, 21): ENOSYS,
                 (AF_NETLINK, 3, NETLINK_AUDIT): EINVAL,
                 (2, 1, 6): ALLOW, (2, 1, 132): ENOSYS, (10, 2, 115): ENOSYS,
                 (2, 1, 256): ENOSYS}
        self._assert_sockets(calls)

    def test_generic_netlink_taken_back_loads_and_holds(self):
        """A WireGuard bundle's profile: generic netlink allowed, sock_diag
        still refused, and with the 32-bit sub-architectures back it still
        builds (the rule's protocol condition keeps it off socketcall)."""
        baseline = json.loads(PROFILE.read_text())
        self._build(derived_profile(baseline, [], netlink=["generic"],
                                    allow_32bit=True))
        calls = {(AF_NETLINK, 3, 16): ALLOW, (AF_NETLINK, 3, 4): ENOSYS,
                 (AF_NETLINK, 3, 6): ENOSYS, (AF_VSOCK, 1, 0): ENOSYS}
        self._assert_sockets(calls, derived_profile(
            baseline, [], netlink=["generic"]))

if __name__ == "__main__":
    unittest.main()
