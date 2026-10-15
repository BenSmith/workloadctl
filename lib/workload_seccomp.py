"""A workload's seccomp profile: the baseline, or the baseline plus the
syscalls its `[security] seccomp_allow` names, the netlink protocols its
`[security] seccomp_netlink` takes back and the 32-bit compat its
`[security] seccomp_32bit` opts back in.

The derived profile is rendered by the generator beside the units, from the
baseline installed at that moment, so it is rebuilt whenever the units are
and `drift` reports one an RPM update has left behind. Each allowed name is
taken out of every entry of the baseline, denials, capability gates and
argument filters alike, and allowed in one entry of its own: a name both
allowed and denied leaves the outcome to libseccomp's rule ordering, and an
ungated allow beside a gated deny undoes the gate.

The baseline refuses generic netlink and sock_diag: a generic netlink
family lookup and a sock_diag request make the kernel load the module they
name, and the name is in the message, where no filter reads it. A protocol
taken back is allowed by a socket() rule of its own, beside the baseline's
netlink allows, which no baseline entry matches.

The baseline drops x86_64's 32-bit sub-architectures (x86, x32): on x86
libseccomp folds every `socket` rule onto `socketcall` with the family
behind a pointer, so socketcall(SYS_SOCKET) reaches any family, vsock
included, past the family refusals — and no rule can refuse it without
colliding with the fold the allows need. With no sub-arch there is no
socketcall and a 32-bit syscall hits the filter's bad-architecture KILL. A
workload that runs 32-bit code sets seccomp_32bit, which puts the
sub-architectures back on its derived profile (and with them the folded,
family-blind socketcall, scoped to that workload).

Installed to /usr/libexec/workloadctl/workload_seccomp.py.
"""
import copy
import json
import os
import re
from pathlib import Path

# Baseline seccomp profile applied to all workloads unless overridden via
# security_opt.
SECCOMP_BASELINE = "/usr/share/containers/seccomp-workload-baseline.json"

SYSCALL_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

# The x86_64 entry whose 32-bit compat sub-architectures the baseline drops,
# and seccomp_32bit puts back on a derived profile.
ARCH_X86_64 = "SCMP_ARCH_X86_64"
SUBARCHES_32BIT = ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]

AF_NETLINK = 16
MASK64 = (1 << 64) - 1
# The netlink protocols the baseline refuses and seccomp_netlink may take
# back: generic (wg-quick configures a WireGuard link through it) and
# sock_diag (ss lists sockets through it).
NETLINK_PROTOCOLS = {"generic": 16, "sock_diag": 4}


def baseline_source() -> Path:
    """Where the generator reads the baseline. Honors
    WORKLOAD_SECCOMP_BASELINE for tests; units always name SECCOMP_BASELINE."""
    return Path(os.environ.get("WORKLOAD_SECCOMP_BASELINE", SECCOMP_BASELINE))


def seccomp_allow(config: dict) -> list[str]:
    """The syscalls the workload's top-level [security] adds to the
    baseline, sorted and without repeats; [] when it adds none."""
    names = config.get("security", {}).get("seccomp_allow") or []
    return sorted(set(names))


def seccomp_netlink(config: dict) -> list[str]:
    """The netlink protocols the workload's top-level [security] takes back
    from the baseline, sorted and without repeats; [] when it takes none."""
    names = config.get("security", {}).get("seccomp_netlink") or []
    return sorted(set(names))


def seccomp_32bit(config: dict) -> bool:
    """Whether the workload's top-level [security] opts its containers back
    into the 32-bit sub-architectures the baseline drops."""
    return bool(config.get("security", {}).get("seccomp_32bit"))


def needs_derived_profile(config: dict) -> bool:
    """Whether the workload runs under a profile derived from the baseline
    rather than the baseline itself: it adds syscalls, takes back netlink
    protocols or opts into 32-bit. The generator writes the file exactly when
    this holds, and the run args point at it exactly then, so the two cannot
    drift apart."""
    return (bool(seccomp_allow(config)) or bool(seccomp_netlink(config))
            or seccomp_32bit(config))


def derived_profile_name(name: str) -> str:
    """The derived profile's file name, beside the workload's units."""
    return f"workload-{name}.seccomp.json"


def _netlink_allow(protocol: str) -> dict:
    """The socket() rule allowing one netlink protocol, in the shape of the
    baseline's own netlink allows."""
    return {"names": ["socket"], "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": AF_NETLINK, "valueTwo": 0,
                      "op": "SCMP_CMP_EQ"},
                     {"index": 2, "value": MASK64,
                      "valueTwo": NETLINK_PROTOCOLS[protocol],
                      "op": "SCMP_CMP_MASKED_EQ"}],
            "comment": f"netlink: {protocol}, from seccomp_netlink",
            "includes": {}, "excludes": {}}


def derived_profile(baseline: dict, names, *, netlink=(),
                    allow_32bit=False) -> dict:
    """`baseline` with each of `names` taken out of every entry and allowed
    unconditionally, each of the `netlink` protocols allowed, and — when
    allow_32bit — x86_64's 32-bit sub-arches put back. An entry left with no
    names is dropped."""
    names = set(names)
    profile = copy.deepcopy(baseline)
    syscalls = []
    for entry in profile.get("syscalls", []):
        kept = [n for n in entry["names"] if n not in names]
        if kept:
            entry["names"] = kept
            syscalls.append(entry)
    if names:
        syscalls.append({"names": sorted(names), "action": "SCMP_ACT_ALLOW"})
    syscalls.extend(_netlink_allow(p) for p in sorted(set(netlink)))
    profile["syscalls"] = syscalls
    if allow_32bit:
        for entry in profile.get("archMap", []):
            if entry.get("architecture") == ARCH_X86_64:
                entry["subArchitectures"] = list(SUBARCHES_32BIT)
    return profile


def render_derived_profile(names, *, netlink=(), allow_32bit=False) -> str:
    """The derived profile's text, from the baseline installed now. Raises
    OSError or ValueError when the baseline cannot be read."""
    baseline = json.loads(baseline_source().read_text())
    return json.dumps(
        derived_profile(baseline, names, netlink=netlink,
                        allow_32bit=allow_32bit),
        indent=1) + "\n"


def validate_seccomp(config: dict, kind: str) -> list[str]:
    """Errors for [security] seccomp_allow, seccomp_netlink and
    seccomp_32bit: a list of syscall names, a list of netlink protocols and
    a boolean, on a container that is not privileged and names no profile
    of its own, and only in the top-level [security]. All three adjust the
    baseline, so all three are refused where it does not apply."""
    errors = []
    security = config.get("security", {})
    names = security.get("seccomp_allow")
    protocols = security.get("seccomp_netlink")
    want_32bit = security.get("seccomp_32bit")
    for i, c in enumerate(config.get("containers") or []):
        csec = c.get("security", {}) if isinstance(c, dict) else {}
        for key in ("seccomp_allow", "seccomp_netlink", "seccomp_32bit"):
            if key in csec:
                errors.append(
                    f"containers[{c.get('name', i)}].security.{key}: "
                    f"set {key} in the top-level [security]; one profile "
                    f"serves every container of the workload")
    if names is None and protocols is None and want_32bit is None:
        return errors
    keys = " and ".join(k for k, v in (("seccomp_allow", names),
                        ("seccomp_netlink", protocols),
                        ("seccomp_32bit", want_32bit)) if v is not None)
    if kind == "vm":
        return errors + [f"[security].{keys}: a VM runs under no seccomp "
                         f"profile of workloadctl's"]
    if names is not None and (not isinstance(names, list) or not all(
            isinstance(n, str) and SYSCALL_NAME.match(n) for n in names)):
        errors.append("[security].seccomp_allow must be a list of syscall "
                      "names (lowercase letters, digits and _)")
    if protocols is not None and (not isinstance(protocols, list) or not all(
            isinstance(p, str) and p in NETLINK_PROTOCOLS
            for p in protocols)):
        errors.append("[security].seccomp_netlink must be a list of netlink "
                      "protocols: "
                      + ", ".join(sorted(NETLINK_PROTOCOLS)))
    if want_32bit is not None and not isinstance(want_32bit, bool):
        errors.append("[security].seccomp_32bit must be true or false")
    if security.get("privileged"):
        errors.append(f"[security].{keys}: privileged = true runs under "
                      f"no seccomp profile")
    for where, sec in [("[security]", security)] + [
            (f"containers[{c.get('name', i)}].security", c.get("security", {}))
            for i, c in enumerate(config.get("containers") or [])
            if isinstance(c, dict)]:
        if any(isinstance(o, str) and o.startswith("seccomp=")
               for o in sec.get("security_opt", [])):
            errors.append(
                f"[security].{keys}: {where}.security_opt names a "
                f"seccomp= profile, which replaces the baseline; use one or "
                f"the other")
    return errors
