"""The per-workload SELinux type, and the udica module that confines it.

Two things, both taking an `action` because they run in both directions
and a teardown is the same step with the sign flipped: the fcontext for a
VM workload's tree (svirt_image_t, so a confined QEMU can use its disks)
and the CIL module built from a bundle's shipped policy over udica's base
templates. The level each tree carries is no rule: the setup unit stamps
it (ensure_common.stamp_selinux_labels). `shadowed_filecon_paths` is the check that a bundle's filecon
lines are not silently overridden by the roots registered via semanage.
Everything here shells out to semodule and semanage and prints
its own diagnostic; SelinuxPolicyError tells the caller that has happened.

Installed to /usr/libexec/workloadctl/workload_selinux.py.
"""

import difflib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from cli_log import error, info, warn
from config_parser import workload_root_dir
from workload_lib import (
    NAME_PATTERN,
    bundle_file,
    bundle_names,
    bundle_roots,
    selinux_module_name,
    selinux_type_name,
)
from workload_mcs import VM_TREE_TYPE
from workloadctl_core import WorkloadConfig


class SelinuxPolicyError(Exception):
    """Raised by apply_selinux_policy() when loading/removing a workload's
    SELinux type fails.

    Same contract as substrate.ProvisionFailed: the diagnostic has already
    been printed, so the caller exits 1 without printing again (the enable
    path) or lets it fold into the disable path's best-effort failure list.
    """

UDICA_TEMPLATE_DIR = Path("/usr/share/udica/templates")


def _selinux_available() -> bool:
    """True if the host can load CIL policy modules (semodule + udica bases)."""
    return bool(shutil.which("semodule")) and UDICA_TEMPLATE_DIR.is_dir()


def _selinux_enforcing() -> bool:
    """True if SELinux is currently in enforcing mode."""
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "Enforcing"
    except FileNotFoundError:
        return False


def _available_bundles() -> list[str]:
    """Bundles whose winning policy.cil exists (the template
    apply_selinux_policy loads), sorted."""
    shipped, local = bundle_roots()
    return [b for b in bundle_names()
            if bundle_file(local / b, shipped / b, "policy.cil")[0].exists()]


def _print_available_bundles(bundle: str):
    """Hint at valid selinux_policy bundles after a missing-template error."""
    available = _available_bundles()
    if not available:
        return
    match = difflib.get_close_matches(bundle, available, n=1)
    if match:
        error(f"         did you mean {match[0]!r}?")
    error("         available bundles: " + ", ".join(available))


def fcontext_pattern(name: str) -> str:
    """The fcontext pattern covering one VM workload's whole tree."""
    return f"{workload_root_dir(name)}(/.*)?"


def _local_rules_under(root: str) -> list[str]:
    """The file_contexts.local patterns for `root` and below it."""
    listed = subprocess.run(["semanage", "fcontext", "-l", "-C"],
                            capture_output=True, text=True)
    if listed.returncode != 0:
        return []
    found = []
    for line in listed.stdout.splitlines():
        words = line.split()
        if (words and words[0].startswith(root)
                and words[0][len(root):][:1] in ("/", "(")):
            found.append(words[0])
    return found


def apply_vm_fcontext(config: WorkloadConfig, action: str):
    """Make a workload's rules in file_contexts.local exactly what it needs:
    for a VM, its whole tree as svirt_image_t; for a container, none.

    A confined QEMU cannot use a disk of the blanket rule's
    container_file_t, and the rule keeps a relabel from handing it one.
    It wins over the blanket rule, registered first, because within
    file_contexts.local the rule added last applies. Any other rule under
    the workload's root is removed, so nothing there competes with it.

    Best-effort: a host without semanage, or with SELinux disabled, is not
    a reason to fail an enable.
    """
    if not shutil.which("semanage"):
        return
    root = str(workload_root_dir(config.name))
    wanted = fcontext_pattern(config.name)
    keep = action != "disable" and config.is_vm
    present = _local_rules_under(root)
    for pattern in present:
        if keep and pattern == wanted:
            continue
        subprocess.run(["semanage", "fcontext", "-d", pattern],
                       check=False, capture_output=True)
    if not keep or wanted in present:
        return
    result = subprocess.run(
        ["semanage", "fcontext", "-a", "-t", VM_TREE_TYPE, wanted],
        capture_output=True, text=True)
    if result.returncode != 0:
        warn(f"  WARNING: could not register the SELinux fcontext rule for "
             f"'{config.name}': {result.stderr.strip()}")
        return
    info(f"  Registered SELinux fcontext: {wanted} -> {VM_TREE_TYPE}")


# Path prefixes workloadctl registers in file_contexts.local (the blanket rule
# from the RPM's %post, plus every per-workload VM rule under the same root).
# A CIL filecon anywhere under these is unreachable — see below.
LOCAL_FCONTEXT_ROOTS = ("/var/lib/workloads", "/run/workload-vm")

# CIL is s-expressions, so a filecon is `(filecon "<path>" <class> <context>)`.
_CIL_FILECON_RE = re.compile(r'\(\s*filecon\s+"([^"]*)"')


def shadowed_filecon_paths(cil_text: str) -> list[str]:
    """Paths in a bundle's `policy.cil` whose `filecon` will be silently ignored.

    A module's filecon lands in the base `file_contexts`, and
    `file_contexts.local` outranks the base file *wholesale* — most-specific-wins
    applies only within one source. So a filecon under a path workloadctl has
    registered via semanage does not conflict with that rule and does not lose
    on specificity; it is simply never consulted. The label an operator asked
    for is not applied, nothing errors, and the module loads clean.

    Filecons elsewhere are fine and are how `security/wlvfsd.cil` retypes
    /usr/libexec/virtiofsd: nothing registers /usr/libexec in `.local`, so that
    rule competes within the base file where specificity does apply.
    """
    shadowed = []
    for path in _CIL_FILECON_RE.findall(cil_text):
        # CIL filecons may be literal paths or regexes; either way the leading
        # literal segment is what decides which source file the entry lands
        # against, so a plain prefix test is the right comparison.
        if any(path == root or path.startswith(root + "/")
               for root in LOCAL_FCONTEXT_ROOTS):
            shadowed.append(path)
    return shadowed


def apply_selinux_policy(config: WorkloadConfig, action: str):
    """Load (enable) or remove (disable) a workload's per-workload SELinux type.

    The bundle ships its policy as a CIL template (`policy.cil`) using the
    __WL_MODULE__ placeholder. On enable we substitute the name-keyed block name
    (wl_<name>) and load it alongside udica's base templates (which the
    workload's `(blockinherit ...)` resolves against); on disable we remove the
    wl_<name> module, leaving the shared base templates loaded.

    No-op for workloads without `[security].selinux_policy = true`.
    """
    if not config.selinux_policy:
        return

    module = selinux_module_name(config.name)

    if not _selinux_available():
        # Hard-fail only on enable: the container would fail to start under
        # enforcing mode without its type loaded. disable is best-effort
        # teardown — without tooling there's nothing we could remove anyway, so
        # never block it.
        if action != "disable" and _selinux_enforcing():
            error(f"  ERROR: selinux_policy is set for '{config.name}' but SELinux tooling "
                  f"(semodule + container-selinux templates) is missing. The container "
                  f"would fail to start under enforcing mode. Install container-selinux "
                  f"and policycoreutils, then re-run enable.")
            raise SelinuxPolicyError(f"selinux tooling missing for '{config.name}'")
        warn(f"  WARNING: SELinux tooling (semodule + udica templates) not "
             f"found; skipping policy {action} for '{config.name}'")
        return

    if action == "disable":
        loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if module in loaded.stdout.split():
            info(f"  Removing SELinux module {module}...")
            subprocess.run(["semodule", "-r", module], check=False)
        return

    # enable: substitute the block name and load the workload CIL alongside the
    # udica base templates (so any `(blockinherit ...)` resolves). semodule -i
    # upgrades in place, so re-enabling is idempotent. The CIL is sourced from
    # the bundle dir (defaults to the workload name; a `selinux_policy` string
    # names it explicitly so a renamed workload keeps its original policy).
    bundle = config.selinux_bundle
    if bundle is None:
        # Reached only if a workload without selinux_policy is routed here.
        error(f"  ERROR: no SELinux bundle resolved for '{config.name}' "
              f"(selinux_policy not set)")
        raise SelinuxPolicyError(f"no SELinux bundle resolved for '{config.name}'")
    if not NAME_PATTERN.match(bundle):
        # bundle goes straight into a filesystem path; reject anything that
        # isn't a plain workload-style name (blocks traversal / odd values).
        error(f"  ERROR: invalid [workload] bundle {bundle!r} "
              f"(must match {NAME_PATTERN.pattern})")
        # Common footgun: users copy the SELinux *type* name (wl_foo_bar,
        # underscores) into `bundle`, but the bundle is a directory name
        # and dirs are hyphenated. Suggest the hyphenated form.
        if "_" in bundle:
            error(f"         did you mean {bundle.replace('_', '-')!r}? "
                  f"(the bundle is a directory name and uses hyphens, not the "
                  f"underscores of the SELinux type name)")
        raise SelinuxPolicyError(f"invalid bundle {bundle!r} for '{config.name}'")
    template = config.resolve_control_file("policy.cil")
    if not template.exists():
        error(f"  ERROR: SELinux policy template not found: {template}")
        _print_available_bundles(bundle)
        raise SelinuxPolicyError(f"policy template not found for '{config.name}'")

    bases = sorted(str(p) for p in UDICA_TEMPLATE_DIR.glob("*.cil"))
    src = template.read_text().replace("__WL_MODULE__", module)

    info(f"  Installing SELinux module {module} (type {selinux_type_name(config.name)})...")
    with tempfile.TemporaryDirectory() as work:
        cil = Path(work) / f"{module}.cil"
        cil.write_text(src)
        try:
            subprocess.run(["semodule", "-i", str(cil), *bases], check=True)
        except subprocess.CalledProcessError as e:
            error(f"  Error: SELinux policy install failed (exit {e.returncode})")
            raise SelinuxPolicyError(f"semodule -i failed for '{config.name}'")
