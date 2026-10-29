#!/usr/bin/python3
"""Do control files in the local bundle layer (/etc/workloadctl/bundles/) work
end to end under enforcing?

Files there are labelled etc_t where a shipped bundle's are usr_t, and each
consumer reads them in its own way: the build copies them into a context that
root's podman reads, `enable` loads policy.cil and runs setup.sh as root, and a
setup script may hand a helper from the layer to a system service. The unit
suite resolves every path; only a host says whether each reader is allowed.

Two bundles, both throwaway:

  lbr-local  exists only in the local layer.
  lbr-over   is planted in the shipped tree, with a local layer carrying
             asset.txt, setup.sh and helper.py over it, so one build context
             mixes usr_t and etc_t files.
  lbr-vm     is a VM bundle planted in the shipped tree from this checkout's
             vm-base, whose relative user_data_file is answered by a seed in
             the local layer. The guest reads back which seed it booted from.
             --no-vm skips it.

Each is init-ed, built, enabled, probed and purged. Every file the local layer
carries says "local" and every shipped one says "usr", so each row reads which
copy a reader actually got. The audit row reports every AVC since the start,
unfiltered: the rig runs on a quiet dev host, and an AVC here would not
necessarily name a workload.

    sudo python3 tests/manual/local_bundle_rig.py [--keep] [--no-vm]
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

sys.dont_write_bytecode = True

# Spelled out rather than imported: the rig measures the INSTALLED workloadctl,
# and importing lib/ would measure the checkout.
LOCAL_ROOT = Path("/etc/workloadctl/bundles")
SHIPPED_ROOT = Path("/usr/share/workloadctl/workloads")
WORKLOAD_DIR = Path("/etc/workloads.d")
AUDIT_LOG = Path("/var/log/audit/audit.log")
MARK_DIR = Path("/run/lbr-rig")
BASE_IMAGE = "docker.io/library/alpine:latest"
LOCAL, OVER, VM = "lbr-local", "lbr-over", "lbr-vm"
# The VM arm borrows vm-base's image pin and seed from this checkout, so it
# boots what vm-base boots without a second pin to keep current.
VM_BASE = Path(__file__).resolve().parents[2] / "workloads" / "vm-base"
SEED = "cloud-init/user-data"
SEED_MARK = "/etc/lbr-seed"


class Arm(NamedTuple):
    name: str


ARMS = [Arm(LOCAL), Arm(OVER), Arm(VM)]

results = []
created = []      # dirs this run made, removed in reverse at cleanup


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          f"{'  -- ' + detail if detail else ''}", flush=True)


def skip(label, why):
    print(f"  SKIP  {label}  -- {why}", flush=True)


def say(msg):
    print(msg, flush=True)


def run(argv, timeout=120):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"timed out after {timeout}s")


def cli(*args, timeout=300):
    return run(["workloadctl", *args], timeout=timeout)


def last_line(p):
    lines = (p.stderr.strip() or p.stdout.strip()).splitlines()
    return lines[-1][:120] if lines else ""


def label(path):
    try:
        return os.getxattr(path, "security.selinux").decode().rstrip("\0")
    except OSError as e:
        return f"({e})"


# --- fixtures -----------------------------------------------------------------

def toml_for(arm):
    name = arm.name
    if name == VM:
        text = (VM_BASE / "workload.toml").read_text()
        return text.replace('[workload]\nname = "vm-base"\n',
                            f'[workload]\nname = "{VM}"\nenabled = false\n', 1)
    return (f'[workload]\nname = "{name}"\nenabled = false\n\n'
            f'[container]\nimage = "localhost/{name}:latest"\npull = "never"\n'
            f'command = ["sleep", "infinity"]\n\n'
            f'[network]\nmode = "pasta"\n\n'
            f'[host]\nsetup = "setup.sh"\n\n'
            f'[security]\nselinux_policy = true\n')


CONTAINERFILE = f"FROM {BASE_IMAGE}\nCOPY asset.txt /asset.txt\n"

POLICY = """(block __WL_MODULE__
    (blockinherit container)
    (blockinherit net_container)
)
"""


def setup_sh(tag):
    # The helper lookup is the shell chain sunshine-streaming's setup.sh uses,
    # so the WORKLOAD_LOCAL_BUNDLE_DIR row exercises the real contract.
    return f"""#!/bin/sh
set -eu
NAME="${{WORKLOAD_NAME:?}}"
MARK="{MARK_DIR}/$NAME"
HELPER="${{WORKLOAD_INSTANCE_DIR:?}}/helper.py"
[ -f "$HELPER" ] || HELPER="${{WORKLOAD_LOCAL_BUNDLE_DIR:?}}/helper.py"
[ -f "$HELPER" ] || HELPER="${{WORKLOAD_BUNDLE_DIR:?}}/helper.py"
case "${{1:-}}" in
enable)
    mkdir -p {MARK_DIR}
    echo "{tag} $0" > "$MARK.setup"
    systemd-run --wait --quiet --collect --unit="lbr-rig-$NAME-helper" \\
        /usr/bin/python3 "$HELPER" "$MARK.helper"
    ;;
disable) rm -f "$MARK.setup" "$MARK.helper" ;;
artifacts) echo "file $MARK.setup" ;;
*) exit 2 ;;
esac
"""


def helper_py(tag):
    return f'import sys\nopen(sys.argv[1], "w").write("{tag} " + __file__ + "\\n")\n'


def seed(tag):
    # One more write_files entry, not a second write_files: key, which would
    # replace vm-base's list (host key, clock) rather than extend it.
    text = (VM_BASE / SEED).read_text()
    entry = (f"write_files:\n  - path: {SEED_MARK}\n"
             f"    content: \"{tag} {VM}\\n\"\n")
    assert text.count("\nwrite_files:\n") == 1, "vm-base seed changed shape"
    return text.replace("\nwrite_files:\n", "\n" + entry, 1)


def plant(d, files):
    for parent in reversed([d, *d.parents]):
        if not parent.exists():
            parent.mkdir()
            created.append(parent)
    for fname, text in files.items():
        (d / fname).parent.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(text)
        if fname.endswith(".sh"):
            (d / fname).chmod(0o755)


def stage():
    plant(LOCAL_ROOT / LOCAL, {
        "workload.toml": toml_for(Arm(LOCAL)), "Containerfile": CONTAINERFILE,
        "asset.txt": f"local {LOCAL}\n", "setup.sh": setup_sh("local"),
        "helper.py": helper_py("local"), "policy.cil": POLICY,
    })
    plant(SHIPPED_ROOT / OVER, {
        "workload.toml": toml_for(Arm(OVER)), "Containerfile": CONTAINERFILE,
        "asset.txt": f"usr {OVER}\n", "setup.sh": setup_sh("usr"),
        "helper.py": helper_py("usr"), "policy.cil": POLICY,
    })
    plant(LOCAL_ROOT / OVER, {
        "asset.txt": f"local {OVER}\n", "setup.sh": setup_sh("local"),
        "helper.py": helper_py("local"),
    })


def stage_vm():
    plant(SHIPPED_ROOT / VM, {"workload.toml": toml_for(Arm(VM)), SEED: seed("usr")})
    plant(LOCAL_ROOT / VM, {SEED: seed("local")})


# --- rows ---------------------------------------------------------------------

def check_premises():
    say("\n== premises ==")
    mode = run(["getenforce"]).stdout.strip()
    record("host is Enforcing", mode == "Enforcing", mode)
    lab = label(LOCAL_ROOT / LOCAL / "Containerfile")
    record("local-layer files are etc_t", ":etc_t:" in lab, lab)
    lab = label(SHIPPED_ROOT / OVER / "Containerfile")
    record("planted shipped files are usr_t", ":usr_t:" in lab, lab)
    p = cli("catalog", "--json")
    try:
        by_name = {r["bundle"]: r for r in json.loads(p.stdout)}
    except (ValueError, KeyError, TypeError):
        by_name = {}
    src = {n: by_name.get(n, {}).get("source") for n in (LOCAL, OVER)}
    ok = src == {LOCAL: "local", OVER: "shipped+local"}
    record("installed workloadctl has the layered catalog", ok, str(src))
    if not ok:
        sys.exit("the installed workloadctl is not the local-layer build; "
                 "every row after this would measure the wrong code")


def expected_sources(name):
    if name == LOCAL:
        return dict.fromkeys(("Containerfile", "asset.txt", "setup.sh",
                              "helper.py", "policy.cil"), "local")
    return {"Containerfile": "usr", "policy.cil": "usr", "asset.txt": "local",
            "setup.sh": "local", "helper.py": "local"}


def bring_up(name):
    say(f"\n== {name}: init, build, enable ==")
    p = cli("init", name)
    record(f"{name}: init", p.returncode == 0, last_line(p))
    p = cli("info", name, "--files", "--json")
    try:
        got = {f["file"]: f["source"] for f in json.loads(p.stdout)["control_files"]}
    except (ValueError, KeyError, TypeError):
        got = {}
    want = expected_sources(name)
    record(f"{name}: info --files names the winning layer",
           {k: got.get(k) for k in want} == want, str(got))
    p = cli("build", name, timeout=600)
    record(f"{name}: build", p.returncode == 0, last_line(p))
    p = cli("enable", name, timeout=600)
    record(f"{name}: enable", p.returncode == 0, last_line(p))
    deadline = time.time() + 180
    while time.time() < deadline:
        r = cli("exec", name, "--", "echo", "UP", timeout=30)
        if r.returncode == 0 and "UP" in r.stdout:
            return True
        time.sleep(3)
    record(f"{name}: container answers exec", False, "never came up")
    subprocess.run(["journalctl", "-u", f"workload-{name}.service", "-n", "30",
                    "--no-pager"])
    return False


def probe(name):
    say(f"\n== {name}: what each reader got ==")
    module = "wl_" + name.replace("-", "_")
    r = cli("exec", name, "--", "cat", "/asset.txt", timeout=30)
    # Each bundle's asset names it, so the two builds can't share a cached
    # layer and each image is read for its own bundle.
    record(f"{name}: the image COPY-ed the local asset",
           r.stdout.strip() == f"local {name}", repr(r.stdout.strip() or r.stderr.strip()))
    r = cli("exec", name, "--", "cat", "/proc/self/attr/current", timeout=30)
    record(f"{name}: container runs as {module}.process",
           f"{module}.process" in r.stdout, r.stdout.strip("\0\n ") or r.stderr.strip())
    mods = run(["semodule", "-l"]).stdout.split()
    record(f"{name}: policy module {module} loaded", module in mods)
    setup = MARK_DIR / f"{name}.setup"
    text = setup.read_text().strip() if setup.exists() else "(no marker)"
    record(f"{name}: setup.sh ran from the local layer",
           text == f"local {LOCAL_ROOT / name / 'setup.sh'}", text)
    helper = MARK_DIR / f"{name}.helper"
    text = helper.read_text().strip() if helper.exists() else "(no marker)"
    record(f"{name}: a system service ran the local layer's helper",
           text == f"local {LOCAL_ROOT / name / 'helper.py'}", text)


def tear_down(name):
    say(f"\n== {name}: disable --purge ==")
    p = cli("disable", name, "--purge", timeout=300)
    record(f"{name}: disable --purge", p.returncode == 0, last_line(p))
    module = "wl_" + name.replace("-", "_")
    record(f"{name}: policy module removed",
           module not in run(["semodule", "-l"]).stdout.split())
    record(f"{name}: setup.sh disable ran",
           not (MARK_DIR / f"{name}.setup").exists())


def check_vm_premise():
    shipped = SHIPPED_ROOT / "vm-base" / "workload.toml"
    text = shipped.read_text() if shipped.exists() else ""
    ok = f'user_data_file = "{SEED}"' in text
    record("installed vm-base names its seed relatively", ok, str(shipped))
    if not ok:
        sys.exit("the installed workloadctl predates layered seed lookup; "
                 "the VM rows would measure the wrong code")


def vm_run():
    say(f"\n== {VM}: a local-layer seed over a shipped VM bundle ==")
    p = cli("init", VM)
    record(f"{VM}: init", p.returncode == 0, last_line(p))
    p = cli("info", VM, "--files", "--json")
    try:
        got = {f["file"]: f["source"] for f in json.loads(p.stdout)["control_files"]}
    except (ValueError, KeyError, TypeError):
        got = {}
    record(f"{VM}: info --files names the local seed", got.get(SEED) == "local", str(got))
    p = cli("enable", VM, timeout=900)
    record(f"{VM}: enable", p.returncode == 0, last_line(p))
    got = "(never answered)"
    deadline = time.time() + 600
    while p.returncode == 0 and time.time() < deadline:
        r = cli("exec", VM, "--", "cat", SEED_MARK, timeout=30)
        if r.returncode == 0:
            got = r.stdout.strip()
            break
        time.sleep(5)
    record(f"{VM}: the guest booted the local layer's seed",
           got == f"local {VM}", got)
    if got == "(never answered)":
        subprocess.run(["workloadctl", "logs", "-n", "40", VM])
    p = cli("disable", VM, "--purge", timeout=300)
    record(f"{VM}: disable --purge", p.returncode == 0, last_line(p))


def check_audit(marker):
    say("\n== SELinux ==")
    if run(["getenforce"]).stdout.strip() != "Enforcing":
        skip("audit.log clean", "host is not Enforcing")
        return
    with AUDIT_LOG.open("rb") as fh:
        fh.seek(marker)
        tail = fh.read().decode("utf-8", "replace")
    denials = [ln for ln in tail.splitlines() if "avc:  denied" in ln]
    record("no AVC denial anywhere during the run", not denials,
           f"{len(denials)} denial(s)" if denials else "clean")
    for ln in denials:
        say(f"    {ln}")


# --- driver -------------------------------------------------------------------

def preflight(with_vm):
    if os.geteuid() != 0:
        sys.exit("run as root: this rig enables and disables real workloads")
    for tool in ("workloadctl", "podman", "semodule", "systemd-run"):
        if shutil.which(tool) is None:
            sys.exit(f"missing {tool}")
    if with_vm and not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm for the VM arm; pass --no-vm to skip it")
    for p in (*(WORKLOAD_DIR / n for n in (LOCAL, OVER, VM)),
              *(LOCAL_ROOT / n for n in (LOCAL, OVER, VM)),
              SHIPPED_ROOT / OVER, SHIPPED_ROOT / VM):
        if p.exists():
            sys.exit(f"{p} is left over from an earlier run; remove it first")


def cleanup():
    say("\n== cleanup ==")
    for name in (LOCAL, OVER, VM):
        if (WORKLOAD_DIR / name).exists():
            cli("disable", name, "--purge", timeout=300)
            shutil.rmtree(WORKLOAD_DIR / name, ignore_errors=True)
    for name in (LOCAL, OVER):
        run(["podman", "rmi", "-f", f"localhost/{name}:latest"])
    for d in (LOCAL_ROOT / LOCAL, LOCAL_ROOT / OVER, LOCAL_ROOT / VM,
              SHIPPED_ROOT / OVER, SHIPPED_ROOT / VM):
        shutil.rmtree(d, ignore_errors=True)
    for d in reversed(created):
        if d.exists() and not any(d.iterdir()):
            d.rmdir()
    shutil.rmtree(MARK_DIR, ignore_errors=True)
    say("  removed")


def main():
    keep = "--keep" in sys.argv
    with_vm = "--no-vm" not in sys.argv
    preflight(with_vm)
    marker = AUDIT_LOG.stat().st_size if AUDIT_LOG.exists() else 0
    try:
        stage()
        if with_vm:
            stage_vm()
        check_premises()
        if with_vm:
            check_vm_premise()
        for name in (LOCAL, OVER):
            if bring_up(name):
                probe(name)
            tear_down(name)
        if with_vm:
            vm_run()
        check_audit(marker)
    finally:
        if not keep:
            cleanup()
    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
