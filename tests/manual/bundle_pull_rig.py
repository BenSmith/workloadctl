#!/usr/bin/python3
"""Does `workloadctl bundle` hold its threat model on a real host?

The unit suite drives the verbs through a stub skopeo. Only a host says
whether the real skopeo applies /etc/workloadctl/bundle-policy.json rather
than /etc/containers/policy.json, whether a signed artifact podman pushed
unpacks to root-owned etc_t files, and whether an added bundle then init-s
and enables under enforcing.

Fixtures, all throwaway: a registry:2 on 127.0.0.1:5000, a sigstore keypair
and a second "wrong" one, a registries.conf.d drop-in marking the registry
insecure, a registries.d entry turning on sigstore attachments, and the
bundle policy. Anything that existed is backed up and restored.

    sudo python3 tests/manual/bundle_pull_rig.py [--keep]
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

# Spelled out rather than imported: the rig measures the INSTALLED workloadctl.
LOCAL_ROOT = Path("/etc/workloadctl/bundles")
STAGING = Path("/etc/workloadctl/.bundle-staging")
SHIPPED_ROOT = Path("/usr/share/workloadctl/workloads")
WORKLOAD_DIR = Path("/etc/workloads.d")
BUNDLE_POLICY = Path("/etc/workloadctl/bundle-policy.json")
REGISTRIES_CONF = Path("/etc/containers/registries.conf.d/99-bpr-rig.conf")
REGISTRIES_D = Path("/etc/containers/registries.d/99-bpr-rig.yaml")
AUDIT_LOG = Path("/var/log/audit/audit.log")
WORK = Path("/run/bpr-rig")
REG = "127.0.0.1:5000"
REPO = f"{REG}/bpr"
REGISTRY_IMAGE = "docker.io/library/registry:2"
BASE_IMAGE = "docker.io/library/alpine:latest"
ARTIFACT_TYPE = "application/vnd.workloadctl.bundle.v1"
LAYER_TYPE = ARTIFACT_TYPE + ".tar"
APP, INST, SHIPPED, DIRB = "bpr-app", "bpr-inst", "bpr-shipped", "bpr-dir"

results = []
backups = {}      # path -> original bytes, or None if it didn't exist


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          f"{'  -- ' + detail if detail else ''}", flush=True)


def say(msg):
    print(msg, flush=True)


def run(argv, timeout=120, **kw):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"timed out after {timeout}s")


def cli(*args, timeout=300):
    return run(["workloadctl", *args], timeout=timeout)


def last_line(p):
    lines = (p.stderr.strip() or p.stdout.strip()).splitlines()
    return lines[-1][:160] if lines else ""


def label(path):
    try:
        return os.getxattr(path, "security.selinux").decode().rstrip("\0")
    except OSError as e:
        return f"({e})"


def refused(p, text):
    return p.returncode != 0 and text in p.stderr


def nothing_left(name):
    left = [str(p) for p in (LOCAL_ROOT / name, LOCAL_ROOT / f"{name}.origin.json")
            if p.exists()]
    left += [str(p) for p in STAGING.iterdir()] if STAGING.is_dir() else []
    return not left, ", ".join(left) or "clean"


# --- fixtures -----------------------------------------------------------------

def put(path, text):
    if path not in backups:
        backups[path] = path.read_bytes() if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def restore_files():
    for path, data in backups.items():
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)


def keypair(prefix):
    pf = WORK / "pass"
    pf.write_text("rig\n")
    p = run(["skopeo", "generate-sigstore-key", "--output-prefix", str(WORK / prefix),
             "--passphrase-file", str(pf)])
    if p.returncode != 0:
        sys.exit(f"generate-sigstore-key: {p.stderr.strip()}")


def policy(key):
    return json.dumps({
        "default": [{"type": "reject"}],
        "transports": {"docker": {REPO: [{
            "type": "sigstoreSigned", "keyPath": str(WORK / f"{key}.pub"),
            "signedIdentity": {"type": "matchRepository"}}]}},
    }, indent=2)


def fixtures():
    WORK.mkdir(mode=0o700, exist_ok=True)
    keypair("good")
    keypair("wrong")
    put(REGISTRIES_CONF, f'[[registry]]\nlocation = "{REG}"\ninsecure = true\n')
    put(REGISTRIES_D, f"docker:\n  {REG}:\n    use-sigstore-attachments: true\n")
    run(["podman", "rm", "-f", "bpr-registry"])
    p = run(["podman", "run", "-d", "--rm", "--name", "bpr-registry",
             "-p", f"{REG}:5000", REGISTRY_IMAGE])
    if p.returncode != 0:
        sys.exit(f"registry: {p.stderr.strip()}")
    for _ in range(30):
        if run(["curl", "-sf", f"http://{REG}/v2/"]).returncode == 0:
            return
        time.sleep(1)
    sys.exit("registry never answered")


def bundle_dir(name, files):
    d = WORK / "src" / name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    for rel, text in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text)
        if rel.endswith(".sh"):
            (d / rel).chmod(0o755)
    return d


def publish(tag, files, key="good"):
    """Push `files` as a bundle artifact to REPO/<tag>, signed with `key`
    (None: unsigned). Returns the manifest digest."""
    ref = f"{REPO}/{tag}"
    d = bundle_dir(tag.replace(":", "-"), files)
    tar = WORK / "bundle.tar"
    run(["tar", "-C", str(d), "-cf", str(tar), "."])
    run(["podman", "artifact", "rm", ref])
    p = run(["podman", "artifact", "add", "--type", ARTIFACT_TYPE,
             "--file-type", LAYER_TYPE, ref, str(tar)])
    if p.returncode != 0:
        sys.exit(f"artifact add {ref}: {p.stderr.strip()}")
    digest = p.stdout.strip().splitlines()[-1]
    sign = ([] if key is None else
            ["--sign-by-sigstore-private-key", str(WORK / f"{key}.private"),
             "--sign-passphrase-file", str(WORK / "pass")])
    p = run(["podman", "artifact", "push", *sign, ref], timeout=180)
    if p.returncode != 0:
        sys.exit(f"artifact push {ref}: {p.stderr.strip()}")
    return digest if digest.startswith("sha256:") else "sha256:" + digest


def app_toml(name, extra=""):
    return (f'[workload]\nname = "{name}"\n\n'
            f'[container]\nimage = "{BASE_IMAGE}"\npull = "missing"\n'
            f'command = ["sleep", "infinity"]\n\n[network]\nmode = "pasta"\n{extra}')


SETUP = '\n[host]\nsetup = "setup.sh"\n'
BUILD = '\n[build]\nscript = "build.sh"\n'


def setup_sh(tag):
    return f'#!/bin/sh\necho "{tag} $1" > /run/bpr-rig/setup.$WORKLOAD_NAME\n'


# --- rows ---------------------------------------------------------------------

def premises():
    say("\n== premises ==")
    mode = run(["getenforce"]).stdout.strip()
    record("host is Enforcing", mode == "Enforcing", mode)
    p = cli("bundle", "--help")
    record("installed workloadctl has `bundle`", p.returncode == 0, last_line(p))
    if p.returncode != 0:
        sys.exit("the installed workloadctl has no bundle verb")
    publish("unsigned:1", {"workload.toml": app_toml(APP)}, key=None)
    p = run(["skopeo", "inspect", "--raw", f"docker://{REPO}/unsigned:1"])
    record("control: the host's own policy.json accepts the unsigned artifact",
           p.returncode == 0, last_line(p) if p.returncode else "accepted")


def no_policy():
    say("\n== no bundle policy ==")
    put(BUNDLE_POLICY, "")
    BUNDLE_POLICY.unlink()
    publish("app:1", {"workload.toml": app_toml(APP)})
    p = cli("bundle", "add", f"{REPO}/app:1", "--name", APP)
    record("no bundle-policy.json: a signed OCI add is refused",
           refused(p, "no bundle trust policy"), last_line(p))
    record("  and leaves nothing", *nothing_left(APP))
    forget(APP)


def refusals():
    say("\n== refusals ==")
    put(BUNDLE_POLICY, policy("good"))
    for tag, key in (("unsigned:1", None), ("wrongkey:1", "wrong")):
        if key:
            publish(tag, {"workload.toml": app_toml(APP)}, key=key)
        p = cli("bundle", "add", f"{REPO}/{tag}", "--name", APP)
        record(f"{tag.split(':')[0]} refused under the bundle policy",
               refused(p, "skopeo refused"), last_line(p))
        record("  and leaves nothing", *nothing_left(APP))
        forget(APP)
    # a correct signature, copied with its manifest to another repository
    p = run(["skopeo", "copy", "--all", f"docker://{REPO}/app:1",
             f"docker://{REG}/elsewhere/app:1"], timeout=120)
    put(BUNDLE_POLICY, json.dumps({**json.loads(policy("good")), "transports": {"docker": {
        REPO: json.loads(policy("good"))["transports"]["docker"][REPO],
        f"{REG}/elsewhere": json.loads(policy("good"))["transports"]["docker"][REPO]}}}))
    p2 = cli("bundle", "add", f"{REG}/elsewhere/app:1", "--name", APP)
    record("moved signature refused (signed identity names another repo)",
           p.returncode == 0 and refused(p2, "skopeo refused"),
           last_line(p2) if p.returncode == 0 else f"copy failed: {last_line(p)}")
    record("  and leaves nothing", *nothing_left(APP))
    forget(APP)
    put(BUNDLE_POLICY, policy("good"))
    p = cli("bundle", "add", "bpr-app:1")
    record("mistyped bare name refused before any network call",
           refused(p, "not a registry reference") or refused(p, "doesn't name a registry"),
           last_line(p))
    plant_shipped(SHIPPED)
    publish("bpr-shipped:1", {"workload.toml": app_toml(SHIPPED)})
    p = cli("bundle", "add", f"{REPO}/bpr-shipped:1")
    record("a shipped bundle's name refused", refused(p, "shipped bundle is named"),
           last_line(p))
    shutil.rmtree(SHIPPED_ROOT / SHIPPED, ignore_errors=True)


def forget(name):
    """Undo a wrongly admitted add, so a broken refusal makes only its own row
    red rather than every later one ("already exists")."""
    shutil.rmtree(LOCAL_ROOT / name, ignore_errors=True)
    (LOCAL_ROOT / f"{name}.origin.json").unlink(missing_ok=True)


def plant_shipped(name):
    (SHIPPED_ROOT / name).mkdir(parents=True, exist_ok=True)
    (SHIPPED_ROOT / name / "workload.toml").write_text(app_toml(name))


def gated_adds():
    say("\n== root-run files ==")
    for what, extra, files in (
            ("setup script", SETUP, {"setup.sh": setup_sh("v1")}),
            ("[build] script", BUILD, {"build.sh": "#!/bin/sh\nexit 0\n"})):
        tag = "gate-" + what.split()[0].strip("[]") + ":1"
        publish(tag, {"workload.toml": app_toml(APP, extra), **files})
        p = cli("bundle", "add", f"{REPO}/{tag}", "--name", APP)
        record(f"{what}: refused without --allow-host-setup",
               refused(p, "run as host root"), last_line(p))
        record("  and leaves nothing", *nothing_left(APP))
        p = cli("bundle", "add", f"{REPO}/{tag}", "--name", APP, "--allow-host-setup")
        record(f"{what}: added with the flag", p.returncode == 0, last_line(p))
        cli("bundle", "rm", APP)


def signed_add_and_enable():
    say("\n== signed add, init, enable ==")
    d1 = publish("app:1", {"workload.toml": app_toml(APP, SETUP),
                           "setup.sh": setup_sh("v1"), "cloud-init/user-data": "x\n"})
    p = cli("bundle", "add", f"{REPO}/app:1", "--name", APP, "--allow-host-setup")
    record("signed add", p.returncode == 0, last_line(p))
    rec = json.loads((LOCAL_ROOT / f"{APP}.origin.json").read_text())
    record("record pins the pushed digest", rec.get("digest") == d1,
           f"{rec.get('digest')} vs {d1}")
    files = [p for p in (LOCAL_ROOT / APP).rglob("*")]
    bad = [f"{p}: {label(p)} uid={p.stat().st_uid}" for p in files
           if ":etc_t:" not in label(p) or p.stat().st_uid != 0]
    record("every file is etc_t and root-owned", not bad and bool(files), "; ".join(bad[:3]))
    record("setup.sh kept its mode",
           (LOCAL_ROOT / APP / "setup.sh").stat().st_mode & 0o777 == 0o755)
    p = cli("catalog", "--json")
    try:
        origin = {r["bundle"]: r.get("origin") for r in json.loads(p.stdout)}.get(APP)
    except (ValueError, TypeError):
        origin = None
    record("catalog shows the origin", origin == f"oci {REPO}/app:1@{d1}", str(origin))
    p = cli("init", APP, "--as", INST)
    record("init --as from the added bundle", p.returncode == 0, last_line(p))
    p = cli("enable", INST, timeout=600)
    record("enable runs it (setup.sh from the bundle)", p.returncode == 0
           and (WORK / f"setup.{INST}").read_text().startswith("v1 enable")
           if (WORK / f"setup.{INST}").exists() else False, last_line(p))
    return d1


def updates(d1):
    say("\n== update ==")
    d2 = publish("app:1", {"workload.toml": app_toml(APP, SETUP),
                           "setup.sh": setup_sh("v1"), "extra": "2\n"})
    p = cli("bundle", "update", APP)
    record("update to a new digest, setup.sh unchanged: no flag needed",
           p.returncode == 0 and f"{d1} → {d2}" in p.stdout, last_line(p))
    record("  lists the instance", INST in p.stdout)
    publish("app:1", {"workload.toml": app_toml(APP, SETUP), "setup.sh": setup_sh("v2")})
    p = cli("bundle", "update", APP)
    record("changed setup.sh needs the flag again", refused(p, "setup.sh"), last_line(p))
    p = cli("bundle", "update", APP, "--allow-host-setup")
    record("  and installs with it", p.returncode == 0, last_line(p))

    (LOCAL_ROOT / APP / "setup.sh").write_text("edited\n")
    publish("app:1", {"workload.toml": app_toml(APP, SETUP), "setup.sh": setup_sh("v2"),
                      "three": "3\n"})
    p = cli("bundle", "update", APP)
    record("drift refused, naming the file", refused(p, "setup.sh"), last_line(p))
    p = cli("bundle", "update", APP, "--force")
    record("--force replaces it", p.returncode == 0 and
           "v2" in (LOCAL_ROOT / APP / "setup.sh").read_text(), last_line(p))
    (LOCAL_ROOT / APP / "three").write_text("edited\n")
    p = cli("bundle", "update", APP)
    record("same digest with drift refused", refused(p, "three"), last_line(p))
    p = cli("bundle", "update", APP, "--force")
    record("--force restores it", p.returncode == 0 and "Restored" in p.stdout
           and (LOCAL_ROOT / APP / "three").read_text() == "3\n", last_line(p))

    plant_shipped(APP)
    p = cli("bundle", "update", APP)
    record("a shipped bundle now named the same: update refused",
           refused(p, "shipped bundle is now named"), last_line(p))
    p = cli("diagnose", INST, "--json")
    try:
        checks = {c["check"]: c for c in json.loads(p.stdout)["checks"]}
    except (ValueError, KeyError, TypeError):
        checks = {}
    record("  diagnose warns (bundle_origin)", checks.get("bundle_origin", {}).get("warning")
           is True, str(checks.get("bundle_origin", "absent"))[:160])
    shutil.rmtree(SHIPPED_ROOT / APP, ignore_errors=True)


def dir_bundles():
    say("\n== directory bundles ==")
    src = bundle_dir(DIRB, {"workload.toml": app_toml(DIRB, SETUP), "setup.sh": setup_sh("d1")})
    p = cli("bundle", "add", str(src))
    record("dir add lists setup.sh and needs no flag",
           p.returncode == 0 and "setup.sh" in p.stdout, last_line(p))
    (src / "workload.toml").write_text(app_toml(DIRB, SETUP) + "# edited\n")
    p = cli("bundle", "update", DIRB)
    record("update with no source follows the dir",
           p.returncode == 0 and "# edited" in (LOCAL_ROOT / DIRB / "workload.toml").read_text(),
           last_line(p))
    src2 = bundle_dir(DIRB + "-two", {"workload.toml": app_toml(DIRB) + "# two\n"})
    p = cli("bundle", "update", DIRB, str(src2))
    rec = json.loads((LOCAL_ROOT / f"{DIRB}.origin.json").read_text())
    record("update from a second dir records it", p.returncode == 0
           and rec["source"] == f"dir:{src2}", last_line(p))
    shutil.rmtree(src2)
    p = cli("bundle", "update", DIRB)
    record("its dir deleted: update with no source refused", refused(p, "is gone"),
           last_line(p))
    cli("bundle", "rm", DIRB)


def removal():
    say("\n== rm ==")
    p = cli("bundle", "rm", APP)
    record("rm refused while an instance uses it", refused(p, INST), last_line(p))
    p = cli("disable", INST, "--purge", timeout=300)
    shutil.rmtree(WORKLOAD_DIR / INST, ignore_errors=True)
    p = cli("bundle", "rm", APP)
    record("rm once unused", p.returncode == 0 and not (LOCAL_ROOT / APP).exists()
           and not (LOCAL_ROOT / f"{APP}.origin.json").exists(), last_line(p))


def check_audit(marker):
    say("\n== SELinux ==")
    if run(["getenforce"]).stdout.strip() != "Enforcing":
        say("  SKIP  audit.log clean  -- host is not Enforcing")
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

def preflight():
    if os.geteuid() != 0:
        sys.exit("run as root")
    for tool in ("workloadctl", "podman", "skopeo", "curl"):
        if shutil.which(tool) is None:
            sys.exit(f"missing {tool}")
    for p in (WORKLOAD_DIR / INST, SHIPPED_ROOT / APP, SHIPPED_ROOT / SHIPPED,
              *(LOCAL_ROOT / n for n in (APP, DIRB, SHIPPED))):
        if p.exists():
            sys.exit(f"{p} is left over from an earlier run; remove it first")


def cleanup():
    say("\n== cleanup ==")
    if (WORKLOAD_DIR / INST).exists():
        cli("disable", INST, "--purge", timeout=300)
        shutil.rmtree(WORKLOAD_DIR / INST, ignore_errors=True)
    for n in (APP, DIRB, SHIPPED):
        shutil.rmtree(LOCAL_ROOT / n, ignore_errors=True)
        (LOCAL_ROOT / f"{n}.origin.json").unlink(missing_ok=True)
        shutil.rmtree(SHIPPED_ROOT / n, ignore_errors=True)
    run(["podman", "rm", "-f", "bpr-registry"])
    out = run(["podman", "artifact", "ls", "--format", "{{.Repository}}:{{.Tag}}"]).stdout
    for ref in out.split():
        if ref.startswith(REG):
            run(["podman", "artifact", "rm", ref])
    restore_files()
    shutil.rmtree(WORK, ignore_errors=True)
    say("  removed")


def main():
    keep = "--keep" in sys.argv
    preflight()
    marker = AUDIT_LOG.stat().st_size if AUDIT_LOG.exists() else 0
    try:
        fixtures()
        premises()
        no_policy()
        refusals()
        gated_adds()
        d1 = signed_add_and_enable()
        updates(d1)
        dir_bundles()
        removal()
        check_audit(marker)
    finally:
        if not keep:
            cleanup()
    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
