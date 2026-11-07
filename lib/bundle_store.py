"""Installing a bundle into the local bundle root, and its origin record.

A bundle is staged beside the root (`/etc/workloadctl/.bundle-staging/`), on
the same filesystem but outside it, so discovery never sees a half-written
one, and is renamed into place. `<root>/<bundle>.origin.json` records where
it came from and the hash of every file, which is what drift and the
root-run file check compare against.
"""

import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time
import tomllib
from contextlib import contextmanager
from pathlib import Path

from egress_selinux import selinux_enabled
from workload_lib import bundle_roots

LOCK_PATH = Path(os.environ.get("WORKLOADCTL_BUNDLE_LOCK",
                                "/run/lock/workloadctl-bundle.lock"))

POLICY_CIL = "policy.cil"

# Never more than the owner may write, and no setuid/setgid/sticky: what
# tarfile's "data" filter leaves, applied to a directory copy too.
_MODE_MASK = 0o755


class BundleError(Exception):
    pass


def staging_root() -> Path:
    return bundle_roots()[1].parent / ".bundle-staging"


def record_path(name: str) -> Path:
    return bundle_roots()[1] / f"{name}.origin.json"


@contextmanager
def bundle_lock():
    with open(LOCK_PATH, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def _pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def sweep_staging() -> list[Path]:
    """Remove what a killed run left in staging: `<bundle>.<pid>[.old]` dirs
    whose pid isn't running. `/etc` persists, so nothing else would."""
    removed = []
    root = staging_root()
    if not root.is_dir():
        return removed
    for d in root.iterdir():
        parts = d.name.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and _pid_running(int(parts[1])):
            continue
        shutil.rmtree(d, ignore_errors=True)
        removed.append(d)
    return removed


def drop_empty_staging() -> None:
    """Remove the staging dir once nothing is left in it, so a finished
    verb leaves nothing behind in /etc."""
    try:
        staging_root().rmdir()
    except OSError:
        pass


def new_staging(name: str) -> Path:
    root = staging_root()
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    d = root / f"{name}.{os.getpid()}"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(mode=0o755)
    return d


def extract_tar(tar: Path, dest: Path) -> None:
    """Regular files and dirs only; links and devices are refused by name.
    The "data" filter refuses absolute and `..` paths and drops owners."""
    try:
        with tarfile.open(tar) as tf:
            members = tf.getmembers()
            bad = [m.name for m in members if not (m.isfile() or m.isdir())]
            if bad:
                raise BundleError(f"bundle holds links or special files: {', '.join(bad)}")
            bad = [m.name for m in members
                   if m.name.startswith("/") or ".." in Path(m.name).parts]
            if bad:
                raise BundleError(f"bundle paths leave the bundle: {', '.join(bad)}")
            tf.extractall(dest, members=members, filter="data")
    except (tarfile.TarError, OSError) as e:
        raise BundleError(f"can't unpack the bundle: {e}") from None


def copy_dir(src: Path, dest: Path) -> None:
    """Copy regular files and dirs, without owner, xattrs or labels.
    Symlinks are refused by name, never followed."""
    for top, dirs, files in os.walk(src):
        rel = Path(top).relative_to(src)
        for n in dirs + files:
            st = os.lstat(Path(top) / n)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise BundleError(f"not a regular file or dir: {rel / n}")
        for n in dirs:
            (dest / rel / n).mkdir(mode=0o755)
        for n in files:
            out = dest / rel / n
            shutil.copyfile(Path(top) / n, out)
            os.chmod(out, stat.S_IMODE(os.lstat(Path(top) / n).st_mode) & _MODE_MASK)


def relabel(path: Path) -> None:
    if selinux_enabled() and shutil.which("restorecon"):
        r = subprocess.run(["restorecon", "-R", str(path)], capture_output=True, text=True)
        if r.returncode != 0:
            raise BundleError(f"restorecon {path} failed: {r.stderr.strip()}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hashes(root: Path) -> dict[str, str]:
    """{relpath: sha256} of every regular file under `root`."""
    return {p.relative_to(root).as_posix(): _sha256(p)
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def dir_digest(files: dict[str, str]) -> str:
    """A directory source's digest: the hash of its sorted file map."""
    blob = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def root_run_refs(data: dict) -> set[str]:
    """The files a workload TOML has host root run: `[host] setup` and
    `[build] script`."""
    refs = {data.get("host", {}).get("setup"), data.get("build", {}).get("script")}
    return {r for r in refs if isinstance(r, str) and r}


def root_run_files(bundle_dir: Path, extra_refs: set[str] = frozenset()) -> dict[str, str]:
    """{ref: sha256} of the bundle's root-run files: what its workload.toml
    and `extra_refs` (the TOMLs of instances using it) name, plus policy.cil.
    An absolute ref names a host file, not bundle content, and maps to
    "absolute"; a relative one the bundle lacks is left out."""
    try:
        data = tomllib.loads((bundle_dir / "workload.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise BundleError(f"bundle workload.toml unreadable: {e}") from None
    refs = root_run_refs(data) | set(extra_refs)
    if (bundle_dir / POLICY_CIL).is_file():
        refs.add(POLICY_CIL)
    out = {}
    for ref in sorted(refs):
        if os.path.isabs(ref):
            out[ref] = "absolute"
            continue
        path = (bundle_dir / ref).resolve()
        if path.is_relative_to(bundle_dir.resolve()) and path.is_file():
            out[ref] = _sha256(path)
    return out


def changed_root_run(new: dict[str, str], old: dict[str, str]) -> list[str]:
    """Root-run files that are new, or whose hash differs, against `old`."""
    return sorted(ref for ref, h in new.items() if old.get(ref) != h)


def containerfiles(bundle_dir: Path) -> list[str]:
    return sorted(p.relative_to(bundle_dir).as_posix() for p in bundle_dir.rglob("*")
                  if p.is_file() and p.name.startswith(("Containerfile", "Dockerfile")))


def read_record(name: str) -> dict | None:
    try:
        return json.loads(record_path(name).read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise BundleError(f"unreadable record {record_path(name)}: {e}") from None


def recorded_source(record: dict) -> tuple[str, str]:
    """("oci", ref) or ("dir", abs path)."""
    kind, _, value = record.get("source", "").partition(":")
    if kind not in ("oci", "dir") or not value:
        raise BundleError(f"record has no usable source: {record.get('source')!r}")
    return kind, value


def origin(name: str) -> str | None:
    """`oci <ref>@<digest>` or `dir <path>` for a recorded bundle, else None."""
    try:
        record = read_record(name)
        if record is None:
            return None
        kind, value = recorded_source(record)
    except BundleError:
        return None
    return f"oci {value}@{record.get('digest')}" if kind == "oci" else f"dir {value}"


def make_record(source: str, digest: str, files: dict[str, str],
                root_run: dict[str, str]) -> dict:
    return {"source": source, "digest": digest,
            "added": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": files, "root_run": root_run}


def write_record(name: str, record: dict) -> None:
    path = record_path(name)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.rename(tmp, path)


def remove_record(name: str) -> None:
    record_path(name).unlink(missing_ok=True)


def drift(bundle_dir: Path, record: dict) -> list[str]:
    """Files added, removed or changed since the record was written."""
    now = tree_hashes(bundle_dir) if bundle_dir.is_dir() else {}
    was = record.get("files", {})
    return sorted(rel for rel in now.keys() | was.keys() if now.get(rel) != was.get(rel))


def swap_in(staged: Path, name: str) -> None:
    """Move `staged` to `<root>/<name>`. An existing bundle goes aside into
    staging first, so it's missing between the two renames."""
    root = bundle_roots()[1]
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = root / name
    old = None
    if target.exists():
        old = staging_root() / f"{name}.{os.getpid()}.old"
        shutil.rmtree(old, ignore_errors=True)
        os.rename(target, old)
    os.rename(staged, target)
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def remove_bundle(name: str) -> None:
    """Move the bundle dir into staging, then delete it, so the root never
    holds a half-deleted bundle. The root goes too once empty: swap_in made
    it, and on an image-based host it would stay in the config diff."""
    root = bundle_roots()[1]
    target = root / name
    if target.exists():
        staging_root().mkdir(mode=0o755, parents=True, exist_ok=True)
        gone = staging_root() / f"{name}.{os.getpid()}.rm"
        os.rename(target, gone)
        shutil.rmtree(gone, ignore_errors=True)
    remove_record(name)
    try:
        root.rmdir()
    except OSError:
        pass
