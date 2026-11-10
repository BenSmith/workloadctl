"""A filtered container workload's image, fetched outside its filter.

A filtered workload's egress goes to its own inspector, so a pull by the
workload user would be intercepted and refused. Instead the image is
downloaded by a throwaway `DynamicUser=` uid in a transient unit (the
filter matches only the `_wl-<name>` uid), and root hands the archive to
the workload user's `podman load` on stdin. Unpacking stays rootless.

Nothing the workload controls may run on the host as `_wl-<name>` outside
the filter, so the download is never done as that uid, and the fetch
identity's files are opened by root with O_NOFOLLOW.

The fetch runs as a start step of each filtered container's unit
(`workload-image-fetch <name> <container>`) and from `update`. The unit
runs `podman run --pull=never`.
"""
import contextlib
import fcntl
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from cli_log import info, warn
from config_parser import workload_root_dir
from image_fetch_worker import ARCHIVE_NAME, ERROR_NAME, INSPECT_NAME
from image_ref import source_reference
from podman import Podman
from workload_lib import replace_file_atomically

WORKER = "/usr/libexec/workloadctl/workload-image-fetch-worker"
CACHE_PARENT = "workloadctl-fetch"
# A DynamicUser= unit's CacheDirectory= lives under /var/cache/private.
CACHE_ROOT = Path("/var/cache/private") / CACHE_PARENT
CACHE_LINK_ROOT = Path("/var/cache") / CACHE_PARENT
LOCK_DIR = Path("/run/lock")
RECORD_NAME = "image-fetch.json"

INSPECT_MAX_SEC = 60
COPY_MAX_SEC = 30 * 60
# The workload unit's start must outlast a whole fetch and the load.
START_TIMEOUT_SEC = 35 * 60
LOAD_TIMEOUT_SEC = 30 * 60
# Stored (unpacked) image size over its compressed layers.
UNPACKED_RATIO = 3

POLICIES = ("missing", "newer", "always", "update")


class ImageFetchError(Exception):
    """The fetch failed. The message is formatted for the operator."""


class WorkerFailed(Exception):
    """The transient fetch unit failed. The message is the worker's reason."""


def fetch_unit(name: str) -> str:
    return f"workload-image-fetch-{name}.service"


def cache_dir(name: str) -> Path:
    return CACHE_ROOT / name


def record_path(name: str) -> Path:
    return workload_root_dir(name) / RECORD_NAME


def lock_path(name: str) -> Path:
    return LOCK_DIR / f"workload-image-{name}.lock"


# ---------------- record ----------------

def read_record(name: str) -> dict:
    try:
        data = json.loads(record_path(name).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_record(name: str, image: str, digest: str, image_id: str) -> None:
    record = read_record(name)
    record[image] = {"digest": digest, "image_id": image_id}
    replace_file_atomically(record_path(name),
                            json.dumps(record, indent=2) + "\n",
                            default_mode=0o600, owner=(0, 0))


def up_to_date(entry, digest: str, store_id: str) -> bool:
    """The registry still serves what was loaded, and the store still has
    it under the name."""
    return (isinstance(entry, dict) and bool(store_id)
            and entry.get("digest") == digest
            and entry.get("image_id") == store_id)


# ---------------- the transient unit ----------------

def worker_argv(name: str, args: list[str], runtime_max: int) -> list[str]:
    """`systemd-run` for one worker step. No --pipe: from a unit's start
    step SELinux refuses the bus broker the step's pipe."""
    props = [
        "DynamicUser=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "NoNewPrivileges=yes",
        f"RuntimeMaxSec={runtime_max}",
        f"CacheDirectory={CACHE_PARENT}/{name}",
    ]
    argv = ["systemd-run", "--wait", "--collect", "--quiet",
            f"--unit={fetch_unit(name)}"]
    for prop in props:
        argv += ["-p", prop]
    return argv + [WORKER, *args]


def stop_leftover_unit(name: str) -> None:
    """Stop a fetch unit an earlier, killed start left running.

    The lock is the start step's, not the unit's: a start timeout or a
    `systemctl stop` kills the step, and the unit runs on until its
    RuntimeMaxSec."""
    subprocess.run(["systemctl", "stop", fetch_unit(name)],
                   capture_output=True, check=False, timeout=90)


def clear_cache(name: str) -> None:
    shutil.rmtree(cache_dir(name), ignore_errors=True)


def remove_cache(name: str) -> None:
    """For `disable --purge`: the cache directory and systemd's link to it."""
    clear_cache(name)
    with contextlib.suppress(OSError):
        (CACHE_LINK_ROOT / name).unlink()


def _open_cache_file(name: str, filename: str) -> int:
    """An fd on a regular file the fetch identity wrote, never a link."""
    dfd = os.open(cache_dir(name), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=dfd)
    finally:
        os.close(dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{filename} in the fetch cache is not a regular file")
    return fd


def _read_cache_file(name: str, filename: str, limit: int = 65536) -> str:
    fd = _open_cache_file(name, filename)
    with os.fdopen(fd, "rb") as f:
        return f.read(limit).decode(errors="replace")


def run_worker(name: str, args: list[str], runtime_max: int) -> None:
    result = subprocess.run(worker_argv(name, args, runtime_max),
                            capture_output=True, text=True,
                            timeout=runtime_max + 60)
    if result.returncode == 0:
        return
    try:
        reason = _read_cache_file(name, ERROR_NAME).strip()
    except OSError:
        reason = ""
    if not reason:
        reason = (result.stderr.strip()
                  or f"{fetch_unit(name)} failed (exit {result.returncode}); "
                     f"see journalctl -u {fetch_unit(name)}")
    raise WorkerFailed(reason)


def inspect(name: str, image: str) -> dict:
    run_worker(name, ["inspect", image], INSPECT_MAX_SEC)
    data = json.loads(_read_cache_file(name, INSPECT_NAME))
    if not isinstance(data, dict) or not isinstance(data.get("digest"), str):
        raise WorkerFailed(f"unreadable {INSPECT_NAME}")
    return data


# ---------------- free space ----------------

def _free(path: Path) -> tuple[int, int]:
    """(device, free bytes) of the filesystem holding path or its nearest
    existing parent."""
    while not path.exists() and path != path.parent:
        path = path.parent
    st = os.statvfs(path)
    return os.stat(path).st_dev, st.f_bavail * st.f_frsize


def space_shortfalls(size: int, cache: tuple[int, int],
                     volume: tuple[int, int]) -> list[str]:
    """What a fetch of `size` compressed bytes lacks, per filesystem.

    The cache holds the temporary layout and the archive (2 × size). The
    volume holds the load's own copy and the unpacked image
    ((1 + UNPACKED_RATIO) × size). On one filesystem the archive is still
    there during the load."""
    cache_dev, cache_free = cache
    volume_dev, volume_free = volume
    need_cache = 2 * size
    need_volume = (1 + UNPACKED_RATIO) * size
    if cache_dev == volume_dev:
        need = max(need_cache, size + need_volume)
        if need > volume_free:
            return [f"needs {_gib(need)} free, has {_gib(volume_free)}"]
        return []
    out = []
    if need_cache > cache_free:
        out.append(f"the fetch cache needs {_gib(need_cache)} free, has "
                   f"{_gib(cache_free)}")
    if need_volume > volume_free:
        out.append(f"the workload volume needs {_gib(need_volume)} free, "
                   f"has {_gib(volume_free)}")
    return out


def _gib(n: int) -> str:
    return f"{n / 2**30:.1f} GiB"


def check_space(config, image: str, size) -> None:
    if size is None:
        warn(f"  ⚠ The registry gave no layer sizes for '{image}'; free "
             f"space not checked")
        return
    short = space_shortfalls(size, _free(CACHE_ROOT),
                             _free(Path(config.home_dir)))
    if short:
        raise ImageFetchError(
            f"Not fetching '{image}' ({_gib(size)} compressed): "
            + "; ".join(short))


# ---------------- load ----------------

def clear_load_leftovers(home_dir) -> None:
    """Delete the temp copies a killed `podman load` left in the home.

    Regular files only: the home is the workload user's, and unlinking a
    link it planted removes just the link."""
    with contextlib.suppress(OSError), os.scandir(home_dir) as entries:
        for entry in entries:
            if (entry.name.startswith("podman")
                    and entry.name[len("podman"):].isdigit()
                    and entry.is_file(follow_symlinks=False)):
                with contextlib.suppress(OSError):
                    os.unlink(entry.path)


def load_archive(username: str, uid: int, home_dir, stdin,
                 timeout: int | None = None) -> subprocess.CompletedProcess:
    """`podman load` from stdin as the workload user.

    On stdin, because a path in the workload home may be a link it
    planted. TMPDIR is the home, where the load's own copy must land for
    that user to write it."""
    return subprocess.run(
        ["sudo", "-n", "-u", username,
         "-E", f"XDG_RUNTIME_DIR=/run/user/{uid}",
         "-E", f"HOME={home_dir}",
         "-E", f"TMPDIR={home_dir}",
         "podman", "load"],
        stdin=stdin, capture_output=True, cwd=home_dir, timeout=timeout,
    )


def _load_fetched(config, image: str) -> None:
    fd = _open_cache_file(config.name, ARCHIVE_NAME)
    try:
        result = load_archive(config.username, config.uid, config.home_dir,
                              fd, timeout=LOAD_TIMEOUT_SEC)
    finally:
        os.close(fd)
    if result.returncode != 0:
        raise ImageFetchError(
            f"Failed to load the fetched '{image}': "
            f"{result.stderr.decode(errors='replace').strip()}")


# ---------------- the fetch ----------------

@contextlib.contextmanager
def workload_lock(name: str):
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path(name), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def fetch_image(config, cname: str, image: str, policy: str) -> str:
    """Bring `image` into the workload user's store per `policy`.

    `missing` fetches only when the store lacks the image. `newer`,
    `always` and `update` ask the registry, and fetch only when its digest
    differs from the recorded one or the store no longer holds the
    recorded image. An unreachable registry is a warning for `newer` with
    a local image, and an error otherwise.

    Returns "unchanged" or "loaded"; raises ImageFetchError.
    """
    if policy not in POLICIES:
        raise ValueError(f"no fetch for pull policy {policy!r}")
    name = config.name
    pod = Podman.for_user(config.username, config.uid, config.home_dir)
    with workload_lock(name):
        stop_leftover_unit(name)
        clear_cache(name)
        clear_load_leftovers(config.home_dir)

        store_id = pod.image_id(image)
        if policy == "missing" and store_id:
            return "unchanged"

        try:
            found = inspect(name, image)
        except (WorkerFailed, OSError, ValueError) as e:
            if policy == "newer" and store_id:
                warn(f"  ⚠ {cname}: could not ask the registry about "
                     f"'{image}' (the fetch runs outside the workload's "
                     f"filter): {e}. Using the local image.")
                return "unchanged"
            raise ImageFetchError(
                f"Fetching '{image}' outside the workload's filter failed: "
                f"{e}") from None
        finally:
            clear_cache(name)

        digest = found["digest"]
        if up_to_date(read_record(name).get(image), digest, store_id):
            return "unchanged"

        check_space(config, image, found.get("size"))
        info(f"  {cname}: fetching '{image}' ({digest[:19]}) outside the "
             f"workload's filter...")
        try:
            run_worker(name, ["copy", source_reference(image, digest), image],
                       COPY_MAX_SEC)
            _load_fetched(config, image)
        except (WorkerFailed, OSError) as e:
            raise ImageFetchError(
                f"Fetching '{image}' outside the workload's filter failed: "
                f"{e}") from None
        finally:
            clear_cache(name)

        new_id = pod.image_id(image)
        if not new_id:
            raise ImageFetchError(
                f"The fetched archive loaded, but the store has no "
                f"'{image}'")
        write_record(name, image, digest, new_id)
        info(f"  {cname}: loaded '{image}' ({new_id[:12]})")
        return "loaded"


def container_spec(config, cname: str) -> tuple[str, str]:
    """(image, pull policy) of one container of the workload."""
    for spec_cname, image, pull in config.container_specs():
        if spec_cname == cname:
            return image, pull
    raise ImageFetchError(f"{config.name} has no container {cname!r}")
