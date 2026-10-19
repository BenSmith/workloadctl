"""Per-workload user provisioning that does not know which substrate it serves.

The half of `libexec/workload-ensure-user` that runs for every workload: the
home directory, the environment file, the SELinux labels, the provenance
record. A function belongs here when it cannot tell a VM from a container --
not when it merely happens to be called from both branches today.

`setup_workload_runtime_dir`, `generate_egress_ca` and
`provision_egress_pki_dirs` are keyed on the workload NAME and read nothing
under `[vm]`, which is what lets the container egress path call them verbatim
rather than grow a second copy. Their names must stay substrate-neutral for
the same reason. The PATH the first one operates on is still
`/run/workload-vm/<name>`, and that is not an oversight: the string is an
SELinux fcontext rule the RPM registers, so it is an interface rather than a
name we are free to correct.

`log` is reached as `ensure_common.log(...)` from every other module, never
imported by name. `from ensure_common import log` would COPY the binding, and
a test that then patched the copy would silence nothing while the real writer
ran. That failure is not symmetric: a patch an assertion reads back fails
loudly, but a patch installed only to quiet the journal goes inert and the
test still passes. Fifteen sites patch this function; routing it through the
module leaves exactly one binding to patch, and it is the one every caller
resolves at call time. (The generator's `log_msg` is imported by name because
nothing patches it -- the difference is the traffic, not the taste.)
"""

import fcntl
import grp
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import deployment
from config_parser import workload_root_dir
from workload_lib import (
    EGRESS_PKI_BASE, RUN_SYSTEMD_SYSTEM, workload_data_dir,
    workload_egress_dir, workload_state_dir,
)
from workload_mcs import CONTAINER_TREE_TYPE, VM_TREE_TYPE, mcs_level
from run_files import workload_env_dir
from moatery.egress_ca import (
    ca_cert_path, ca_dir, denial_dir, leaf_dir, ca_key_path,
)
from config_parser import SOCKET_DIR
from egress_policy import POLICY_DIRNAME
from guest_ca import container_ca_bundle_path, host_trust_bundle

# moatery's CA mint: the one place the CA's openssl invocation and its
# refusals live, so the inspector that signs with the CA and the step that
# makes it cannot disagree about what a CA is.
CA_MINT_BIN = "/usr/libexec/moatery/moat-mint-ca"


def log(msg):
    """Print to stdout (captured by systemd journal)."""
    print(msg, flush=True)


def warn_if_stale_home(pw, name):
    """Warn (don't fix) when a workload user's passwd home doesn't match the expected state/ dir.

    The workload service is unaffected — the generator forces Environment=HOME=<state>
    in the unit — but podman's auto-generated healthcheck timer runs a bare
    `podman healthcheck run` that inherits the user manager's HOME (= the mismatched
    passwd home), resolves an empty graphroot, can't find the container, and leaves
    health frozen at 'starting' forever.

    We only warn: rewriting an in-use user's home (usermod -d) requires stopping
    the workload and bouncing user@<uid>.service to take effect, which is an
    operator decision, not something to do under an ExecStartPre on every boot.
    """
    expected = str(workload_state_dir(name))
    actual = pw.pw_dir
    if actual == expected:
        return
    uid = pw.pw_uid
    log(f"  WARNING: mismatched home for {pw.pw_name}: {actual!r} (expected {expected!r}).")
    log( "           The service runs correctly, but podman's healthcheck timer "
         "inherits this home and reads an empty graphroot, so health is frozen at 'starting'.")
    log(f"           Fix: systemctl stop workload-{name}; usermod -d {expected} "
        f"{pw.pw_name}; systemctl restart workload-{name}  "
        f"(restarting bounces user@{uid}.service so the new HOME takes effect).")


def setup_home_directory(pw, name):
    """Create and configure the workload's state/ ($HOME) and data/ subdirs.

    Anchored on workload_state_dir/workload_data_dir, not pw.pw_dir: the generator
    forces HOME=<state> independently, so these must land where the service actually
    reads/writes regardless of what passwd records. See warn_if_stale_home.
    """
    state_path = workload_state_dir(name)
    if not state_path.exists():
        log(f"  Creating home (state) directory {state_path}")
        state_path.mkdir(parents=True, exist_ok=True)
    os.chown(state_path, pw.pw_uid, pw.pw_gid)
    os.chmod(state_path, 0o700)

    data_path = workload_data_dir(name)
    if not data_path.exists():
        log(f"  Creating data directory {data_path}")
        data_path.mkdir(parents=True, exist_ok=True)
    os.chown(data_path, pw.pw_uid, pw.pw_gid)
    os.chmod(data_path, 0o700)


def record_deployment_provenance(name):
    """Stamp the workload's /var root with the deployment provisioning it now.

    /etc is per-deployment on ostree and /var is shared, so `bootc rollback`
    takes a workload's config and passwd line away while its state stays behind
    — and `cleanup`'s definition of an orphan ("state with no config") is then
    satisfied by state another deployment still owns. The stamp is how cleanup
    tells the two apart; see lib/deployment.py for the rule it feeds.

    Runs after setup_home_directory, which creates the root. Best-effort by
    design: a missing stamp costs exactly the pre-marker behavior, so warning
    and continuing is strictly better than failing a service start over it.
    """
    root = workload_root_dir(name)
    try:
        if deployment.write_marker(root, name):
            log(f"  Recorded deployment provenance in {deployment.marker_path(root)}")
    except Exception as e:
        log(f"  WARNING: Failed to record deployment provenance for {name}: {e}")


# The group file systemd-sysusers writes memberships into, the image's own,
# which NSS reads (nss-altfiles) and nothing writes, and the lock both
# sysusers and the shadow tools take before writing the first.
ETC_GROUP = Path("/etc/group")
IMAGE_GROUP = Path("/usr/lib/group")
PASSWD_LOCK = Path("/etc/.pwd.lock")


def join_image_groups(name):
    """Give the workload user the memberships its sysusers config could not.

    The config's `m` lines name the user's groups: kvm for a VM, and each of
    extra_groups. systemd-sysusers writes a membership into the group's line
    in /etc/group, and a group an image defines only in /usr/lib/group (video,
    render and input on Fedora bootc) has no such line: sysusers reports
    success and the user is not a member, and so does `usermod -aG`. So each
    such group's line is copied into /etc/group, and sysusers is run again for
    the memberships alone.

    Raises: a user without its groups starts without the devices they open.
    """
    conf = RUN_SYSTEMD_SYSTEM / f"workload-{name}.conf"
    try:
        lines = conf.read_text().splitlines()
    except FileNotFoundError:
        return
    wanted = [line.split()[1:3] for line in lines if line.startswith("m ")]

    def missing():
        return [(user, group) for user, group in wanted
                if user not in grp.getgrnam(group).gr_mem]

    absent = missing()
    if not absent:
        return
    image = {}
    if IMAGE_GROUP.exists():
        image = {line.split(":", 1)[0]: line
                 for line in IMAGE_GROUP.read_text().splitlines()
                 if line and not line.startswith("#")}
    with os.fdopen(os.open(PASSWD_LOCK, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC,
                           0o600), "w") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX)
        text = ETC_GROUP.read_text()
        present = {line.split(":", 1)[0] for line in text.splitlines()}
        copy = [image[group] for group in dict.fromkeys(g for _, g in absent)
                if group not in present and group in image]
        if copy:
            with open(ETC_GROUP, "a") as f:
                if text and not text.endswith("\n"):
                    f.write("\n")
                f.write("".join(line + "\n" for line in copy))
            log(f"  Copied {', '.join(line.split(':', 1)[0] for line in copy)} "
                f"from {IMAGE_GROUP} into {ETC_GROUP}")
    subprocess.run(["systemd-sysusers", "--inline",
                    *(f"m {user} {group}" for user, group in absent)],
                   check=True, capture_output=True, text=True)
    still = missing()
    if still:
        raise RuntimeError(
            "not a member of " + ", ".join(group for _, group in still)
            + f": no line in {ETC_GROUP} or {IMAGE_GROUP} to add it to")


def _provision_dir_secure(root_dir, host_path, uid, gid, mode):
    """Create `host_path` (a descendant of `root_dir`) and chown/chmod it to the
    workload user WITHOUT ever following a symlink (B1 — root-TOCTOU hardening).

    This runs as **root** on every service start inside a tree the *workload
    user* owns, so a `resolve()`-then-`os.chown()` sequence is racy: the workload
    user can swap a path component to a symlink between the containment check and
    the chown, tricking root into chowning an arbitrary host file. We instead
    descend from `root_dir` one literal component at a time with
    `O_NOFOLLOW|O_DIRECTORY` (openat) and `fchown`/`fchmod` the final fd. A
    symlink anywhere on the path makes the openat fail (ELOOP) and we refuse —
    the walk itself enforces containment, so a swapped component can only abort
    provisioning, never escape the tree. `root_dir` is root-created and trusted
    as the anchor.

    Returns True on success, False if a component was unsafe (symlink/non-dir).
    """
    # Walk the LITERAL path components (not host_path.resolve(), which would
    # collapse away the very symlink we must refuse). `root_dir` is the trusted,
    # root-created anchor; every component below it is opened O_NOFOLLOW.
    try:
        parts = host_path.relative_to(root_dir).parts
    except ValueError:
        return False  # not lexically under the root — caller also gates this
    if not parts:
        # host_path == root_dir: chowning the anchor would hand the workload
        # user ownership of the root-owned trust boundary this walk relies on.
        log(f"  WARNING: refusing to provision {host_path}: it is the "
            f"workload root itself")
        return False
    if ".." in parts:
        log(f"  WARNING: refusing to provision {host_path}: '..' in path")
        return False
    dir_fd = os.open(str(root_dir), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            child_fd = None
            for _ in range(2):
                try:
                    child_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dir_fd)
                    break
                except FileNotFoundError:
                    try:
                        os.mkdir(part, mode, dir_fd=dir_fd)
                    except FileExistsError:
                        pass  # created concurrently — retry the O_NOFOLLOW open
                except OSError as exc:
                    # ELOOP (symlink) or ENOTDIR — refuse to traverse.
                    log(f"  WARNING: refusing to provision {host_path}: unsafe "
                        f"path component {part!r} ({exc.strerror})")
                    return False
            if child_fd is None:
                log(f"  WARNING: refusing to provision {host_path}: unsafe "
                    f"path component {part!r}")
                return False
            os.close(dir_fd)
            dir_fd = child_fd
        os.fchown(dir_fd, uid, gid)
        os.fchmod(dir_fd, mode)
        return True
    finally:
        os.close(dir_fd)


def volume_dir_mode(name, host_path):
    """The mode a volume's host directory is given: 0755, so container users
    other than the workload's own can traverse it, except when the volume is
    the workload's data/ or state/ itself. Those stay 0700: under the
    root-owned workload root, they are what keeps the tree from every other
    host account."""
    if host_path in (workload_data_dir(name), workload_state_dir(name)):
        return 0o700
    return 0o755


def _make_missing_dirs_secure(root_dir, host_path, uid, gid, mode):
    """Create the directories missing on the way to `host_path` (a descendant
    of `root_dir`), `host_path` included, owned by the workload user. A
    directory already there is left as it is: it is the workload's own.

    The same no-follow walk as `_provision_dir_secure`, so a symlink on the
    path refuses rather than redirects. Returns True on success, False if a
    component was unsafe.
    """
    try:
        parts = host_path.relative_to(root_dir).parts
    except ValueError:
        return False
    if ".." in parts:
        log(f"  WARNING: refusing to create {host_path}: '..' in path")
        return False
    dir_fd = os.open(str(root_dir), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            try:
                os.mkdir(part, mode, dir_fd=dir_fd)
                made = True
            except FileExistsError:
                made = False
            try:
                child_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=dir_fd)
            except OSError as exc:
                log(f"  WARNING: refusing to create {host_path}: unsafe "
                    f"path component {part!r} ({exc.strerror})")
                return False
            os.close(dir_fd)
            dir_fd = child_fd
            if made:
                os.fchown(dir_fd, uid, gid)
                os.fchmod(dir_fd, mode)
        return True
    finally:
        os.close(dir_fd)


def _descend_nofollow(root_dir, parts, what: str):
    """Open the directory at `parts` below `root_dir`, one literal component at a
    time, never following a symlink — the non-creating half of the walk
    `_provision_dir_secure` documents at length, factored out because more than
    one caller needs root to reach a path inside a tree the workload user owns.

    Returns the final directory fd (the CALLER closes it), or None if a
    component was missing, not a directory, or a symlink.
    """
    dir_fd = os.open(str(root_dir), os.O_RDONLY | os.O_DIRECTORY)
    for part in parts:
        try:
            child_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=dir_fd)
        except FileNotFoundError:
            os.close(dir_fd)
            return None
        except OSError as exc:
            log(f"  WARNING: refusing to {what}: unsafe path "
                f"component {part!r} ({exc.strerror})")
            os.close(dir_fd)
            return None
        os.close(dir_fd)
        dir_fd = child_fd
    return dir_fd


def _write_file_nofollow(root_dir, host_path, content: bytes, uid, gid,
                         mode) -> bool:
    """Replace the file `host_path` (below `root_dir`) with `content`, owned
    uid:gid at `mode`, without following a symlink.

    Root writes these into a directory the workload user owns, so anything at
    the name may be a link it planted. The directory is reached by
    `_descend_nofollow`, the content goes to a temp created
    O_EXCL|O_NOFOLLOW, and the rename replaces whatever is at the name rather
    than writing through it. Returns True, or False if a component on the way
    was unsafe.
    """
    host_path = Path(host_path)
    try:
        parts = host_path.parent.relative_to(root_dir).parts
    except ValueError:
        return False
    if ".." in parts:
        return False
    dir_fd = _descend_nofollow(root_dir, parts, f"write {host_path}")
    if dir_fd is None:
        return False
    tmp = f".{host_path.name}.tmp"
    try:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dir_fd)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view):]
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, host_path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return True
    finally:
        os.close(dir_fd)


def _read_file_nofollow(root_dir, host_path, limit: int = 1 << 20):
    """The bytes of the file `host_path` (below `root_dir`), read without
    following a symlink; None if it is missing, a link, not a regular file,
    hardlinked, larger than `limit`, or below an unsafe component.

    What root reads here can reach a place the workload user reads back (the
    seed ISO), so a link at the name must not lend it another file.
    """
    host_path = Path(host_path)
    try:
        parts = host_path.parent.relative_to(root_dir).parts
    except ValueError:
        return None
    if ".." in parts:
        return None
    dir_fd = _descend_nofollow(root_dir, parts, f"read {host_path}")
    if dir_fd is None:
        return None
    try:
        fd = os.open(host_path.name,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=dir_fd)
    except OSError:
        return None
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_size > limit):
            return None
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return None if size > limit else b"".join(chunks)
    finally:
        os.close(fd)


def _install_file_nofollow(src, root_dir, host_path, *,
                           replace: bool) -> bool:
    """Move the file `src`, in a root-only directory on the same
    filesystem, to `host_path` below `root_dir`, without following a link.

    The directory is reached by `_descend_nofollow`. With `replace`, a
    rename over whatever is at the name: a link there is replaced, not
    written through. Without it, a hard link that fails if anything is
    there. Returns True, or False if a component was unsafe or, without
    `replace`, the name was taken.
    """
    host_path = Path(host_path)
    try:
        parts = host_path.parent.relative_to(root_dir).parts
    except ValueError:
        return False
    if ".." in parts:
        return False
    dir_fd = _descend_nofollow(root_dir, parts, f"install {host_path}")
    if dir_fd is None:
        return False
    try:
        if replace:
            os.rename(src, host_path.name, dst_dir_fd=dir_fd)
            return True
        try:
            os.link(src, host_path.name, dst_dir_fd=dir_fd,
                    follow_symlinks=False)
        except FileExistsError:
            return False
        os.unlink(src)
        return True
    finally:
        os.close(dir_fd)


# Mounted where SELinux is enabled at all.
SELINUXFS_ENFORCE = Path("/sys/fs/selinux/enforce")


def _label(argv):
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)}: {result.stderr.strip()}")


def stamp_selinux_labels(name, uid, is_vm):
    """Give the workload's tree and its egress PKI the workload's level.

    The rules give both trees their types at s0, and a relabel puts them
    back there; nothing registers the level (workload_mcs), so it is
    stamped here at every setup. The workload root takes one type
    throughout, set with the level in one pass, so no file is at s0
    between the two. The PKI has three types, which restorecon sets
    first; -F because a plain restorecon leaves a file alone while its
    type is a customizable one.

    Raises: a tree left at s0 is open to every workload's processes.
    """
    if not SELINUXFS_ENFORCE.exists():
        return
    level = mcs_level(uid)
    tree_type = VM_TREE_TYPE if is_vm else CONTAINER_TREE_TYPE
    _label(["chcon", "-R", "-h", "-t", tree_type, "-l", level,
            str(workload_root_dir(name))])
    egress = workload_egress_dir(name)
    if egress.is_dir():
        _label(["restorecon", "-RF", str(egress)])
        _label(["chcon", "-R", "-h", "-l", level, str(egress)])


def _detect_host_ip():
    """Return the host's primary LAN IP via the default route, or empty string.

    Uses the source address that would be chosen to reach 1.1.1.1, which
    selects the default-route interface and ignores secondary addresses (e.g.
    libvirt bridges, VPN tuns). Override by setting HOST_IP in the workload's
    [container.environment] in its TOML — an explicit value there takes
    precedence over the EnvironmentFile.
    """
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            stderr=subprocess.DEVNULL, text=True
        )
        for token, nxt in zip(out.split(), out.split()[1:]):
            if token == "src":
                return nxt
    except Exception:
        pass
    return ""


def write_environment_file(name, pw, config):
    """Write UID-dependent environment variables for the systemd service.

    The generated service uses EnvironmentFile= to pick up XDG_RUNTIME_DIR
    (which depends on the UID). This allows the generator to create service
    files before the user exists.
    """
    # No mode= here: systemd/workloads-dirs.conf owns this directory's mode and
    # tmpfiles runs under sysinit.target, long before any workload's
    # ExecStartPre — so exist_ok=True makes a mode= argument dead, and 0700
    # would be wrong anyway (see that file: the workload user must traverse
    # this dir to read its own --env-file). Bare mkdir is the boot-order
    # fallback only.
    env_dir = workload_env_dir()
    env_dir.mkdir(parents=True, exist_ok=True)

    lines = [
        f"XDG_RUNTIME_DIR=/run/user/{pw.pw_uid}",
        f"HOST_IP={_detect_host_ip()}",
    ]

    env_file = env_dir / f"workload-{name}.env"
    env_file.write_text("\n".join(lines) + "\n")
    log(f"  Wrote environment file {env_file}")


def setup_workload_runtime_dir(pw, name: str):
    """Create the runtime directory /run/workload-vm/{name}/, labelled.

    Both substrates: a VM's QMP and console sockets, and a filtered
    container's inspect.json. The path keeps `workload-vm` in it because the
    RPM registers an fcontext rule on that exact string.

    The relabel is REQUIRED, and registering the fcontext rule is not enough on
    its own. The kernel labels a newly created file from its parent directory,
    not from `file_contexts` — that file is consulted only by userspace tools
    like restorecon. So the rule the RPM's %post registers
    (`/run/workload-vm(/.*)? -> svirt_var_run_t`) does nothing for a directory
    mkdir'd here: it inherits `var_run_t` from /run, and a confined QEMU then
    cannot create its QMP socket, cannot read the cloud-init ISO, and fails to
    start rather than degrading. /run is a tmpfs, so this recurs every boot.

    It happens HERE, before anything is written into the directory, because
    everything created inside afterwards (the sockets, cloud-init.iso) inherits
    from the directory — relabelling later would leave those behind.

    Plain restorecon, no -F: var_run_t is not a customizable type, unlike the
    container_file_t/svirt_image_t pair under /var/lib/workloads.
    """
    sock_dir = SOCKET_DIR / name
    sock_dir.mkdir(parents=True, exist_ok=True)
    # The inspector's and responder's inputs, beside the runtime dir and not
    # in it: the runtime dir is the workload uid's, and anything in it QEMU
    # could replace (egress_policy.POLICY_DIR). Root's, 0750 with the
    # workload's group so the services read it; made before the relabel so
    # it carries the same label they already read.
    policy = SOCKET_DIR / POLICY_DIRNAME / name
    policy.parent.mkdir(mode=0o755, exist_ok=True)
    policy.mkdir(mode=0o750, exist_ok=True)
    os.chown(policy, 0, pw.pw_gid)
    os.chmod(policy, 0o750)
    if shutil.which("restorecon"):
        # Recursive and rooted at the parent: the parent is what the rule names,
        # and a wrong label there is inherited by every workload's subdirectory.
        subprocess.run(["restorecon", "-R", str(SOCKET_DIR)],
                       check=False, capture_output=True)
    os.chown(sock_dir, pw.pw_uid, pw.pw_gid)
    os.chmod(sock_dir, 0o750)
    log(f"  Socket directory: {sock_dir}")


def _mint_ca_into(name: str, state_dir: Path) -> None:
    """Run the mint against `state_dir`, or raise with what it said."""
    try:
        result = subprocess.run(
            [CA_MINT_BIN, "--name", name, "--state-dir", str(state_dir)],
            capture_output=True, text=True,
        )
    except OSError as exc:
        raise RuntimeError(
            f"moat-mint-ca (egress CA) could not run: {exc}") from exc
    if result.returncode != 0:
        # Both streams, as _ssh_keygen reports them: a program that could
        # not start says so on either, and one of them is empty.
        said = " / ".join(s.strip() for s in (result.stdout, result.stderr)
                          if s.strip())
        raise RuntimeError(
            f"moat-mint-ca (egress CA) failed: "
            f"{said or f'no output, exit {result.returncode}'}")


def egress_anchor(name: str) -> Path:
    """The workload's directory in the egress PKI tree: root's, 0711 so
    the inspector, as the workload user, reaches its caches through it."""
    EGRESS_PKI_BASE.mkdir(mode=0o711, parents=True, exist_ok=True)
    anchor = workload_egress_dir(name)
    try:
        anchor.mkdir(mode=0o711)
    except FileExistsError:
        pass
    st = os.lstat(anchor)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        raise RuntimeError(f"{anchor} is not root's directory")
    os.chmod(anchor, 0o711)
    return anchor


def generate_egress_ca(pw, name: str):
    """Mint this workload's egress CA if absent, or raise with the mint's words.

    Symmetric to generate_vm_host_keypair, and here for the same reason it is:
    the seed ISO carries this certificate, so "before the seed" has to be a fact
    about one function rather than an ordering between units. Both are called a
    few lines above build_cloud_init_iso in the same process.

    Idempotent, and the guard is what keeps it so. Re-minting would invalidate
    the anchor already installed in a provisioned guest exactly as churning the
    host key would invalidate the SSH pin -- and worse, because cloud-init runs
    once per instance-id, so the replacement never arrives and every HTTPS
    request fails validation on a VM `diagnose` calls healthy.

    Generated for every filtered VM whatever `tls` says. Gating it on
    tls = "inspect" would turn the emergency splice into a one-way door: the
    seed is fingerprinted over its rendered text, so dropping the CA out of it
    rotates the instance-id and re-provisions the guest in the middle of the
    incident the hatch exists for.

    When it DOES mint, it clears the leaf caches -- see the comment at the end.
    provision_egress_pki_dirs recreates them a moment later, which is why
    removing them here is safe.
    """
    # The workload user owns ca/, so any name there may be a link it
    # planted. The CA is minted in a root-only directory beside it and
    # copied in without following one.
    anchor = egress_anchor(name)
    dir_path = ca_dir(anchor)
    key_path = ca_key_path(anchor)
    cert_path = ca_cert_path(anchor)

    present = [p for p in (key_path, cert_path) if os.path.lexists(p)]
    if len(present) == 2:
        return  # already minted -- keep the guest's anchor valid
    # Half a CA is refused, naming both files, rather than re-minted over:
    # the half that is there may be the guest's anchor.
    if present:
        raise RuntimeError(
            f"moat-mint-ca (egress CA): half a CA is there ({present[0]} "
            f"without {({key_path, cert_path} - set(present)).pop()}); "
            f"refusing to mint over it")

    if not _provision_dir_secure(anchor, dir_path, pw.pw_uid, pw.pw_gid,
                                 0o700):
        raise RuntimeError(f"cannot provision {dir_path} safely")

    with tempfile.TemporaryDirectory(prefix=".ca-mint-",
                                     dir=anchor) as mint_dir:
        _mint_ca_into(name, Path(mint_dir))
        for src, dst, mode in (
                (ca_key_path(mint_dir), key_path, 0o600),
                # The certificate is a public anchor that the seed builder
                # and `diagnose` both read; the key is the part worth
                # protecting.
                (ca_cert_path(mint_dir), cert_path, 0o644)):
            if not _write_file_nofollow(anchor, dst,
                                        Path(src).read_bytes(),
                                        pw.pw_uid, pw.pw_gid, mode):
                raise RuntimeError(f"cannot write {dst} safely")

    # A NEW CA MAKES EVERY CACHED LEAF A FORGERY, so the caches go with it.
    # This runs only on the branch that actually minted -- the guard above
    # returns before it for the ordinary case -- and the case it exists for is
    # an operator recovering a lost or damaged CA by deleting its ca/. The
    # leaves are files with a 30-day life, LeafCache adopts any PEM it finds at
    # the hashed path without asking who signed it, and the guest by then
    # trusts only the replacement. The result is a guest that fails handshakes
    # on exactly its established hosts, told by the listener's own log line to
    # re-seed -- which is both the wrong remedy and already done.
    for cache_dir in (leaf_dir(anchor), denial_dir(anchor)):
        shutil.rmtree(cache_dir, ignore_errors=True)

    log(f"  Generated egress CA: {cert_path}")


def write_container_ca_bundle(pw, name: str):
    """Write the bundle a container mounts, from this host's roots now.

    On every start, so a host's root update reaches the container at its
    next one. Beside the CA, so it has the CA's type, which the containers
    may read.
    """
    anchor = egress_anchor(name)
    content = host_trust_bundle(ca_cert_path(anchor).read_bytes())
    if not _write_file_nofollow(anchor, container_ca_bundle_path(anchor),
                                content, pw.pw_uid, pw.pw_gid, 0o644):
        raise RuntimeError(f"cannot write the CA bundle for {name} safely")


def provision_egress_pki_dirs(pw, name: str):
    """Create the leaf caches beside the CA.

    Here rather than left to the minter's own mkdir: a directory the
    inspector made would take its parent's type, and the inspector has no
    `relabelto`. stamp_selinux_labels types them, later in the same setup
    and before the inspector starts.
    """
    anchor = egress_anchor(name)
    for directory in (ca_dir(anchor), leaf_dir(anchor), denial_dir(anchor)):
        if not _provision_dir_secure(anchor, directory,
                                     pw.pw_uid, pw.pw_gid, 0o700):
            raise RuntimeError(f"cannot provision {directory} safely")
