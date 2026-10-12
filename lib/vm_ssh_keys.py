"""The SSH material a VM workload is reached with, and where it lands.

The per-workload client keypair `workloadctl exec`/`shell` dials with, the
VM's host keypair and its pin in the workload's known_hosts (so the first
connection has nothing to trust on faith), and the seeding of the client
pubkey into a virtiofs share that covers the guest home, where cloud-init's
`ssh_authorized_keys` cannot reach (docs/vm-virtiofs.md §8). All of it is
generated once, on the host, as the workload user's files; the seed ISO
reads the results.

`log` is reached as `ensure_common.log(...)`, never imported by name; see that
module's docstring for why the copy matters here specifically.

Installed to /usr/libexec/workloadctl/vm_ssh_keys.py.
"""

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import ensure_common
from config_parser import parse_volume_spec, workload_root_dir
from ensure_common import (
    _descend_nofollow,
    _install_file_nofollow,
    _provision_dir_secure,
    _read_file_nofollow,
    _write_file_nofollow,
)
from vm_defs import VM_DEFAULT_GUEST_USER, VM_GUEST_HOME_BASE
from workload_lib import expand_volume_path, workload_state_dir


def _ssh_keygen(key_path: Path, comment: str, what: str):
    """Write an Ed25519 keypair to key_path, or raise with what ssh-keygen said.

    ssh-keygen talks on **stdout**, not stderr — the key paths, the fingerprint
    and the randomart all go there on success, and a failure like
    `Saving key "/x" failed: Permission denied` goes there too. Reporting
    `result.stderr` alone therefore yields an empty diagnostic on precisely the
    runs where one is needed, so take both streams and say so if there were
    neither.
    """
    result = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment,
         "-f", str(key_path)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return
    said = " / ".join(s.strip() for s in (result.stdout, result.stderr) if s.strip())
    raise RuntimeError(
        f"ssh-keygen ({what}) failed: {said or f'no output, exit {result.returncode}'}")


def _anchor(pw) -> Path:
    """The home's parent, root's: where the no-follow walks start."""
    return Path(pw.pw_dir).parent


def _read_ssh_file(pw, name: str) -> str:
    """~/.ssh/NAME's text, or '' if it is missing or not a plain file: it
    goes into the seed, which the workload user reads back, so a link at
    the name is not followed."""
    data = _read_file_nofollow(_anchor(pw), Path(pw.pw_dir) / ".ssh" / name)
    return data.decode("utf-8", "replace") if data is not None else ""


def _generate_keypair(pw, key_path: Path, comment: str, what: str) -> bool:
    """Generate an Ed25519 keypair at `key_path` (in ~/.ssh) unless one is
    there; True if this call made it.

    ~/.ssh is the workload user's, so ssh-keygen writes into a root-only
    directory in the workload root and the pair is linked into place by the
    no-follow walk: a link at either name is never written through. A key
    that appears meanwhile (ensure_user_lock() should make that unreachable)
    is kept, being as good as ours.
    """
    anchor = _anchor(pw)
    ssh_dir = key_path.parent
    if not _provision_dir_secure(anchor, ssh_dir, pw.pw_uid, pw.pw_gid,
                                 0o700):
        raise RuntimeError(f"cannot provision {ssh_dir} safely")
    if os.path.lexists(key_path):
        return False
    with tempfile.TemporaryDirectory(prefix=".keygen-", dir=anchor) as tmp:
        made = Path(tmp) / key_path.name
        _ssh_keygen(made, comment, what)
        made_pub = made.with_suffix(".pub")
        os.chown(made, pw.pw_uid, pw.pw_gid)
        os.chmod(made, 0o600)
        os.chown(made_pub, pw.pw_uid, pw.pw_gid)
        os.chmod(made_pub, 0o644)
        if not _install_file_nofollow(made, anchor, key_path, replace=False):
            return False
        if not _install_file_nofollow(made_pub, anchor,
                                      key_path.with_suffix(".pub"),
                                      replace=True):
            raise RuntimeError(f"cannot install {key_path}.pub safely")
    return True


def generate_ssh_keypair(pw, name: str):
    """Generate a per-workload Ed25519 SSH keypair if it doesn't exist.

    Raises RuntimeError on failure: the cloud-init ISO depends on the pubkey
    to inject an authorized_keys entry; a missing key would silently produce
    a VM with a passwordless sudoer and no way for `workloadctl exec` to SSH
    in. Better to fail provisioning loudly.
    """
    key_path = Path(pw.pw_dir) / ".ssh" / "id_ed25519"
    if _generate_keypair(pw, key_path, f"workload-{name}@hypervisor",
                         "client key"):
        ensure_common.log(f"  Generated SSH keypair: {key_path}")


def _read_ssh_pubkey(pw) -> str:
    """Return the workload's public SSH key, or '' if not generated yet."""
    return _read_ssh_file(pw, "id_ed25519.pub").strip()


def _validated_guest_user(vm_cfg) -> str:
    """Return [vm].user, refusing anything that is not a POSIX username.

    The value is interpolated unquoted into the built-in #cloud-config
    (`- name: {guest_user}`, just above a NOPASSWD sudo grant) and is joined into
    a host path by seed_vm_home_share_ssh_key, so both callers need the same
    guarantee: a value carrying a newline could inject arbitrary cloud-config,
    and one carrying a slash or '..' could aim the seed at another directory.
    Fail closed — a bad name aborts VM provisioning.
    """
    guest_user = vm_cfg.get("user", VM_DEFAULT_GUEST_USER)
    if not re.match(r'^[a-z_][a-z0-9_-]*$', guest_user) or len(guest_user) > 32:
        raise RuntimeError(
            f"[vm].user {guest_user!r} is not a valid POSIX username "
            f"(^[a-z_][a-z0-9_-]*$, max 32 chars)"
        )
    return guest_user



# An authorized_keys larger than this is not a real one — refuse to read it into
# memory rather than let a workload-owned file dictate root's allocation.
_AUTHORIZED_KEYS_MAX = 1 << 20

def _seed_authorized_keys(root_dir, ssh_dir: Path, pubkey: str, uid, gid) -> bool:
    """Ensure `pubkey` is present in <ssh_dir>/authorized_keys, as the workload user.

    Runs as root inside a tree the workload user owns, so it reaches the file
    through _descend_nofollow and opens it O_NOFOLLOW: a symlink swapped in for
    authorized_keys must fail the open, never redirect root's write. Additive by
    design — an operator's own keys in the file are kept, and a file that already
    carries ours is left byte-identical.

    Returns True if the key was written, False if it was already there.
    Raises RuntimeError if the file cannot be reached or is not a plain file:
    the caller has already decided the guest depends on it.
    """
    parts = (ssh_dir / "authorized_keys").relative_to(root_dir).parts
    dir_fd = _descend_nofollow(root_dir, parts[:-1], f"seed {ssh_dir}")
    if dir_fd is None:
        raise RuntimeError(f"cannot reach {ssh_dir} safely")
    try:
        created = True
        try:
            fd = os.open("authorized_keys",
                         os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=dir_fd)
        except FileExistsError:
            created = False
            try:
                fd = os.open("authorized_keys", os.O_RDWR | os.O_NOFOLLOW,
                             dir_fd=dir_fd)
            except OSError as exc:
                # ELOOP: authorized_keys is a symlink. O_NOFOLLOW turned an
                # arbitrary-file write by the workload user into this error.
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is not a plain file "
                    f"({exc.strerror})") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is not a regular file")
            # A hardlink to a file elsewhere would make this write — and the
            # chown below — reach outside the tree.
            if st.st_nlink != 1:
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys has {st.st_nlink} hardlinks")
            if st.st_size > _AUTHORIZED_KEYS_MAX:
                raise RuntimeError(
                    f"{ssh_dir}/authorized_keys is {st.st_size} bytes — refusing to read")
            existing = os.read(fd, st.st_size).decode("utf-8", "replace")
            present = pubkey.strip() in (ln.strip() for ln in existing.splitlines())
            if not present:
                os.lseek(fd, 0, os.SEEK_END)
                if existing and not existing.endswith("\n"):
                    os.write(fd, b"\n")
                os.write(fd, pubkey.strip().encode() + b"\n")
            os.fchown(fd, uid, gid)
            # Only force the mode when we made the file or when sshd's
            # StrictModes would reject what is there (group/other bits): an
            # operator's deliberate 0640 is none of our business.
            if created or st.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            return not present
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def seed_vm_home_share_ssh_key(pw, config):
    """Put the workload's pubkey in a [vm].volumes share mounted at the guest home.

    cloud-init writes ~/.ssh/authorized_keys in its *init* stage and mounts
    [vm].volumes in the *config* stage that follows, so a share whose guest path
    is the login user's home covers the only key the CLI has. The guest boots
    perfectly healthy and `workloadctl exec`/`shell` fail authentication — on
    every boot, not just the first, since the fstab entry mounts before sshd.

    Seeding the share host-side is what makes such a TOML self-sufficient:
    without it the working configuration lives in an operator's shell history,
    and a purge, a restore onto an empty share, or the same bundle stamped on
    another host all produce a VM nobody can log into.

    Skips (with a warning) a share outside the workload tree: the no-follow walk
    needs a root-owned anchor to be safe, and an operator who mounts a directory
    of their own at the guest home owns what is in it.
    """
    vm_cfg = config.get("vm", {})
    volumes = vm_cfg.get("volumes", [])
    if not volumes:
        return
    name = config["workload"]["name"]
    guest_home = PurePosixPath(VM_GUEST_HOME_BASE) / _validated_guest_user(vm_cfg)
    pubkey = _read_ssh_pubkey(pw)
    if not pubkey:
        return  # build_cloud_init_iso raises on this; nothing to add here.

    state_dir = workload_state_dir(name)
    root_dir = workload_root_dir(name)
    for vol_spec in volumes:
        expanded = expand_volume_path(vol_spec, str(state_dir))
        host_str, guest_str, _opts = parse_volume_spec(expanded)
        if not host_str or not guest_str:
            continue
        guest_path = PurePosixPath(guest_str)
        # The share covers the home when it IS the home, or contains it (a share
        # mounted at /home). A share *below* the home hides nothing.
        try:
            sub = guest_home.relative_to(guest_path)
        except ValueError:
            continue

        home_host = Path(host_str) / sub if str(sub) != "." else Path(host_str)
        try:
            home_host.resolve().relative_to(root_dir.resolve())
        except ValueError:
            ensure_common.log(f"  WARNING: {guest_str} shares {host_str}, which is outside "
                f"{root_dir} — it hides the guest's authorized_keys and only you "
                f"can seed it. Copy {Path(pw.pw_dir) / '.ssh/id_ed25519.pub'} to "
                f"{home_host}/.ssh/authorized_keys (0600) or `workloadctl exec` "
                f"will not be able to log in.")
            continue

        if not _provision_dir_secure(root_dir, home_host, pw.pw_uid, pw.pw_gid,
                                     0o755):
            raise RuntimeError(f"could not provision guest home share {home_host}")
        ssh_dir = home_host / ".ssh"
        if not _provision_dir_secure(root_dir, ssh_dir, pw.pw_uid, pw.pw_gid,
                                     0o700):
            raise RuntimeError(f"could not provision {ssh_dir}")
        if _seed_authorized_keys(root_dir, ssh_dir, pubkey, pw.pw_uid, pw.pw_gid):
            ensure_common.log(f"  Seeded SSH key into {guest_str} share: "
                f"{ssh_dir}/authorized_keys")


def generate_vm_host_keypair(pw, name: str):
    """Generate the VM's SSH *host* keypair if absent (S1 host-key pinning).

    Symmetric to generate_ssh_keypair (the client key): the private half is
    injected into the guest as /etc/ssh/ssh_host_ed25519_key via cloud-init, and
    the public half is pinned into vm_known_hosts on the host, so the CLI can
    verify the guest with StrictHostKeyChecking=yes and no trust-on-first-use.
    Idempotent: generated once and reused across reseeds so the pin stays stable
    — do NOT churn it, that would invalidate the pin.
    """
    # Kept once there, so the pin stays stable.
    key_path = Path(pw.pw_dir) / ".ssh" / "vm_host_ed25519_key"
    if _generate_keypair(pw, key_path, f"workload-{name}-host@hypervisor",
                         "VM host key"):
        ensure_common.log(f"  Generated VM host keypair: {key_path}")


def _read_vm_host_private_key(pw) -> str:
    """Return the PEM of the VM host private key, or '' if not generated yet."""
    return _read_ssh_file(pw, "vm_host_ed25519_key")


def _read_vm_host_pubkey(pw) -> str:
    """Return the VM host public key line, or '' if not generated yet."""
    return _read_ssh_file(pw, "vm_host_ed25519_key.pub").strip()


def write_vm_known_hosts(pw, name: str, host_pubkey: str):
    """Pin the guest host key into ~/.ssh/vm_known_hosts, keyed by workload name.

    The CLI connects with HostKeyAlias=<name>, so a single line keyed by the
    bare name (not the churning DHCP address) is the pin the CLI verifies
    against. Rewritten idempotently whenever the host pubkey changes.
    """
    known_hosts = Path(pw.pw_dir) / ".ssh" / "vm_known_hosts"
    line = f"{name} {host_pubkey}\n"
    if _read_ssh_file(pw, "vm_known_hosts") == line:
        return
    # Atomic: the CLI reads this file with StrictHostKeyChecking=yes and takes no
    # lock, so a `vm ssh` running concurrently with a restart could otherwise
    # read the pin mid-rewrite and fail against a truncated line. Renamed over
    # the name, so a link there is replaced, not written through.
    if not _write_file_nofollow(_anchor(pw), known_hosts, line.encode(),
                                pw.pw_uid, pw.pw_gid, 0o644):
        raise RuntimeError(f"cannot write {known_hosts} safely")
    ensure_common.log(f"  Pinned VM host key in {known_hosts}")
