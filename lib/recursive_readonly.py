"""
The `rro` volume option: a bind that is read-only all the way down.

podman's `ro` makes only the bind itself read-only; the mounts beneath it keep
their own flags, so `/:/host:ro` leaves `/host/proc`, `/host/sys`, the homes
and `/run/user` writable as far as the mount is concerned. crun applies `rro`
(mount_setattr, MOUNT_ATTR_RDONLY with AT_RECURSIVE), but podman refuses the
option. So the generator emits the bind as `ro` and names its destination in
an annotation, and a precreate OCI hook (workload-oci-rro, selected through
--hooks-dir) turns that bind's `ro` into `rro` in the config podman hands the
runtime.

The hook fails closed: podman refuses to create the container when it exits
non-zero, and it does when an annotated destination has no `ro` bind. What
fails open is the hook not running at all, which podman does not report: so
`workloadctl diagnose` reads the running container's mountinfo
(rro_writable_mounts).

The read-only flag reaches only the mounts that exist when the container
starts. A mount the host makes later arrives with its own flags under slave or
shared propagation, so `rro` requires private propagation, the default.
"""

RRO_ANNOTATION = "io.workloadctl.recursive-readonly"
RRO_HOOKS_DIR = "/usr/share/workloadctl/oci-hooks.d"

_PROPAGATING = ("slave", "rslave", "shared", "rshared")


def _split(volume):
    """(destination, options) of a `src:dst[:opts]` volume spec."""
    parts = volume.split(":", 2)
    if len(parts) < 2:
        return None, []
    return parts[1], parts[2].split(",") if len(parts) > 2 else []


def rro_volume_errors(volumes, where):
    """Validation errors for the `rro` volumes in a [storage].volumes list."""
    errors = []
    for volume in volumes:
        destination, opts = _split(volume)
        if "rro" not in opts:
            continue
        if destination is None:
            errors.append(f"{where}: {volume!r}: rro needs a destination")
        if "ro" in opts or "rw" in opts:
            errors.append(f"{where}: {volume!r}: rro is read-only already; "
                          f"drop 'ro'/'rw'")
        propagating = [o for o in opts if o in _PROPAGATING]
        if propagating:
            errors.append(
                f"{where}: {volume!r}: rro with {propagating[0]} propagation "
                f"lets a mount the host makes later arrive writable; use "
                f"rprivate (the default)")
        if destination and "," in destination:
            errors.append(f"{where}: {volume!r}: rro destination may not "
                          f"contain ','")
    return errors


def rro_volume_flag(parts):
    """The podman form of an expanded `src:dst:opts` volume split in three:
    `rro` becomes `ro`, which podman accepts, and the destination is returned
    for the annotation. (parts, None) when the volume has no `rro`."""
    if len(parts) < 3:
        return parts, None
    opts = parts[2].split(",")
    if "rro" not in opts:
        return parts, None
    opts = ["ro" if o == "rro" else o for o in opts]
    return [parts[0], parts[1], ",".join(opts)], parts[1]


def rro_annotation(destinations):
    """The annotation, `key=value`, that selects the hook and names the
    destinations it makes recursive."""
    return f"{RRO_ANNOTATION}={','.join(destinations)}"


class RroHookError(Exception):
    pass


def rro_rewrite(config):
    """The precreate hook's work on an OCI config: each annotated
    destination's bind gets `rro` for `ro`. Raises RroHookError when a
    destination has no such bind, so that podman refuses the container."""
    value = config.get("annotations", {}).get(RRO_ANNOTATION, "")
    destinations = [d for d in value.split(",") if d]
    if not destinations:
        raise RroHookError(f"annotation {RRO_ANNOTATION} names no destination")
    mounts = config.get("mounts", [])
    for destination in destinations:
        found = [m for m in mounts
                 if m.get("destination") == destination
                 and "ro" in m.get("options", [])]
        if len(found) != 1:
            raise RroHookError(
                f"{destination}: {len(found)} read-only mounts there, "
                f"expected one")
        found[0]["options"] = [
            "rro" if o == "ro" else o for o in found[0]["options"]]
    return config


def rro_writable_mounts(mountinfo, destination):
    """The mount points at or under `destination` that mountinfo (the text of
    /proc/PID/mountinfo) shows read-write."""
    writable = []
    prefix = destination.rstrip("/") + "/"
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        point, options = fields[4], fields[5].split(",")
        if (point == destination or point.startswith(prefix)) \
                and "rw" in options:
            writable.append(point)
    return writable
