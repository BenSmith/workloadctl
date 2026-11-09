#!/usr/bin/env python3
"""What diagnose reads from an image's stored layers to judge a gid shift.

diagnose runs as root over directories the workload controls, so nothing
here follows a link: a layer directory must resolve inside the workload's
state directory, the walk never descends a symlink, and the two files read
by name (/etc/group, /etc/shadow) are opened relative to the layer with
O_NOFOLLOW at every step. The verdict over the result is
diagnose_subid.image_shift_check.

Installed to /usr/libexec/workloadctl/diagnose_image_shift.py.
"""

import json
import os
import stat
from collections import Counter

READ_LIMIT = 1 << 20
LAYERS_JSON_LIMIT = 64 << 20


def _to_ns(gid_map, host):
    for ns, start, size in gid_map:
        if start <= host < start + size:
            return ns + host - start
    return None


def _translate(gid_map, recorded, host):
    """A host gid in the workload's namespace ids, then through the layer's
    recorded map if it has one; None when either misses."""
    ns = _to_ns(gid_map, host)
    if ns is not None and recorded:
        ns = _to_ns([(e["container_id"], e["host_id"], e["size"])
                     for e in recorded], ns)
    return ns


def _inside(path, root):
    real, base = os.path.realpath(path), os.path.realpath(root)
    return real == base or real.startswith(base.rstrip("/") + "/")


def _layer_dirs(info):
    data = (info.get("GraphDriver") or {}).get("Data") or {}
    dirs = [data.get("UpperDir")]
    dirs += (data.get("LowerDir") or "").split(":")
    return [d for d in dirs if d]


def _recorded_maps(graphroot, state_dir):
    """{layer id: [{container_id, host_id, size}, …]} from layers.json."""
    path = os.path.join(graphroot, "overlay-layers", "layers.json")
    if not _inside(path, state_dir):
        return {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return {}
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return {}
        raw = f.read(LAYERS_JSON_LIMIT)
    try:
        layers = json.loads(raw)
        return {layer["id"]: layer.get("gidmap") or []
                for layer in layers}
    except (ValueError, KeyError, TypeError):
        return {}


def _read_etc(layer_dir, name, want_gid_from=None):
    """(content or None, gid or None) for `<layer>/etc/<name>`. A link at
    `etc` or at the file, or anything but a regular file, reads as
    absent."""
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        top = os.open(layer_dir, flags | os.O_DIRECTORY)
    except OSError:
        return None, None
    try:
        try:
            etc = os.open("etc", flags | os.O_DIRECTORY, dir_fd=top)
        except OSError:
            return None, None
        try:
            try:
                fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=etc)
            except OSError:
                return None, None
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    return None, None
                content = f.read(READ_LIMIT)
                gid = None
                if want_gid_from is not None:
                    try:
                        gid = want_gid_from(
                            etc, os.path.join(layer_dir, "etc", name))
                    except OSError:
                        gid = None
                return content, gid
        finally:
            os.close(etc)
    finally:
        os.close(top)


def _fd_gid(dir_fd, path):
    return os.stat(os.path.basename(path), dir_fd=dir_fd,
                   follow_symlinks=False).st_gid


def _parse_groups(content):
    groups = {}
    for line in content.decode(errors="replace").splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2].isdigit():
            groups[int(fields[2])] = fields[0]
    return groups


def _walk_layer(layer_dir, gid_map, recorded, gid_of):
    """(Counter of translated gids, files outside the map) for one layer."""
    hist, outside = Counter(), 0
    for root, dirnames, filenames in os.walk(layer_dir, followlinks=False):
        for name in dirnames + filenames:
            try:
                host = gid_of(os.path.join(root, name))
            except OSError:
                continue
            ns = _translate(gid_map, recorded, host)
            if ns is None:
                outside += 1
            else:
                hist[ns] += 1
    return hist, outside


def image_shift_facts(info, state_dir, gid_map, cache=None, gid_of=None,
                      shadow_gid_of=None):
    """What image_shift_check needs for one image, or None when the image
    is not judged: (counts, groups, shadow_gid, outside).

    `info` is the image's inspect dict; `gid_map` the user's rows as
    (namespace, host, size); `cache` is shared across the workload's images,
    so a base layer is walked once. A layer directory outside `state_dir`
    skips the image.
    """
    gid_of = gid_of or (lambda p: os.lstat(p).st_gid)
    shadow_gid_of = shadow_gid_of or _fd_gid
    cache = {} if cache is None else cache
    dirs = _layer_dirs(info)
    if not dirs:
        return None
    for d in dirs:
        if not _inside(d, state_dir) or os.path.islink(d):
            return None
    counts, outside = Counter(), 0
    groups, shadow_gid = None, None
    maps = {}
    for d in dirs:
        graphroot = os.path.dirname(os.path.dirname(os.path.dirname(d)))
        if graphroot not in maps:
            maps[graphroot] = _recorded_maps(graphroot, state_dir)
        layer_id = os.path.basename(os.path.dirname(d))
        key = (d, layer_id)
        if key not in cache:
            cache[key] = _walk_layer(
                d, gid_map, maps[graphroot].get(layer_id), gid_of)
        hist, out = cache[key]
        counts.update(hist)
        outside += out
        recorded = maps[graphroot].get(layer_id)
        if groups is None:
            content, _ = _read_etc(d, "group")
            if content is not None:
                groups = _parse_groups(content)
        if shadow_gid is None:
            content, host = _read_etc(d, "shadow", shadow_gid_of)
            if content is not None and host is not None:
                shadow_gid = _translate(gid_map, recorded, host)
    counts = {g: c for g, c in counts.items() if g >= 1}
    return counts, groups or {}, shadow_gid, outside
