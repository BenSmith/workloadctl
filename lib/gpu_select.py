"""Which GPU a container gets, and whether the workload goes through CDI.

`gpu = "auto"` reads sysfs, so callers on the boot path resolve it here once
and pass the answer on; container_run_args does no I/O.

Installed to /usr/libexec/workloadctl/gpu_select.py.
"""
import os
from pathlib import Path

from gen_common import log_msg


def resolve_auto_gpu(name=None):
    """Detect the primary GPU from sysfs.

    Returns 'nvidia', 'nouveau', 'amd', 'intel', or 'none'. For NVIDIA cards
    the bound driver is checked: the proprietary driver uses the CDI path,
    but nouveau has no NVIDIA Container Toolkit support and must use the plain
    DRM render node instead — so it is reported separately.

    On a multi-GPU host the pick (first card in sysfs sort order) is
    arbitrary; if `name` is given, a warning is logged when more than one
    candidate GPU is present so the operator knows "auto" isn't deterministic
    across GPUs and can pin one via `devices.gpu = "nvidia:<uuid-or-index>"`.

    WORKLOAD_GPU_OVERRIDE pins the result regardless of host hardware. This
    makes the generated units deterministic for the snapshot tests (which must
    pass on any runner, GPU or not) and lets an operator force a result.
    """
    override = os.environ.get("WORKLOAD_GPU_OVERRIDE")
    if override:
        return override

    vendor_map = {"0x10de": "nvidia", "0x1002": "amd", "0x8086": "intel"}
    candidates = []
    try:
        for vendor_path in sorted(Path("/sys/class/drm").glob("card*/device/vendor")):
            vendor = vendor_path.read_text().strip().lower()
            if vendor in vendor_map:
                candidates.append((vendor_path, vendor_map[vendor]))
    except OSError:
        pass

    if not candidates:
        return "none"

    if len(candidates) > 1 and name is not None:
        cards = ", ".join(p.parent.parent.name for p, _ in candidates)
        log_msg(
            f"WARNING: {name} uses devices.gpu=\"auto\" with {len(candidates)} "
            f"GPUs present ({cards}); picking {candidates[0][0].parent.parent.name} "
            f"(sysfs sort order, arbitrary). Pin a specific GPU via "
            f"devices.gpu=\"nvidia:<uuid-or-index>\" to avoid ambiguity.",
            level="warning",
        )

    vendor_path, result = candidates[0]
    if result == "nvidia":
        try:
            if (vendor_path.parent / "driver").resolve().name == "nouveau":
                return "nouveau"
        except OSError:
            pass
    return result


def _gpu_sections(config):
    """The tables that may hold [devices]: the workload's own (single mode)
    and each [[containers]] entry."""
    containers = config.get("containers")
    if isinstance(containers, list):
        return [c for c in containers if isinstance(c, dict)]
    return [config]


def uses_cdi(config) -> bool:
    """True when any container's gpu resolves to the proprietary NVIDIA
    driver, which podman injects through CDI.

    podman's CDI library idmaps every injected mount when the container
    has a user namespace, and rootless podman cannot idmap a host
    filesystem, so such a container must run in the user's default
    namespace. That namespace and the subgid lines that shape it belong
    to the workload user, not one container, so the answer is
    workload-wide: one CDI container puts every container on it.
    """
    if "vm" in config:
        return False
    for section in _gpu_sections(config):
        devices = section.get("devices")
        gpu = devices.get("gpu", "none") if isinstance(devices, dict) else "none"
        if not isinstance(gpu, str):
            continue
        if gpu == "auto":
            gpu = resolve_auto_gpu()
        if gpu.partition(":")[0] == "nvidia":
            return True
    return False
