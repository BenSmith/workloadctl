"""
[security] kernel_modules: the modules the host loads before a container
workload starts.

No workload domain may make the kernel load a module (workload-vm.cil's
deny), so a container whose software needs one the host has not loaded
(wg-quick's `ip link add ... type wireguard`) fails. The workload names the
modules instead, and its setup unit, which runs in a host domain, loads
them before any of its containers start. A module the image refuses fails
here, by name, rather than inside the container.
"""
import re
import subprocess

# modprobe's own names: letters, digits, _ and - (which it treats alike),
# starting with neither.
MODULE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def kernel_modules(config: dict) -> list[str]:
    """The modules `config` names, in order."""
    return list(config.get("security", {}).get("kernel_modules") or [])


def validate_kernel_modules(config: dict, kind: str) -> list[str]:
    """Errors for [security] kernel_modules: a list of module names, on a
    container workload, and only in the top-level [security]."""
    errors = []
    for i, c in enumerate(config.get("containers") or []):
        if isinstance(c, dict) and "kernel_modules" in c.get("security", {}):
            errors.append(
                f"containers[{c.get('name', i)}].security.kernel_modules: "
                f"set kernel_modules in the top-level [security]; the host "
                f"loads them for the whole workload")
    names = config.get("security", {}).get("kernel_modules")
    if names is None:
        return errors
    if kind == "vm":
        return errors + ["[security].kernel_modules: a VM's guest loads its "
                         "own kernel's modules"]
    if not isinstance(names, list) or not all(
            isinstance(n, str) and MODULE_NAME.match(n) for n in names):
        errors.append("[security].kernel_modules must be a list of module "
                      "names (letters, digits, _ and -, starting with a "
                      "letter or digit)")
    return errors


def load_kernel_modules(config: dict, run=None) -> None:
    """modprobe each module `config` names; raise naming the first that
    fails, with what modprobe said."""
    run = run or subprocess.run
    for name in kernel_modules(config):
        result = run(["modprobe", "--", name], capture_output=True,
                     text=True)
        if result.returncode != 0:
            said = (result.stderr or result.stdout).strip()
            raise RuntimeError(
                f"modprobe {name} failed: "
                f"{said or f'exit {result.returncode}'}")
