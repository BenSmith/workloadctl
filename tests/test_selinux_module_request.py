"""No workload domain may make the kernel load a module.

A socket() for a family the kernel has not loaded runs modprobe for it, and
Fedora's domain_kernel_load_modules lets every domain ask. Each workload
domain's module takes `system module_request` away with a deny, which on the
proving host (2026-10-16) removed the boolean's rule for these domains and
left udev_t and unconfined_service_t theirs.
"""
import re
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parent.parent / "security"

# Each domain, and the module that must carry its deny: the one defining the
# type, or workload-vm for the base policy's.
DOMAINS = {
    "container_domain": "workload-vm",
    "svirt_t": "workload-vm",
    "passt_t": "workload-vm",
    "wlvfsd_t": "workload-vm",
    "wlinspect_t": "workload-inspect",
    "wlresolve_t": "workload-resolve",
    "wlclock_t": "workload-clock",
}


def _rules(module):
    text = (SECURITY / f"{module}.cil").read_text()
    text = re.sub(r";[^\n]*", "", text)
    return re.sub(r"\s+", " ", text)


class TestNoWorkloadDomainLoadsModules(unittest.TestCase):

    def test_every_workload_domain_is_denied_module_request(self):
        for domain, module in DOMAINS.items():
            with self.subTest(domain=domain):
                self.assertIn(
                    f"(deny {domain} kernel_t (system (module_request)))",
                    _rules(module))

    def test_no_module_names_another_modules_types(self):
        """A deny for a type another module defines would make this one fail
        to load wherever that one is missing."""
        for domain, module in DOMAINS.items():
            if module == "workload-vm" and not domain.startswith("wl"):
                continue
            with self.subTest(domain=domain):
                self.assertIn(f"(type {domain})", _rules(module))

    def test_no_shipped_module_grants_module_request(self):
        for cil in SECURITY.glob("*.cil"):
            with self.subTest(module=cil.name):
                self.assertNotRegex(
                    _rules(cil.stem), r"\(allow [^()]*\([^()]*\(module_request")


if __name__ == "__main__":
    unittest.main()
