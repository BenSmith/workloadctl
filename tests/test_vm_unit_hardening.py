#!/usr/bin/env python3
"""The VM unit confines what an escape into QEMU can write.

The 2026-10-11 security audit (F30): a VM's unit set User= and Slice= and
nothing else, so `systemd-analyze security` scored it 9.4 UNSAFE, worse than
a deliberately unhardened control, and its QEMU ran in the host's mount
namespace with the whole filesystem writable wherever its uid and label
allowed. A container workload's unit has had ProtectSystem=strict, a private
/tmp and a socket-family deny-list all along.

NoNewPrivileges is absent on purpose, and asserted absent: QEMU reaches
svirt_t by a type transition at exec, which no_new_privs refuses.

QEMU's own -sandbox (audit F21) was absent too while QEMU launched passt
itself (`-netdev passt`): passt inherits the filter and fails under it,
even `-sandbox on` alone (measured with QEMU 10.2.2 on the proving host).
passt now runs beside QEMU, so a passt VM's QEMU runs the full sandbox. A
bridged VM's does not: qemu-bridge-helper is a spawn, and the filter's
no_new_privs keeps it from its privilege.
"""

import unittest

import gen_vm
from workload_lib import workload_data_dir, workload_state_dir

PASST = {"workload": {"name": "web"}, "vm": {"network": {}}}
BRIDGED = {"workload": {"name": "web"}, "vm": {"network": {"bridge": "br0"}}}


def _service_lines(config):
    text = gen_vm.generate_vm_service(config, "_wl-web", 10000)
    return text, text.splitlines()


class TestTheVmUnitIsHardened(unittest.TestCase):

    def test_the_filesystem_is_read_only_but_the_workload_tree(self):
        for config in (PASST, BRIDGED):
            with self.subTest(network=config["vm"]["network"]):
                _, lines = _service_lines(config)
                self.assertIn("ProtectSystem=strict", lines)
                rw = [ln for ln in lines if ln.startswith("ReadWritePaths=")]
                self.assertEqual(len(rw), 1, rw)
                self.assertIn(f'"{workload_state_dir("web")}"', rw[0])
                # Optional (a VM without a data disk), so `-`, inside the
                # quotes where systemd reads it.
                self.assertIn(f'"-{workload_data_dir("web")}"', rw[0])

    def test_tmp_is_private_and_alg_and_packet_sockets_are_refused(self):
        _, lines = _service_lines(PASST)
        self.assertIn("PrivateTmp=yes", lines)
        self.assertIn("RestrictAddressFamilies=~AF_ALG AF_PACKET", lines)

    def test_no_new_privileges_is_not_set(self):
        """QEMU's transition to svirt_t happens at exec; no_new_privs would
        refuse it and the VM would not start."""
        text, _ = _service_lines(PASST)
        self.assertNotIn("NoNewPrivileges", text)

    def test_a_passt_vms_qemu_runs_its_own_sandbox(self):
        text, _ = _service_lines(PASST)
        self.assertIn("-sandbox on,obsolete=deny,elevateprivileges=deny,"
                      "spawn=deny,resourcecontrol=deny", text)

    def test_a_bridged_vms_qemu_does_not(self):
        """Its netdev spawns qemu-bridge-helper."""
        text, _ = _service_lines(BRIDGED)
        self.assertNotIn("-sandbox", text)
        self.assertIn("-netdev bridge", text)


if __name__ == "__main__":
    unittest.main()
