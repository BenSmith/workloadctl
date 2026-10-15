#!/usr/bin/env python3
"""The image refuses the kernel modules a workload could have loaded.

security/module-autoload-block derives the refusals from the image's own
kernel tables at build time; these hold its classes, the keep list's
dependency closure and the Containerfile step that runs it. A Containerfile
that stopped running it would still build green, refusing nothing.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT, load_script

GIT_ROOT = REPO_ROOT.parent
SCRIPT = GIT_ROOT / "security" / "module-autoload-block"
KEEP = GIT_ROOT / "security" / "module-autoload-keep"
CONTAINERFILE = GIT_ROOT / "hypervisor.Containerfile"

DEP = """\
kernel/net/sctp/sctp.ko.xz: kernel/net/udp_tunnel.ko.xz
kernel/net/udp_tunnel.ko.xz:
kernel/drivers/net/wireguard/wireguard.ko.xz: kernel/net/udp_tunnel.ko.xz
kernel/drivers/net/vxlan/vxlan.ko.xz: kernel/net/udp_tunnel.ko.xz
kernel/drivers/vhost/vhost_vsock.ko.xz: kernel/net/vmw_vsock/vsock.ko.xz
kernel/net/vmw_vsock/vsock.ko.xz:
kernel/net/vmw_vsock/vsock_loopback.ko.xz: kernel/net/vmw_vsock/vsock.ko.xz
kernel/drivers/tty/n_hdlc.ko.xz:
kernel/crypto/twofish_generic.ko.xz:
kernel/drivers/scsi/scsi_transport_iscsi.ko.xz:
kernel/fs/nfs/nfs.ko.xz:
kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko.xz:
kernel/drivers/char/ipmi/ipmi-msghandler.ko.xz:
"""

ALIAS = """\
# Aliases extracted from modules themselves.
alias net-pf-10-proto-132 sctp
alias rtnl-link-wireguard wireguard
alias rtnl-link-vxlan vxlan
alias devname:vhost-vsock vhost_vsock
alias tty-ldisc-13 n_hdlc
alias crypto-twofish twofish_generic
alias twofish twofish_generic
alias net-pf-16-proto-8 scsi_transport_iscsi
alias fs-nfs nfs
alias pci:v00008086d000010D3sv*sd*bc*sc*i* e1000e
alias char-major-10-241 vhost_vsock
alias ipmi-msghandler ipmi-msghandler
"""


@unittest.skipUnless(SCRIPT.exists(), "image half absent")
class Derivation(unittest.TestCase):

    def setUp(self):
        self.m = load_script("../security/module-autoload-block",
                             "module_autoload_block")
        self.deps = self.m.read_deps(DEP)
        self.aliases = self.m.read_aliases(ALIAS)

    def blocked(self, keep):
        return self.m.blocked(self.deps, self.aliases, keep)

    def test_candidates_are_the_net_tree_and_the_reachable_aliases(self):
        self.assertEqual(
            self.m.candidates(self.deps, self.aliases),
            {"sctp", "udp_tunnel", "wireguard", "vxlan", "vsock",
             "vsock_loopback", "n_hdlc", "twofish_generic",
             "scsi_transport_iscsi"})

    def test_filesystems_devices_and_hardware_are_not_candidates(self):
        got = self.m.candidates(self.deps, self.aliases)
        for name in ("nfs", "e1000e", "vhost_vsock", "ipmi_msghandler"):
            self.assertNotIn(name, got)

    def test_a_kept_module_keeps_its_dependencies(self):
        got = self.blocked(["wireguard"])
        self.assertNotIn("wireguard", got)
        self.assertNotIn("udp_tunnel", got)
        self.assertIn("vxlan", got)
        self.assertIn("sctp", got)

    def test_a_kept_device_keeps_the_family_it_needs(self):
        got = self.blocked(["vhost_vsock"])
        self.assertNotIn("vsock", got)
        self.assertIn("vsock_loopback", got)

    def test_nothing_kept_refuses_every_candidate(self):
        self.assertEqual(set(self.blocked([])),
                         self.m.candidates(self.deps, self.aliases))

    def test_a_keep_name_the_kernel_lacks_fails(self):
        with self.assertRaises(SystemExit) as caught:
            self.blocked(["wireguard", "no_such_module"])
        self.assertIn("no_such_module", str(caught.exception))

    def test_keep_names_and_module_paths_normalise_dashes(self):
        self.assertIn("ipmi_msghandler", self.deps)
        self.assertEqual(self.m.read_keep("vsock-loopback  # why\n\n# x\n"),
                         ["vsock_loopback"])

    def test_each_refusal_is_an_install_of_false(self):
        text = self.m.render(["sctp", "vxlan"], "7.2.9")
        lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
        self.assertEqual(lines, ["install sctp /bin/false",
                                 "install vxlan /bin/false"])

    def test_main_writes_the_file_from_one_kernels_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            kernel = Path(tmp) / "modules" / "7.2.9"
            kernel.mkdir(parents=True)
            (kernel / "modules.dep").write_text(DEP)
            (kernel / "modules.alias").write_text(ALIAS)
            keep = Path(tmp) / "keep"
            keep.write_text("wireguard\nvhost_vsock\n")
            out = Path(tmp) / "out.conf"
            with contextlib.redirect_stderr(io.StringIO()):
                self.m.main(["--kernel", str(kernel), "--keep", str(keep),
                             "--out", str(out)])
            got = set(re.findall(r"^install (\S+) /bin/false$",
                                 out.read_text(), re.MULTILINE))
            self.assertEqual(got, {"sctp", "vxlan", "vsock_loopback",
                                   "n_hdlc", "twofish_generic",
                                   "scsi_transport_iscsi"})

    def test_tables_with_no_candidate_fail_rather_than_refuse_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            kernel = Path(tmp) / "7.2.9"
            kernel.mkdir()
            (kernel / "modules.dep").write_text("kernel/fs/nfs/nfs.ko.xz:\n")
            (kernel / "modules.alias").write_text("")
            keep = Path(tmp) / "keep"
            keep.write_text("")
            with self.assertRaises(SystemExit):
                self.m.main(["--kernel", str(kernel), "--keep", str(keep),
                             "--out", str(Path(tmp) / "out")])

    def test_the_shipped_keep_list_parses_without_repeats(self):
        names = self.m.read_keep(KEEP.read_text())
        self.assertTrue(names)
        self.assertEqual(len(names), len(set(names)))

    def test_the_shipped_keep_list_keeps_the_virtio_nic(self):
        self.assertIn("virtio_net", self.m.read_keep(KEEP.read_text()))


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class Wiring(unittest.TestCase):

    def setUp(self):
        self.text = CONTAINERFILE.read_text().replace("\\\n", " ")

    def test_the_image_copies_the_script_and_its_keep_list(self):
        self.assertRegex(
            self.text,
            r"COPY security/module-autoload-block "
            r"security/module-autoload-keep\s+/usr/libexec/hypervisor-build/")

    def test_the_image_runs_it_with_the_keep_list(self):
        self.assertRegex(
            self.text,
            r"RUN /usr/libexec/hypervisor-build/module-autoload-block\s+"
            r"--keep /usr/libexec/hypervisor-build/module-autoload-keep")

    def test_line_disciplines_stop_autoloading(self):
        self.assertRegex(
            self.text, r"dev\.tty\.ldisc_autoload = 0'\s+>\s*"
            r"/usr/lib/sysctl\.d/\S+\.conf")


if __name__ == "__main__":
    unittest.main()
