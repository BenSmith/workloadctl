"""What still handles the retired per-workload proxy on a host that ran it.

The proxy itself is gone. These are the pieces that clean up after it: the
refusal that names its seed concern, the run-file entry that unlinks its unit,
and the %post that removes its policy module.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestTheRetiredSeedConcern(unittest.TestCase):

    def test_seed_provides_no_longer_accepts_the_proxy_concern(self):
        from vm_defs import SEED_PROVIDES_CHOICES, SEED_PROVIDES_RETIRED
        self.assertNotIn("proxy", SEED_PROVIDES_CHOICES)
        self.assertIn("proxy", SEED_PROVIDES_RETIRED)
        # Named, not just refused: a custom seed that declared the old concern
        # DOES provide something, and the generic unknown-entry message would
        # send its author hunting a typo they did not make.
        self.assertIn(SEED_PROVIDES_RETIRED["proxy"], SEED_PROVIDES_CHOICES)


class TestTheRemovableViewStillNamesTheUnit(unittest.TestCase):
    """/run/systemd/system is tmpfs, so a reboot clears the previous version's
    unit -- but an in-place RPM upgrade does not, and the stale unit is still
    running a tinyproxy this version stopped packaging. Listing it with
    present=False is what lets `workloadctl remove` unlink it.
    """

    def test_the_removable_view_still_unlinks_a_stale_proxy_unit(self):
        source = (ROOT / "lib" / "run_files.py").read_text()
        self.assertIn('"unit", "proxy", False', source, (
            "the migration entry for the retired proxy unit is gone. A host "
            "upgraded in place keeps the previous version's "
            "workload-<name>-proxy.service with nothing that knows its name."))


class TestThePolicyModuleIsRemovedOnUpgrade(unittest.TestCase):
    """%post removes workload-proxy, unguarded on $1.

    %postun's module removals are guarded on an erase, which is right for the
    modules the package still ships. This one it no longer ships, so on an
    UPGRADE nothing else would ever take it out: the host keeps a loaded
    wlproxy_t whose filecon labels /usr/bin/tinyproxy for a domain no unit
    enters, indefinitely.
    """

    def setUp(self):
        self.spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        post = self.spec.index("\n%post")
        self.post = self.spec[post:self.spec.index("\n%postun")]

    def test_post_removes_the_module(self):
        self.assertIn("semodule -r workload-proxy", self.post)

    def test_post_relabels_the_binary_it_had_retyped(self):
        """Removing the module drops its filecon, but the installed binary
        keeps wlproxy_exec_t until something relabels it -- leaving a file
        labelled for a type that no longer exists on any host that still has
        tinyproxy."""
        self.assertIn("restorecon /usr/bin/tinyproxy", self.post)

    def test_the_removal_is_not_guarded_on_a_fresh_install(self):
        """The whole point is the upgrade. A `[ $1 -eq 1 ]` guard around it
        would remove the module on exactly the installs that never had it."""
        block = self.post[self.post.index("semodule -r workload-proxy") - 400:
                          self.post.index("semodule -r workload-proxy")]
        self.assertNotIn('"$1"', block)
        self.assertNotIn("[ $1 ", block)

    def test_postun_no_longer_removes_it_twice(self):
        postun = self.spec[self.spec.index("\n%postun"):]
        postun = postun[:postun.index("\n%files")]
        self.assertNotIn("workload-proxy", postun)


if __name__ == "__main__":
    unittest.main()
