"""The per-workload egress CA: how it is minted, and that it is minted once.

The assertions here parse the CERTIFICATE rather than matching the argv that
produced it. That is the whole point of the file. Three extensions are load-
bearing and invisible to most clients -- a CA missing them works under curl, Go
and Node and fails only under Python's ssl, presenting as a trust failure
indistinguishable from "the guest never installed our CA" -- so a test that
asserted `-addext subjectKeyIdentifier=hash` appeared in a list would pass
against an openssl that ignored it.
"""

import os
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from moatery.egress_ca import (CA_BACKDATE_SECONDS, CA_CERT_NAME, CA_KEY_NAME,
                       CA_VALIDITY_DAYS, ca_cert_path, ca_dir,
                       ca_key_path, ca_openssl_argv, ca_subject,
                       leaf_dir)


# `lib/` reaches sys.path via tests/__init__, so this import follows it.
import ensure_common
from tests import MOATERY_CHECKOUT, MOATERY_LIBEXEC
import vm_default_seed

HAVE_OPENSSL = shutil.which("openssl") is not None


def _mint(tmp, name="myvm", now=None):
    key = Path(tmp) / CA_KEY_NAME
    cert = Path(tmp) / CA_CERT_NAME
    argv = ca_openssl_argv(name, key, cert, now=now or time.time())
    p = subprocess.run(argv, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return key, cert


def _text(cert, *args):
    return subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", *args],
                          capture_output=True, text=True).stdout


class TestCaPaths(unittest.TestCase):
    def test_the_ca_lives_in_the_egress_tree(self):
        # Outside the workload root: `backup` captures only data/, which keeps
        # the private key out of every archive with no exclusion rule, and the
        # policy module types this tree, where a VM's root is one type.
        from workload_lib import workload_egress_dir
        egress = workload_egress_dir("myvm")
        d = ca_dir(egress)
        self.assertEqual(d, Path("/var/lib/workloadctl/egress/myvm/ca"))
        self.assertEqual(ca_key_path(egress), d / CA_KEY_NAME)
        self.assertEqual(ca_cert_path(egress), d / CA_CERT_NAME)

    def test_the_subject_names_the_workload(self):
        # An operator reading a certificate error inside a guest has to be able
        # to tell which of several workloads' CAs it came from.
        self.assertIn("myvm", ca_subject("myvm"))


class TestBackdate(unittest.TestCase):
    def test_not_before_is_backdated_an_hour(self):
        argv = ca_openssl_argv("myvm", "/k", "/c", now=1787000000.0)
        stamp = argv[argv.index("-not_before") + 1]
        self.assertEqual(
            stamp,
            time.strftime("%Y%m%d%H%M%SZ",
                          time.gmtime(1787000000.0 - CA_BACKDATE_SECONDS)))

    def test_not_before_is_explicit_rather_than_defaulted(self):
        # Letting notBefore default to "now" would make the hour of skew
        # tolerance a property of WHEN THE PROCESS RAN rather than of the
        # certificate, which is not a thing anything downstream can read.
        self.assertIn("-not_before", ca_openssl_argv("m", "/k", "/c", now=0.0))


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class TestTheMintedCertificate(unittest.TestCase):
    """Everything here parses what OpenSSL actually emitted."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.now = time.time()
        cls.key, cls.cert = _mint(cls.tmp, now=cls.now)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_it_is_a_ca(self):
        self.assertIn("CA:TRUE", _text(self.cert, "-ext", "basicConstraints"))

    def test_basic_constraints_is_critical(self):
        self.assertIn("critical", _text(self.cert, "-ext", "basicConstraints"))

    def test_it_carries_a_subject_key_identifier(self):
        # Without this, Python 3.14 / OpenSSL 3.5 rejects the chain with
        # `Missing Authority Key Identifier` -- naming the LEAF's extension for
        # a defect in the CA, which is why it is worth its own test.
        #
        # Measured 2026-08-26: OpenSSL 3.5 adds SKI to a self-signed CA on its
        # own, so `-addext subjectKeyIdentifier=hash` is belt-and-braces and
        # REMOVING IT DOES NOT FAIL THIS TEST. Said plainly because a reader
        # who breaks it on purpose finds that out and concludes the test is
        # worthless. It is not: it pins a property we depend on against an
        # OpenSSL whose default differs, which is the case this must survive.
        out = _text(self.cert, "-ext", "subjectKeyIdentifier")
        self.assertIn("Subject Key Identifier", out)

    def test_it_carries_key_usage_for_signing_certificates(self):
        # The second failure Python raises once SKI is present:
        # `CA cert does not include key usage extension`. Unlike SKI above,
        # OpenSSL does NOT add this by itself -- it is what the -addext
        # actually buys, and dropping that line fails here.
        out = _text(self.cert, "-ext", "keyUsage")
        self.assertIn("Certificate Sign", out)
        self.assertIn("CRL Sign", out)
        self.assertIn("critical", out)

    def test_the_key_is_ecdsa_p256(self):
        # Matching the leaves. RSA-2048 minting is slow enough to be noticeable
        # on a cold cache, and a CA of a different family than its leaves buys
        # nothing.
        out = subprocess.run(["openssl", "pkey", "-in", str(self.key),
                              "-noout", "-text"],
                             capture_output=True, text=True).stdout
        self.assertIn("prime256v1", out)

    def test_the_private_key_is_not_encrypted(self):
        # -noenc, because nothing is present to type a passphrase at boot.
        self.assertNotIn("ENCRYPTED", self.key.read_text())

    def test_it_lasts_about_ten_years(self):
        # The exact date depends on when the test ran; what is asserted is that
        # the validity is the decade the never-rotate argument requires and not,
        # say, the 365 days a copied recipe would give it.
        out = _text(self.cert, "-enddate").strip()
        end = time.mktime(time.strptime(out.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z"))
        days = (end - self.now) / 86400
        self.assertGreater(days, CA_VALIDITY_DAYS - 2)

    def test_python_ssl_will_at_least_load_it_as_an_anchor(self):
        # Deliberately NOT called "a Python client accepts it". Loading an
        # anchor parses the certificate; it does not verify a chain, so none of
        # the extension failures above can surface here -- those are raised
        # during verification, against a LEAF, and there are no leaves until
        # T4. This is the cheap half; the real proof is a handshake, owed by
        # the rung that mints something to hand a client.
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(self.cert))
        self.assertEqual(len(ctx.get_ca_certs()), 1)


class TestGeneratorIsIdempotent(unittest.TestCase):
    """Re-minting invalidates a provisioned guest's anchor, and cloud-init runs
    once per instance-id -- so the replacement never arrives and every HTTPS
    request fails validation on a VM `diagnose` calls healthy. The guard is the
    whole feature."""

    def setUp(self):
        # ensure_common, not the entrypoint: both generators are keyed on the
        # workload name and read nothing under [vm], so they are shared with
        # the container egress path and live there. The entrypoint imports
        # them by name, so a patch installed on it would not be the copy these
        # functions resolve.
        self.mod = ensure_common
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.anchor = Path(self.tmp) / "egress"
        self.anchor.mkdir()
        self.pw = types.SimpleNamespace(
            pw_dir=self.tmp, pw_uid=os.getuid(), pw_gid=os.getgid(),
            pw_name="_wl-myvm")
        self._patch()

    def _patch(self):
        mod = self.mod
        self._orig_anchor = mod.egress_anchor
        self._orig_chown = mod.os.chown
        mod.egress_anchor = lambda name: self.anchor
        mod.os.chown = lambda *a, **k: None
        self.addCleanup(setattr, mod, "egress_anchor", self._orig_anchor)
        self.addCleanup(setattr, mod.os, "chown", self._orig_chown)
        # The mint is moatery's program: the checkout's, when one is named,
        # which then has to find the checkout's package too.
        patches = [mock.patch.object(mod, "CA_MINT_BIN",
                                     str(MOATERY_LIBEXEC / "moat-mint-ca"))]
        if MOATERY_CHECKOUT:
            patches.append(mock.patch.dict(
                os.environ, {"PYTHONPATH": MOATERY_CHECKOUT}))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_it_mints_once_and_leaves_it_alone(self):
        self.mod.generate_egress_ca(self.pw, "myvm")
        cert = ca_cert_path(self.anchor)
        key = ca_key_path(self.anchor)
        self.assertTrue(cert.exists() and key.exists())
        first = (cert.read_bytes(), key.read_bytes())

        self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertEqual((cert.read_bytes(), key.read_bytes()), first,
                         "the CA was re-minted; a provisioned guest's anchor "
                         "is now stale and cloud-init will never replace it")

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_the_private_half_is_not_world_readable(self):
        self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertEqual(ca_key_path(self.anchor).stat().st_mode & 0o777, 0o600)
        # The certificate is a public anchor -- the seed builder and `diagnose`
        # both read it -- so it is deliberately NOT 0600.
        self.assertEqual(ca_cert_path(self.anchor).stat().st_mode & 0o777, 0o644)
        self.assertEqual(ca_dir(self.anchor).stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_the_certificate_is_readable_under_a_tight_umask(self):
        """openssl writes under the caller's umask, and the seed builder and
        `diagnose` read the certificate as another user."""
        old = os.umask(0o077)
        try:
            self.mod.generate_egress_ca(self.pw, "myvm")
        finally:
            os.umask(old)
        self.assertEqual(ca_cert_path(self.anchor).stat().st_mode & 0o777,
                         0o644)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_a_kept_ca_keeps_its_leaf_caches(self):
        """The caches go only with a NEW CA. Cleared on every start, the
        inspector re-mints every leaf after each restart and the denial
        cache forgets what it refused."""
        self.mod.generate_egress_ca(self.pw, "myvm")
        leaf = leaf_dir(self.anchor) / "kept.pem"
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_text("x")
        self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertTrue(leaf.exists(), "a start that kept the CA cleared "
                        "its leaf cache")

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_half_a_ca_is_refused_not_minted_over(self):
        """The certificate left behind may be the guest's anchor, so a lost
        key is the operator's to resolve; minting over it would strand a
        provisioned guest without a word."""
        self.mod.generate_egress_ca(self.pw, "myvm")
        cert = ca_cert_path(self.anchor)
        before = cert.read_bytes()
        ca_key_path(self.anchor).unlink()
        with self.assertRaises(RuntimeError) as ctx:
            self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertIn(str(cert), str(ctx.exception))
        self.assertEqual(cert.read_bytes(), before)
        self.assertFalse(ca_key_path(self.anchor).exists())

    def test_a_linked_ca_dir_is_refused_not_minted_into(self):
        # F34: the CA is minted in a root-only directory and copied in by the
        # no-follow walk, which refuses a link at ca/.
        outside = Path(self.tmp) / "outside"
        outside.mkdir()
        (self.anchor / "ca").symlink_to(outside)
        chowned = []
        with mock.patch.object(self.mod.os, "chown",
                               lambda path, *a, **k: chowned.append(path)):
            with self.assertRaises(RuntimeError):
                self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse([p for p in chowned
                          if Path(p).resolve().is_relative_to(outside)])

    def test_a_dangling_link_at_the_key_is_half_a_ca_not_a_target(self):
        target = Path(self.tmp) / "new-key"
        (self.anchor / "ca").mkdir()
        ca_key_path(self.anchor).symlink_to(target)
        with self.assertRaises(RuntimeError):
            self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertFalse(target.exists())

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_the_mint_runs_outside_the_workload_users_tree(self):
        argv = []
        real_run = subprocess.run

        def spy(cmd, **kw):
            argv.append(cmd)
            return real_run(cmd, **kw)

        with mock.patch.object(self.mod.subprocess, "run", spy):
            self.mod.generate_egress_ca(self.pw, "myvm")
        mint_state = Path(argv[0][argv[0].index("--state-dir") + 1])
        self.assertEqual(mint_state.parent, self.anchor)
        self.assertNotEqual(mint_state, self.anchor)
        self.assertTrue(ca_key_path(self.anchor).is_file())

    def test_a_mint_that_cannot_run_raises_naming_it(self):
        with mock.patch.object(self.mod.subprocess, "run",
                               side_effect=FileNotFoundError("no such file")):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertIn("moat-mint-ca", str(ctx.exception))

    def test_openssl_failing_raises_rather_than_returning_quietly(self):
        # A silent failure here yields a filtered VM with no CA, which does not
        # surface until the guest's first HTTPS request.
        # mock.patch.object, NOT `self.mod.subprocess.run = ...`: `mod.subprocess`
        # is the shared stdlib module, so a bare assignment replaces run() for
        # the whole process and leaks into every later test. It did, and it
        # presented as the REAL mint failing with this fake's error string.
        fake = types.SimpleNamespace(
            returncode=1, stdout="", stderr="openssl: unrecognised option")
        with mock.patch.object(self.mod.subprocess, "run", return_value=fake):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertIn("unrecognised option", str(ctx.exception))

    def test_a_failure_with_no_output_still_says_something(self):
        # Same both-streams reasoning as _ssh_keygen: reporting stderr alone
        # yields an empty diagnostic on precisely the runs that need one.
        fake = types.SimpleNamespace(returncode=3, stdout="", stderr="")
        with mock.patch.object(self.mod.subprocess, "run", return_value=fake):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.generate_egress_ca(self.pw, "myvm")
        self.assertIn("exit 3", str(ctx.exception))

    # ------------------------------------------------------------------
    # The PKI directories. Their labels are stamp_selinux_labels' (test_ensure_user).

    def test_the_leaf_caches_are_created_beside_the_ca(self):
        # The minter's own mkdir cannot do this: a directory the INSPECTOR
        # creates inherits its parent's type, and the domain has no
        # relabelto -- it would create a directory it then cannot use.
        self.mod.provision_egress_pki_dirs(self.pw, "myvm")
        for name in ("ca", "leaves", "leaves-denied"):
            d = self.anchor / name
            self.assertTrue(d.is_dir(), name)
            self.assertEqual(d.stat().st_mode & 0o777, 0o700, name)

    def test_a_linked_leaf_cache_is_refused_not_chowned(self):
        outside = Path(self.tmp) / "outside"
        outside.mkdir()
        (self.anchor / "leaves").symlink_to(outside)
        with mock.patch.object(self.mod.os, "fchown") as fchown:
            with self.assertRaises(RuntimeError):
                self.mod.provision_egress_pki_dirs(self.pw, "myvm")
        self.assertTrue((self.anchor / "leaves").is_symlink())
        self.assertEqual(fchown.call_count, 1)  # ca/ alone, before leaves/

    def test_it_is_idempotent(self):
        self.mod.provision_egress_pki_dirs(self.pw, "myvm")
        (self.anchor / "leaves" / "keep.pem").write_text("x")
        self.mod.provision_egress_pki_dirs(self.pw, "myvm")
        self.assertTrue((self.anchor / "leaves" / "keep.pem").exists())


class TestTheEgressAnchor(unittest.TestCase):
    """The workload's directory in the egress tree is root's: the CA is
    minted in it and the no-follow walks start from it."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        for patch in (
                mock.patch.object(ensure_common, "EGRESS_PKI_BASE", self.base),
                mock.patch.object(ensure_common, "workload_egress_dir",
                                  lambda name: self.base / name)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_one_not_roots_is_refused(self):
        if os.getuid() == 0:
            self.skipTest("root owns what it makes")
        with self.assertRaises(RuntimeError):
            ensure_common.egress_anchor("web")

    def test_a_link_at_the_name_is_refused(self):
        (self.base / "web").symlink_to(self.base)
        with mock.patch.object(ensure_common.os, "lstat",
                               wraps=os.lstat) as lstat:
            with self.assertRaises(RuntimeError):
                ensure_common.egress_anchor("web")
        lstat.assert_called_with(self.base / "web")

    def test_roots_directory_is_made_0711(self):
        real = os.lstat

        def as_root(path, *a, **k):
            st = real(path, *a, **k)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev,
                                   st.st_nlink, 0, 0, st.st_size,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(ensure_common.os, "lstat", as_root):
            anchor = ensure_common.egress_anchor("web")
        self.assertEqual(anchor, self.base / "web")
        self.assertEqual(anchor.stat().st_mode & 0o777, 0o711)


class TestTheBundleTheVariablesName(unittest.TestCase):
    """The five variables replace each runtime's store, so what they name
    holds the system's roots and the CA (audit F33: a splicing guest that
    trusted the CA alone verified no origin's certificate)."""

    CA = b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"

    def test_the_first_bundle_with_roots_then_the_ca(self):
        import guest_ca
        with tempfile.TemporaryDirectory() as tmp:
            empty, roots = Path(tmp) / "empty", Path(tmp) / "roots"
            empty.write_bytes(b"\n")
            roots.write_bytes(b"ROOTS")
            got = guest_ca.host_trust_bundle(
                self.CA, (str(Path(tmp) / "absent"), str(empty), str(roots)))
        self.assertEqual(got, b"ROOTS\n" + self.CA)

    def test_no_system_bundle_is_an_error_not_the_ca_alone(self):
        import guest_ca
        with self.assertRaises(FileNotFoundError):
            guest_ca.host_trust_bundle(self.CA, ("/nonexistent/a",))

    def test_the_bundle_and_the_ca_alone_are_two_paths(self):
        import guest_ca
        self.assertNotEqual(guest_ca.CA_BUNDLE_PATH, guest_ca.GUEST_CA_PATH)
        with mock.patch.object(vm_default_seed, "vm_uses_inspect",
                               return_value=True):
            env = vm_default_seed.vm_ca_env({})
        self.assertEqual(env, {v: guest_ca.CA_BUNDLE_PATH
                               for v in guest_ca.CA_ENV_VARS})

    def test_a_container_bundle_is_written_beside_the_ca(self):
        import guest_ca
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "wl" / "state"
            cert = ensure_common.ca_cert_path(state)
            cert.parent.mkdir(parents=True)
            cert.write_bytes(self.CA)
            pw = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            with mock.patch.object(ensure_common, "egress_anchor",
                                   return_value=state), \
                    mock.patch.object(ensure_common, "host_trust_bundle",
                                      side_effect=lambda ca: b"R\n" + ca):
                ensure_common.write_container_ca_bundle(pw, "wl")
            path = guest_ca.container_ca_bundle_path(state)
            self.assertEqual(path.read_bytes(), b"R\n" + self.CA)
            self.assertEqual(path.parent, cert.parent)

    def test_the_custom_seed_template_builds_it_as_the_built_in_does(self):
        import guest_ca
        from tests import REPO_ROOT
        for rel in ("workloads/vm-base/cloud-init/user-data",
                    "lib/scratch_vm.py"):
            text = (REPO_ROOT / rel).read_text()
            for line in guest_ca.GUEST_BUNDLE_LINES:
                self.assertIn(f"#     {line}", text, rel)
            for var in guest_ca.CA_ENV_VARS:
                self.assertIn(f"#       {var}={guest_ca.CA_BUNDLE_PATH}",
                              text, rel)

if __name__ == "__main__":
    unittest.main()


class TestTheCaReachesTheSeed(unittest.TestCase):
    """The built-in cloud-config carries the CA by BOTH routes.

    Either alone leaves a measured population of clients failing: the system
    trust store covers almost everything, and the runtimes that carry their own
    root list (upstream Node, certifi) consult only the file the five
    environment variables name. So `ca_certs.trusted` and the write_files entry
    are not redundant, and a test asserting one would pass against a seed that
    breaks half the guest.
    """

    PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

    def setUp(self):
        self.mod = vm_default_seed

    def _render(self, **kw):
        return self.mod.render_default_user_data(
            name="myvm", guest_user="fedora", pubkey="ssh-ed25519 AAAA u@h",
            mounts=[], has_data_disk=False, **kw)

    def test_the_ca_alone_is_written_where_the_store_takes_it(self):
        from guest_ca import GUEST_CA_PATH
        out = self._render(ca_cert=self.PEM)
        self.assertIn(f"  - path: {GUEST_CA_PATH}", out)
        self.assertIn("-----BEGIN CERTIFICATE-----", out)

    def test_the_guest_builds_the_bundle_at_first_boot_and_every_boot(self):
        from guest_ca import CA_BUNDLE_PATH, GUEST_BUNDLE_LINES
        out = self._render(ca_cert=self.PEM)
        block = "\n".join(f"    {line}" for line in GUEST_BUNDLE_LINES)
        runcmd = out.index("runcmd:")
        bootcmd = out.index("bootcmd:")
        self.assertIn(block, out[runcmd:])
        self.assertIn(block, out[bootcmd:runcmd])
        self.assertIn(f"mv {CA_BUNDLE_PATH}.tmp {CA_BUNDLE_PATH}", block)

    def test_no_ca_builds_no_bundle(self):
        out = self._render(ca_cert="")
        self.assertNotIn("bootcmd:", out)
        self.assertNotIn("egress-ca-bundle", out)

    def test_it_also_goes_into_the_system_trust_store(self):
        out = self._render(ca_cert=self.PEM)
        self.assertIn("ca_certs:", out)
        self.assertIn("  trusted:", out)

    def test_write_files_is_emitted_once_when_both_halves_want_it(self):
        # The env block and the CA bundle are two entries under ONE write_files
        # key. Two `write_files:` keys is not a cloud-config -- the second
        # silently replaces the first, and the loser is whichever half the
        # renderer emitted earlier.
        out = self._render(ca_cert=self.PEM, guest_env={"SSL_CERT_FILE": "/x"})
        self.assertEqual(out.count("write_files:"), 1)

    def test_a_workload_with_no_ca_gets_neither_block(self):
        # egress = "open": no inspector, so nothing to trust.
        out = self._render(ca_cert="")
        self.assertNotIn("ca_certs:", out)

    def test_the_env_block_still_stands_on_its_own(self):
        # Guarding the write_files header on `guest_env or ca_cert` is easy to
        # get wrong in the direction that drops the env block for a workload
        # with no CA.
        out = self._render(guest_env={"WORKLOAD_BROKER_URL": "http://x"})
        self.assertIn("write_files:", out)
        self.assertIn("/etc/environment", out)
