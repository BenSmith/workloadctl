#!/usr/bin/env python3
"""The image takes ssh passwords from the LAN only, and fail2ban's sshd
jail is on.

Audit L19 (2026-10-17): both production hosts took passwords from every
address, the admin account has a password and NOPASSWD sudo, and fail2ban
ran with no jail, so a guessed password from anywhere was root, as fast as
sshd would answer. The user chose passwords from the LAN, keys from
anywhere. On the proving host, sshd -T over Fedora's drop-ins and
workloadctl's gave passwords to 192.168.0.50 and fe80::1 and not to
10.0.0.5; the jail, live, banned the proving client after its fifth
invalid user, through firewalld. The addresses are a build argument
(SSHD_PASSWORD_ADDRESSES), the user's LAN by default.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import configparser
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import REPO_ROOT

GIT_ROOT = REPO_ROOT.parent
CONTAINERFILE = GIT_ROOT / "hypervisor.Containerfile"
DROPIN = GIT_ROOT / "security" / "sshd-lan-passwords.conf"
FILL = GIT_ROOT / "security" / "sshd-password-addresses"
PLACEHOLDER = "@SSHD_PASSWORD_ADDRESSES@"
JAIL = GIT_ROOT / "security" / "fail2ban-sshd.local"


def installed_as(source):
    """Where the Containerfile copies `security/<source>` to."""
    m = re.search(r"^COPY security/%s (\S+)$" % re.escape(source),
                  CONTAINERFILE.read_text(), re.MULTILINE)
    return m and m.group(1)


def settings(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class TestSshdPasswordsFromTheLan(unittest.TestCase):

    def fill(self, addresses):
        """The drop-in after the build step, and the step's result."""
        with tempfile.TemporaryDirectory() as tmp:
            dropin = Path(tmp) / DROPIN.name
            shutil.copy(DROPIN, dropin)
            run = subprocess.run([str(FILL), addresses, str(dropin)],
                                 capture_output=True, text=True)
            return dropin.read_text(), run

    def test_passwords_are_off_except_from_the_listed_addresses(self):
        text, run = self.fill("192.168.0.0/24,fe80::/10")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(settings(text), [
            "PasswordAuthentication no",
            "Match Address 192.168.0.0/24,fe80::/10",
            # The Match holds to the end of the file: nothing after it is
            # global.
            "PasswordAuthentication yes"])

    def test_no_addresses_means_no_passwords(self):
        text, run = self.fill("")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(settings(text), ["PasswordAuthentication no"])

    def test_a_value_that_is_not_addresses_is_refused(self):
        for value in ("10.0.0.0/8\nPermitRootLogin yes", "10.0.0.0/8 *",
                      "host.example"):
            with self.subTest(value=value):
                text, run = self.fill(value)
                self.assertNotEqual(run.returncode, 0)
                self.assertNotIn("PermitRootLogin", text)

    def test_the_build_fills_the_installed_drop_in_from_the_argument(self):
        containerfile = CONTAINERFILE.read_text()
        default = re.search(r"^ARG SSHD_PASSWORD_ADDRESSES=(\S+)$",
                            containerfile, re.MULTILINE)
        self.assertIsNotNone(default)
        self.assertEqual(default.group(1), "192.168.0.0/24,fe80::/10")
        step = re.search(r"^COPY security/%s (\S+)$" % FILL.name,
                         containerfile, re.MULTILINE).group(1)
        self.assertRegex(containerfile, r"RUN %s \\\n\s+\"\$SSHD_PASSWORD_ADDRESSES\" %s\n"
                         % (re.escape(step), re.escape(installed_as(DROPIN.name))))
        self.assertIn(PLACEHOLDER, DROPIN.read_text())

    def test_the_image_puts_it_before_the_drop_ins_that_follow(self):
        target = installed_as(DROPIN.name)
        self.assertIsNotNone(target)
        directory, name = target.rsplit("/", 1)
        self.assertEqual(directory, "/etc/ssh/sshd_config.d")
        # sshd keeps the first value it reads.
        self.assertLess(name, "40-workloadctl.conf")
        self.assertLess(name, "50-redhat.conf")


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class TestTheSshdJail(unittest.TestCase):

    def test_the_jail_is_on_and_reads_the_journal(self):
        jail = configparser.ConfigParser()
        jail.read(JAIL)
        self.assertEqual(dict(jail["sshd"]), {
            "enabled": "true", "backend": "systemd", "maxretry": "5",
            "findtime": "10m", "bantime": "1h"})

    def test_the_image_installs_it(self):
        target = installed_as(JAIL.name)
        self.assertIsNotNone(target)
        self.assertTrue(target.startswith("/etc/fail2ban/jail.d/"))
        self.assertTrue(target.endswith(".local"))


if __name__ == "__main__":
    unittest.main()
