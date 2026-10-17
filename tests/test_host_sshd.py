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
invalid user, through firewalld.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import configparser
import re
import unittest

from tests import REPO_ROOT

GIT_ROOT = REPO_ROOT.parent
CONTAINERFILE = GIT_ROOT / "hypervisor.Containerfile"
DROPIN = GIT_ROOT / "security" / "sshd-lan-passwords.conf"
JAIL = GIT_ROOT / "security" / "fail2ban-sshd.local"


def installed_as(source):
    """Where the Containerfile copies `security/<source>` to."""
    m = re.search(r"^COPY security/%s (\S+)$" % re.escape(source),
                  CONTAINERFILE.read_text(), re.MULTILINE)
    return m and m.group(1)


@unittest.skipUnless(CONTAINERFILE.exists(), "image half absent")
class TestSshdPasswordsFromTheLan(unittest.TestCase):

    def test_passwords_are_off_except_from_the_lan(self):
        lines = [line for line in DROPIN.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(lines[0], "PasswordAuthentication no")
        self.assertEqual(lines[1].split()[0], "Match")
        self.assertEqual(lines[1].split()[1], "Address")
        self.assertIn("192.168.0.0/24", lines[1].split()[2].split(","))
        # The Match holds to the end of the file: nothing after it is global.
        self.assertEqual([line.strip() for line in lines[2:]],
                         ["PasswordAuthentication yes"])

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
