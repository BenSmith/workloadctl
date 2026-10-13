#!/usr/bin/env python3
"""diagnose says when a workload's image is older than it should be.

Nothing refreshes an image unattended (audit F26), so the check is the one
place an operator learns a pull or a rebuild is due.
"""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import diagnose_battery
import diagnose_egress
import diagnose_inspect
import workload_lib
from diagnose_image_age import IMAGE_STALE_DAYS, image_age_check, image_created
from workloadctl_core import WorkloadConfig

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def created(days):
    return (NOW.timestamp() - days * 86400)


def stamp(days):
    when = datetime.fromtimestamp(created(days), timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


class Reading(unittest.TestCase):

    def test_podmans_nanoseconds_are_read(self):
        got = image_created({"Created": "2026-07-18T09:30:01.123456789Z"})
        self.assertEqual(got, datetime(2026, 7, 18, 9, 30, 1, 123456,
                                       tzinfo=timezone.utc))

    def test_an_offset_is_kept(self):
        got = image_created({"Created": "2026-07-18T09:30:01.5+02:00"})
        self.assertEqual(got.utcoffset().total_seconds(), 7200)

    def test_no_time_judges_nothing(self):
        for info in ({}, {"Created": ""}, {"Created": "yesterday"}, None,
                     mock.Mock()):
            self.assertIsNone(image_created(info))
            self.assertIsNone(
                image_age_check("app", "image_current", "img", "missing",
                                info, now=NOW))


class Judging(unittest.TestCase):

    def test_a_fresh_image_passes(self):
        name, passed, message, fix = image_age_check(
            "app", "image_current", "img", "missing",
            {"Created": stamp(IMAGE_STALE_DAYS - 1)}, now=NOW)
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_a_stale_pulled_image_says_update(self):
        name, passed, message, fix = image_age_check(
            "app", "image_current", "img", "missing",
            {"Created": stamp(IMAGE_STALE_DAYS + 2)}, now=NOW)
        self.assertFalse(passed)
        self.assertIn(f"{IMAGE_STALE_DAYS + 1} days", message)
        self.assertEqual(fix, "Pull a newer one: workloadctl update app")

    def test_a_stale_built_image_says_build(self):
        _, passed, _, fix = image_age_check(
            "app", "image_current", "img", "never",
            {"Created": stamp(400)}, now=NOW)
        self.assertFalse(passed)
        self.assertIn("workloadctl build app", fix)


SINGLE_TOML = """\
[workload]
name = "app"

[container]
image = "localhost/app:latest"
"""


class Wiring(unittest.TestCase):
    """The battery runs it for a container workload with its image."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(SINGLE_TOML)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:0123456789ab"
        self.manager.podman.return_value.image_info.return_value = {
            "Created": "2020-01-01T00:00:00Z"}
        self.manager.podman.return_value.container_status.return_value = "Up"
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10099))
        self.enterContext(mock.patch.object(
            diagnose_battery.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        for module in (diagnose_battery, diagnose_inspect, diagnose_egress):
            self.enterContext(mock.patch.object(
                module, "service_active", return_value=(False, "inactive")))

    def test_an_old_image_fails_the_check(self):
        checks, _ = diagnose_battery.collect_diagnose_checks(
            WorkloadConfig("app"), self.manager)
        by_name = {c["check"]: c for c in checks}
        self.assertIn("image_current", by_name)
        self.assertFalse(by_name["image_current"]["passed"])
        self.assertIn("workloadctl update app", by_name["image_current"]["fix"])


if __name__ == "__main__":
    unittest.main()
