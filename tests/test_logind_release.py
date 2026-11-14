"""workload_uid.wait_logind_release: purge and cleanup wait on it before
userdel frees a uid.

A workload purged and another created a few seconds later get the same
uid. If logind still holds the old record (UserStopDelaySec, 10 s), it files
the new user under the old name, sees no linger for it and stops its manager
at the next clean-up, so every restart fails with /run/user/<uid> missing
(226/NAMESPACE).
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import workload_uid


def busctl(results):
    calls = []

    def run(argv, **_kw):
        calls.append(argv)
        return SimpleNamespace(returncode=results.pop(0) if results else 0)
    return run, calls


class LogindReleaseTest(unittest.TestCase):
    def test_asks_logind_for_the_uid(self):
        run, calls = busctl([1])
        with patch.object(workload_uid.subprocess, 'run', run):
            self.assertTrue(workload_uid.wait_logind_release(10005))
        self.assertEqual(calls[0][:2], ['busctl', 'call'])
        self.assertEqual(calls[0][-3:], ['GetUser', 'u', '10005'])

    def test_waits_while_logind_holds_the_uid(self):
        run, calls = busctl([0, 0, 1])
        with patch.object(workload_uid.subprocess, 'run', run), \
             patch.object(workload_uid.time, 'sleep') as sleep:
            self.assertTrue(workload_uid.wait_logind_release(10005))
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_gives_up_at_the_timeout(self):
        clock = iter([0.0, 10.0, 31.0])
        run, _ = busctl([0] * 10)
        with patch.object(workload_uid.subprocess, 'run', run), \
             patch.object(workload_uid.time, 'sleep'), \
             patch.object(workload_uid.time, 'monotonic',
                          lambda: next(clock)):
            self.assertFalse(workload_uid.wait_logind_release(10005, 30))


if __name__ == '__main__':
    unittest.main()
