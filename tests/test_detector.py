# -*- coding: utf-8 -*-
import unittest
from credshield.detector import Detector, Event

PROFILE = {"orders": {"database/creds/orders"}, "billing": {"database/creds/billing"}}


def stream(role, path, n, start=0.0, step=1.0, allowed=True):
    return [Event(start + i * step, role, path, allowed) for i in range(n)]


def run(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out


class DetectorTest(unittest.TestCase):
    def test_role_limits_override_global(self):
        det = Detector(PROFILE, limits={"orders": {"max_issues": 1000}})
        self.assertEqual(run(det, stream("orders", "database/creds/orders", 100, step=1)), [])
        res = run(det, stream("billing", "database/creds/billing", 40, step=1))
        self.assertEqual([d.reason for d in res], ["issue_rate"])

    def test_normal_traffic_no_decisions(self):
        det = Detector(PROFILE)
        self.assertEqual(run(det, stream("orders", "database/creds/orders", 20, step=60)), [])

    def test_unknown_path(self):
        det = Detector(PROFILE)
        res = run(det, [Event(1, "orders", "database/creds/billing", True)])
        self.assertEqual([d.reason for d in res], ["unknown_path"])

    def test_unknown_role_is_unknown_path(self):
        det = Detector(PROFILE)
        res = run(det, [Event(1, "ghost", "database/creds/orders", True)])
        self.assertEqual([d.reason for d in res], ["unknown_path"])

    def test_denial_burst_fires_once(self):
        det = Detector(PROFILE, max_denials=5)
        res = run(det, stream("orders", "database/creds/orders", 12, allowed=False))
        self.assertEqual([d.reason for d in res], ["denial_burst"])

    def test_denials_below_threshold(self):
        det = Detector(PROFILE, max_denials=5)
        self.assertEqual(run(det, stream("orders", "database/creds/orders", 4, allowed=False)), [])

    def test_denials_outside_window_not_counted(self):
        det = Detector(PROFILE, window=300, max_denials=5)
        self.assertEqual(run(det, stream("orders", "database/creds/orders", 8,
                                         step=100, allowed=False)), [])

    def test_issue_rate(self):
        det = Detector(PROFILE, max_issues=30)
        res = run(det, stream("orders", "database/creds/orders", 40, step=1))
        self.assertEqual([d.reason for d in res], ["issue_rate"])

    def test_roles_are_independent(self):
        det = Detector(PROFILE, max_denials=3)
        run(det, stream("orders", "database/creds/orders", 3, allowed=False))
        self.assertEqual(run(det, stream("billing", "database/creds/billing", 5, start=10)), [])

    def test_flag_clears_after_quiet_window(self):
        det = Detector(PROFILE, window=300, max_denials=3)
        first = run(det, stream("orders", "database/creds/orders", 4, allowed=False))
        later = run(det, stream("orders", "database/creds/orders", 4, start=2000, allowed=False))
        self.assertEqual(len(first), 1)
        self.assertEqual(len(later), 1)

    def test_unknown_path_fires_again_after_quiet_window(self):
        det = Detector(PROFILE, window=300)
        a = run(det, [Event(1, "orders", "database/creds/billing", True)])
        b = run(det, [Event(1000, "orders", "database/creds/billing", True)])
        c = run(det, [Event(1010, "orders", "database/creds/billing", True)])
        self.assertEqual((len(a), len(b), len(c)), (1, 1, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
