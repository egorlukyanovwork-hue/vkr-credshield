# -*- coding: utf-8 -*-
import json
import unittest

from credshield.adapter import parse
from credshield.detector import Detector
from credshield.executor import Revoker
from credshield.responder import process
from credshield.simulator import FakeVault
from credshield.vaultapi import VaultApi


def rec(path, role="orders", error=None, t="2026-11-01T10:00:00Z", typ="response"):
    r = {"type": typ, "time": t, "request": {"path": path}, "auth": {"metadata": {"role": role}}}
    if error:
        r["error"] = error
    return json.dumps(r)


class AdapterTest(unittest.TestCase):
    def test_allowed_and_denied(self):
        a = parse(rec("database/creds/orders"))
        d = parse(rec("database/creds/billing", error="permission denied"))
        self.assertTrue(a.allowed)
        self.assertFalse(d.allowed)
        self.assertEqual((a.role, a.path), ("orders", "database/creds/orders"))

    def test_overload_errors_are_not_denials(self):
        self.assertIsNone(parse(rec("database/creds/orders", error="context canceled")))
        self.assertIsNone(parse(rec("database/creds/orders", error="1 error occurred: timeout")))

    def test_ignores_other_records(self):
        self.assertIsNone(parse(rec("sys/health")))
        self.assertIsNone(parse(rec("database/creds/orders", typ="request")))
        self.assertIsNone(parse("не json"))

    def test_missing_role_is_unknown(self):
        r = json.loads(rec("database/creds/orders"))
        r["auth"] = {}
        self.assertEqual(parse(json.dumps(r)).role, "unknown")


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.sim = FakeVault()
        self.logs = []
        self.rev = Revoker(VaultApi(self.sim.addr), "root", log=self.logs.append)
        self.det = Detector({"orders": {"database/creds/orders"}})

    def tearDown(self):
        self.sim.close()

    def test_normal_traffic_no_revocation(self):
        n = process([rec("database/creds/orders", t="2026-11-01T10:%02d:00Z" % m) for m in range(10)],
                    self.det, self.rev)
        self.assertEqual((n, self.sim.revoked_prefixes), (0, []))

    def test_foreign_path_revokes_role_once(self):
        lines = [rec("database/creds/billing", t="2026-11-01T10:00:%02dZ" % s) for s in range(3)]
        process(lines, self.det, self.rev)
        self.assertEqual(self.sim.revoked_prefixes, ["database/creds/orders"])

    def test_token_is_taken_from_provider_at_each_revocation(self):
        seen = []
        rev = Revoker(VaultApi(self.sim.addr), lambda: seen.append(1) or "root", log=self.logs.append)
        det = Detector({"orders": {"database/creds/orders"}})
        process([rec("database/creds/billing")], det, rev)
        self.assertEqual(seen, [1])

    def test_revoke_failure_is_logged_not_raised(self):
        self.sim.down = True
        process([rec("database/creds/billing")], self.det, self.rev)
        self.assertEqual(self.logs[-1]["event"], "revoke_failed")


if __name__ == "__main__":
    unittest.main()
