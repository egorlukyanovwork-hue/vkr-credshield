# -*- coding: utf-8 -*-
import json
import os
import tempfile
import unittest
import urllib.request

from credshield.agent import Agent, Config
from credshield.detector import Detector
from credshield.executor import Revoker
from credshield.metrics import Registry
from credshield.responder import make_registry, process
from credshield.simulator import FakeVault
from credshield.vaultapi import VaultApi


def sample(text, name, **labels):
    """Значение ряда из текста экспозиции."""
    for line in text.splitlines():
        if line.startswith(name):
            head, val = line.rsplit(" ", 1)
            if all('%s="%s"' % kv in head for kv in labels.items()) and head.split("{")[0] == name:
                return float(val)
    return None


class RegistryTest(unittest.TestCase):
    def test_counter_gauge_histogram_format(self):
        r = Registry()
        r.describe("x_total", "counter", "тест")
        r.inc("x_total", 2, a="b")
        r.set("g", 5)
        r.observe("h", 0.3)
        r.observe("h", 3.0)
        t = r.render()
        self.assertIn("# TYPE x_total counter", t)
        self.assertEqual(sample(t, "x_total", a="b"), 2.0)
        self.assertEqual(sample(t, "g"), 5.0)
        self.assertEqual(sample(t, "h_bucket", le="0.5"), 1.0)
        self.assertEqual(sample(t, "h_bucket", le="+Inf"), 2.0)
        self.assertEqual(sample(t, "h_count"), 2.0)

    def test_touch_creates_zero_series(self):
        r = Registry()
        r.touch("y_total", role="orders")
        self.assertEqual(sample(r.render(), "y_total", role="orders"), 0.0)

    def test_http_endpoint(self):
        r = Registry()
        r.inc("z_total")
        srv = r.serve(0)
        try:
            body = urllib.request.urlopen("http://127.0.0.1:%d/metrics" % srv.server_address[1], timeout=3).read().decode()
            self.assertEqual(sample(body, "z_total"), 1.0)
        finally:
            srv.shutdown()
            srv.server_close()


class AgentMetricsTest(unittest.TestCase):
    def setUp(self):
        self.sim = FakeVault(ttl=3600)
        d = tempfile.mkdtemp()
        self.jwt = os.path.join(d, "jwt")
        with open(self.jwt, "w") as f:
            f.write("t")
        self.t = [1000.0]
        self.reg = Registry()
        cfg = Config(addr=self.sim.addr, role="orders", jwt_path=self.jwt, out_path=os.path.join(d, "r", "db.json"))
        self.agent = Agent(cfg, VaultApi(self.sim.addr, timeout=2), lambda: self.t[0], lambda: 0.0, lambda e: None, self.reg)

    def tearDown(self):
        self.sim.close()

    def test_issue_replace_and_lease_gauge(self):
        self.agent.issue()
        self.t[0] += 2401
        self.agent.tick()
        t = self.reg.render()
        self.assertEqual(sample(t, "credshield_agent_issues_total", role="orders", result="ok"), 2.0)
        self.assertEqual(sample(t, "credshield_agent_events_total", role="orders", event="replaced"), 1.0)
        self.assertEqual(sample(t, "credshield_agent_lease_remaining_seconds"), 3600.0)
        self.assertEqual(sample(t, "credshield_agent_file_present"), 1.0)

    def test_failures_and_expiry_are_counted(self):
        self.agent.issue()
        self.sim.down = True
        self.t[0] += 3601
        self.agent.tick()
        t = self.reg.render()
        self.assertGreaterEqual(sample(t, "credshield_agent_issues_total", role="orders", result="error"), 1.0)
        self.assertEqual(sample(t, "credshield_agent_events_total", role="orders", event="expired_removed"), 1.0)
        self.assertEqual(sample(t, "credshield_agent_file_present"), 0.0)


class ResponderMetricsTest(unittest.TestCase):
    def test_events_and_decisions_counted(self):
        sim = FakeVault()
        try:
            reg = make_registry(["orders"])
            rev = Revoker(VaultApi(sim.addr), "root", log=lambda e: None)
            det = Detector({"orders": {"database/creds/orders"}})
            rec = lambda path, err=None: json.dumps(
                dict(type="response", time="2026-11-01T10:00:00Z", request={"path": path},
                     auth={"metadata": {"role": "orders"}}, **({"error": err} if err else {})))
            process([rec("database/creds/orders"), rec("database/creds/billing", "permission denied")], det, rev, reg)
            t = reg.render()
            self.assertEqual(sample(t, "credshield_responder_events_total", role="orders", result="allowed"), 1.0)
            self.assertEqual(sample(t, "credshield_responder_events_total", role="orders", result="denied"), 1.0)
            self.assertEqual(sample(t, "credshield_responder_decisions_total", role="orders", reason="unknown_path"), 1.0)
            self.assertEqual(sample(t, "credshield_responder_revocations_total", role="orders", result="ok"), 1.0)
        finally:
            sim.close()


if __name__ == "__main__":
    unittest.main()
