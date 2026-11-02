# -*- coding: utf-8 -*-
import json
import os
import tempfile
import threading
import unittest

from credshield.agent import Agent, Config
from credshield.simulator import FakeVault
from credshield.vaultapi import VaultApi


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.sim = FakeVault(ttl=3600)
        self.dir = tempfile.mkdtemp()
        self.jwt = os.path.join(self.dir, "jwt")
        with open(self.jwt, "w") as f:
            f.write("token")
        self.out = os.path.join(self.dir, "run", "db.json")
        self.clock = Clock()
        self.events = []
        self.rnd = lambda: 0.0
        self.agent = self.make()

    def make(self, role="orders", **kw):
        cfg = Config(addr=self.sim.addr, role=role, jwt_path=self.jwt, out_path=self.out, **kw)
        return Agent(cfg, VaultApi(self.sim.addr, timeout=2), self.clock, lambda: self.rnd(), self.events.append)

    def tearDown(self):
        self.sim.close()

    def read(self):
        with open(self.out) as f:
            return json.load(f)

    def names(self):
        return [e["event"] for e in self.events]

    def test_first_issue_writes_file_with_mode(self):
        self.agent.issue()
        self.assertEqual(self.read()["username"], "v-orders-1")
        self.assertEqual(os.listdir(os.path.dirname(self.out)), ["db.json"])
        if os.name == "posix":
            self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o440)

    def test_replacement_at_two_thirds(self):
        self.agent.issue()
        self.clock.t += 2399                       # меньше 2/3 срока: обращения нет
        self.assertGreater(self.agent.tick(), 0)
        self.assertEqual(self.sim.n, 1)
        self.clock.t += 2                          # 2401 с >= 2400 с
        self.agent.tick()
        self.assertEqual(self.read()["username"], "v-orders-2")
        self.assertEqual(self.names(), ["issued", "replaced"])

    def test_old_lease_not_revoked_on_replacement(self):
        self.agent.issue()
        self.clock.t += 2401
        self.agent.tick()
        self.assertFalse([c for c in self.sim.calls if "revoke" in c[1]])

    def test_jitter_bounds(self):
        for r in (0.0, 0.5, 0.999):
            self.rnd = lambda r=r: r
            a = self.make(jitter=0.05)
            a.issue()
            share = (a.renew_at - self.clock.t) / 3600
            self.assertGreaterEqual(share, 2 / 3 - 0.05 - 1e-9)
            self.assertLessEqual(share, 2 / 3 + 1e-9)

    def test_backoff_grows_and_is_capped_and_resets(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 2401
        delays = []
        for _ in range(8):
            delays.append(self.agent.tick())
            self.clock.t += delays[-1]
        self.assertEqual(delays[:5], [1.0 * 0.5 * 2 ** i for i in range(5)])
        self.assertLessEqual(max(delays), 30.0)
        self.sim.down = False
        self.agent.tick()
        self.assertEqual(self.agent.failures, 0)

    def test_no_request_before_backoff_elapsed(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 2401
        wait = self.agent.tick()
        calls = len(self.sim.calls)
        for _ in range(5):                          # повторные вызовы цикла в пределах отсрочки
            self.clock.t += wait / 10
            self.agent.tick()
        self.assertEqual(len(self.sim.calls), calls)

    def test_outage_inside_window_has_no_gap(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 2401
        for _ in range(40):                         # недоступность 10 мин при окне 20 мин
            self.clock.t += self.agent.tick()
            if self.clock.t > 1000 + 2401 + 600:
                break
        self.assertTrue(os.path.exists(self.out))
        self.sim.down = False
        self.clock.t += 31
        self.agent.tick()
        self.assertEqual(self.read()["username"], "v-orders-2")
        self.assertNotIn("expired_removed", self.names())

    def test_fail_closed_after_lease_expiry(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 3601
        self.agent.tick()
        self.assertFalse(os.path.exists(self.out))
        self.assertIn("expired_removed", self.names())

    def test_expiry_enforced_while_backoff_pending(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 2401
        self.agent.tick()
        self.agent.next_try = self.clock.t + 10_000   # отсрочка длиннее остатка срока
        self.clock.t = 1000 + 3601
        self.agent.tick()
        self.assertFalse(os.path.exists(self.out))

    def test_backoff_capped_near_deadline(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 3590                         # до конца срока 10 с
        self.assertLessEqual(self.agent.tick(), 5.0)

    def test_undeliverable_credentials_are_revoked(self):
        os.makedirs(self.out)                       # на месте файла каталог: запись невозможна
        self.assertEqual(self.agent.run(once=True), 1)
        self.assertIn(("PUT", "sys/leases/revoke"), self.sim.calls)

    def test_warning_when_replacement_fails_near_deadline(self):
        self.agent.issue()
        self.sim.down = True
        self.clock.t += 3100                         # до конца срока 500 с < 600 с
        self.agent.tick()
        self.agent.tick()
        self.assertEqual(self.names().count("expiring_soon"), 1)

    def test_start_failure_leaves_no_file(self):
        self.sim.down = True
        self.assertEqual(self.agent.run(once=True), 1)
        self.assertFalse(os.path.exists(self.out))

    def test_login_denied_does_not_request_credentials(self):
        self.sim.fail_login = True
        self.assertEqual(self.agent.run(once=True), 1)
        self.assertFalse([c for c in self.sim.calls if c[1].startswith("database/")])

    @unittest.skipUnless(os.name == "posix", "подмена файла при открытом читателе — семантика POSIX")
    def test_reader_never_sees_partial_file(self):
        self.agent.issue()
        stop, bad = [], []

        def reader():
            while not stop:
                try:
                    with open(self.out) as f:
                        json.load(f)
                except (ValueError, FileNotFoundError, PermissionError) as e:
                    bad.append(e)
        th = threading.Thread(target=reader)
        th.start()
        for _ in range(150):
            self.clock.t += 2401
            self.agent.tick()
        stop.append(1)
        th.join()
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
