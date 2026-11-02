# -*- coding: utf-8 -*-
"""Агент доставки: получает учётные данные у хранилища и подменяет файл до истечения аренды.

Алгоритм (подраздел 3.1): токен -> вход -> выдача -> атомарная запись файла -> повторная выдача
при расходовании доли `ratio` срока (с джиттером) -> закрытый отказ: файл удаляется, если срок истёк,
а новых данных нет.
"""
import argparse
import json
import os
import random
import signal
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .metrics import Registry
from .vaultapi import ApiError, VaultApi

EVENTS = ("issued", "replaced", "retry", "expiring_soon", "expired_removed", "start_failed")


@dataclass
class Config:
    addr: str
    role: str
    jwt_path: str = "/var/run/secrets/tokens/vault-token"
    out_path: str = "/run/credentials/db.json"
    auth_mount: str = "kubernetes"
    db_mount: str = "database"
    ratio: float = 2 / 3          # доля срока, после которой запрашиваются новые данные
    jitter: float = 0.05          # доля срока, на которую замена может быть сдвинута раньше
    backoff_base: float = 1.0
    backoff_cap: float = 30.0
    warn_before: float = 600.0    # за сколько секунд до конца срока подаётся сигнал, если замена не удаётся


class Agent:
    def __init__(self, cfg: Config, api, clock: Callable[[], float] = time.time,
                 rnd: Callable[[], float] = random.random, log: Optional[Callable[[dict], None]] = None,
                 metrics: Optional[Registry] = None):
        self.cfg, self.api, self.clock, self.rnd = cfg, api, clock, rnd
        self.m = metrics or Registry()
        self.m.describe("credshield_agent_events_total", "counter", "События агента доставки")
        self.m.describe("credshield_agent_issues_total", "counter", "Попытки получить учётные данные по результату")
        self.m.describe("credshield_agent_issue_duration_seconds", "histogram", "Длительность выдачи: вход и получение данных")
        self.m.describe("credshield_agent_lease_remaining_seconds", "gauge", "Остаток срока действующей аренды")
        self.m.describe("credshield_agent_file_present", "gauge", "1, если файл учётных данных существует")
        for e in EVENTS:
            self.m.touch("credshield_agent_events_total", role=cfg.role, event=e)
        for r in ("ok", "error"):
            self.m.touch("credshield_agent_issues_total", role=cfg.role, result=r)
        self.m.gauge_func("credshield_agent_lease_remaining_seconds",
                          lambda: max(self.lease_end - self.clock(), 0.0) if self.lease_end is not None else 0.0)
        self.m.gauge_func("credshield_agent_file_present", lambda: 1.0 if self.lease_end is not None else 0.0)
        self.log = log or (lambda e: print(json.dumps(e, ensure_ascii=False), flush=True))
        self.lease_end: Optional[float] = None
        self.renew_at: float = 0.0
        self.lease_id: Optional[str] = None
        self.failures = 0
        self.warned = False
        self.next_try = 0.0                  # не обращаться к хранилищу раньше этого момента (отсрочка после отказа)

    def _emit(self, event: str, **kw) -> None:
        self.m.inc("credshield_agent_events_total", role=self.cfg.role, event=event)
        self.log(dict(ts=round(self.clock(), 3), event=event, role=self.cfg.role, **kw))

    def _write(self, c: dict, expires: float) -> None:
        d = os.path.dirname(self.cfg.out_path)
        os.makedirs(d, exist_ok=True)
        tmp = self.cfg.out_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     0o440 if os.name == "posix" else 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"username": c["username"], "password": c["password"], "expires_at": expires}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.cfg.out_path)          # атомарная подмена: читатель видит старый или новый файл целиком

    def issue(self) -> None:
        t0 = time.perf_counter()
        try:
            self._issue()
        except Exception:
            self.m.inc("credshield_agent_issues_total", role=self.cfg.role, result="error")
            raise
        self.m.inc("credshield_agent_issues_total", role=self.cfg.role, result="ok")
        self.m.observe("credshield_agent_issue_duration_seconds", time.perf_counter() - t0, role=self.cfg.role)

    def _issue(self) -> None:
        with open(self.cfg.jwt_path) as f:
            jwt = f.read().strip()
        token = self.api.login(self.cfg.role, jwt, self.cfg.auth_mount)
        c = self.api.creds(token, self.cfg.role, self.cfg.db_mount)
        now = self.clock()
        first = self.lease_end is None
        try:
            self._write(c, now + c["ttl"])
        except OSError:
            try:                                       # учётная запись создана, а доставить её нельзя: отзываем сразу
                self.api.revoke_lease(token, c["lease_id"])
            except ApiError:
                pass
            raise
        self.lease_end = now + c["ttl"]
        self.renew_at = now + c["ttl"] * (self.cfg.ratio - self.cfg.jitter * self.rnd())
        self.lease_id = c["lease_id"]
        self.failures = 0
        self.warned = False
        self.next_try = 0.0
        self._emit("issued" if first else "replaced", ttl=c["ttl"], user=c["username"])

    def _fail(self, err: Exception) -> float:
        self.failures += 1
        if self.lease_end is not None and self.lease_end - self.clock() <= self.cfg.warn_before and not self.warned:
            self.warned = True                         # сигнал для мониторинга: замена не удаётся, срок на исходе
            self._emit("expiring_soon", left=round(self.lease_end - self.clock()))
        delay = min(self.cfg.backoff_cap, self.cfg.backoff_base * 2 ** (self.failures - 1))
        delay *= 0.5 + 0.5 * self.rnd()               # джиттер, чтобы экземпляры не обращались синхронно
        if self.lease_end is not None:                # к концу срока попытки учащаются
            delay = min(delay, max(1.0, (self.lease_end - self.clock()) / 2))
        self._emit("retry", attempt=self.failures, delay=round(delay, 2), error=str(err))
        return delay

    def _expire_if_due(self, now: float) -> None:
        """Закрытый отказ: по истечении срока аренды файл удаляется, даже если новых данных нет."""
        if self.lease_end is not None and now >= self.lease_end:
            try:
                os.remove(self.cfg.out_path)
            except FileNotFoundError:
                pass
            self.lease_end = None
            self._emit("expired_removed")

    def tick(self) -> float:
        """Один шаг цикла; возвращает, сколько секунд ждать до следующего."""
        now = self.clock()
        self._expire_if_due(now)
        if now < self.next_try:
            return self.next_try - now
        if self.lease_end is not None and now < self.renew_at:
            return self.renew_at - now
        try:
            self.issue()
            return max(self.renew_at - self.clock(), 0.0)
        except (ApiError, OSError, KeyError, ValueError) as e:
            delay = self._fail(e)
            self.next_try = self.clock() + delay
            self._expire_if_due(self.clock())
            return delay

    def run(self, sleep: Callable[[float], None] = time.sleep, once: bool = False) -> int:
        if once:
            try:
                self.issue()
                return 0
            except (ApiError, OSError, KeyError, ValueError) as e:
                self._emit("start_failed", error=str(e))
                return 1
        stop = []
        signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
        while not stop:
            sleep(min(self.tick(), 1.0))
        return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--once", action="store_true", help="одна выдача и выход (init-контейнер)")
    a = p.parse_args(argv)
    env = os.environ.get
    cfg = Config(addr=env("VAULT_ADDR", ""), role=env("CRED_ROLE", ""),
                 jwt_path=env("JWT_PATH", Config.jwt_path), out_path=env("OUT_PATH", Config.out_path),
                 ratio=float(env("RENEW_RATIO", "0.6667")), jitter=float(env("RENEW_JITTER", "0.05")))
    if not cfg.addr or not cfg.role:
        print("VAULT_ADDR и CRED_ROLE обязательны", file=sys.stderr)
        return 2
    reg = Registry()
    if not a.once and env("METRICS_PORT"):
        reg.serve(int(env("METRICS_PORT")))
    return Agent(cfg, VaultApi(cfg.addr, ca_file=env("VAULT_CACERT")), metrics=reg).run(once=a.once)


if __name__ == "__main__":
    sys.exit(main())
