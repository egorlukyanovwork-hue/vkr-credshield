# -*- coding: utf-8 -*-
"""Нагрузочный замер выдачи: заданная интенсивность запросов (вход + выдача), задержки в секундах."""
import json
import os
import statistics
import threading
import time

from .metrics import Registry
from .vaultapi import ApiError, VaultApi


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main() -> None:
    env = os.environ
    api = VaultApi(env["VAULT_ADDR"], timeout=10)
    role, rate, secs = env["CRED_ROLE"], float(env.get("RATE", "5")), float(env.get("SECONDS", "60"))
    with open(env.get("JWT_PATH", "/var/run/secrets/tokens/vault-token")) as f:
        jwt = f.read().strip()
    lat, errs, lock = [], [], threading.Lock()
    reg = Registry()
    reg.describe("credshield_bench_requests_total", "counter", "Запросы нагрузочного замера по результату")
    reg.describe("credshield_bench_duration_seconds", "histogram", "Задержка запроса: вход и выдача")
    reg.describe("credshield_bench_target_rate", "gauge", "Заданная интенсивность, запросов в секунду")
    for r in ("ok", "error"):
        reg.touch("credshield_bench_requests_total", result=r)
    reg.set("credshield_bench_target_rate", rate)
    if env.get("METRICS_PORT"):
        reg.serve(int(env["METRICS_PORT"]))

    def one():
        t0 = time.perf_counter()
        try:
            tok = api.login(role, jwt)
            api.creds(tok, role)
            d = time.perf_counter() - t0
            with lock:
                lat.append(d)
            reg.inc("credshield_bench_requests_total", result="ok")
            reg.observe("credshield_bench_duration_seconds", d)
        except ApiError as e:
            with lock:
                errs.append(str(e))
            reg.inc("credshield_bench_requests_total", result="error")
            reg.observe("credshield_bench_duration_seconds", time.perf_counter() - t0)

    ths, t_end, n = [], time.perf_counter() + secs, 0
    start = time.perf_counter()
    while time.perf_counter() < t_end:
        th = threading.Thread(target=one)
        th.start()
        ths.append(th)
        n += 1
        time.sleep(max(0.0, start + n / rate - time.perf_counter()))
    for th in ths:
        th.join()
    res = {"rate": rate, "seconds": secs, "sent": n, "ok": len(lat), "errors": len(errs),
           "p50": round(pct(lat, 50), 3), "p95": round(pct(lat, 95), 3), "p99": round(pct(lat, 99), 3),
           "max": round(max(lat), 3), "mean": round(statistics.mean(lat), 3)}
    print(json.dumps(res), flush=True)
    reg.set("credshield_bench_target_rate", 0)
    time.sleep(float(env.get("LINGER", "0")))     # время, чтобы Prometheus успел забрать последние значения


if __name__ == "__main__":
    main()
