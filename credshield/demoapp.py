# -*- coding: utf-8 -*-
"""Демонстрационный микросервис: при каждом обращении читает реквизиты из файла и открывает новое соединение."""
import json
import os
import time

import pg8000.native

from .metrics import Registry


def main() -> None:
    path, host = os.environ.get("CRED_FILE", "/run/credentials/db.json"), os.environ["DB_HOST"]
    db, period = os.environ.get("DB_NAME", "orders"), float(os.environ.get("PERIOD", "5"))
    svc = os.environ.get("SERVICE", db)
    reg = Registry()
    reg.describe("credshield_app_queries_total", "counter", "Запросы микросервиса к СУБД по результату")
    reg.describe("credshield_app_query_duration_seconds", "histogram", "Длительность подключения и запроса")
    for r in ("ok", "error"):
        reg.touch("credshield_app_queries_total", service=svc, result=r)
    if os.environ.get("METRICS_PORT"):
        reg.serve(int(os.environ["METRICS_PORT"]))
    while True:
        t0 = time.time()
        try:
            with open(path) as f:
                c = json.load(f)
            conn = pg8000.native.Connection(c["username"], host=host, database=db, password=c["password"], timeout=5)
            user = conn.run("select current_user")[0][0]
            conn.close()
            rec = {"event": "query", "ok": True, "user": user}
        except Exception as e:                      # noqa: BLE001
            rec = {"event": "query", "ok": False, "error": str(e)[:160]}
        reg.inc("credshield_app_queries_total", service=svc, result="ok" if rec["ok"] else "error")
        reg.observe("credshield_app_query_duration_seconds", time.time() - t0, service=svc)
        rec["ts"] = round(t0, 3)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        time.sleep(period)


if __name__ == "__main__":
    main()
