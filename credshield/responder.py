# -*- coding: utf-8 -*-
"""Сервис реагирования: читает журнал аудита, применяет правила детектора, вызывает исполнитель отзыва."""
import json
import os
import sys
import time
from typing import Dict, Iterable, Optional, Set

from .adapter import parse
from .detector import Detector
from .executor import Revoker
from .metrics import Registry
from .vaultapi import VaultApi


def make_registry(roles) -> Registry:
    reg = Registry()
    reg.describe("credshield_responder_events_total", "counter", "Обращения к учётным данным по журналу аудита")
    reg.describe("credshield_responder_decisions_total", "counter", "Решения детектора по причине")
    reg.describe("credshield_responder_revocations_total", "counter", "Отзывы по результату")
    reg.describe("credshield_responder_last_event_timestamp", "gauge", "Время последнего разобранного события")
    for r in roles:
        for res in ("allowed", "denied"):
            reg.touch("credshield_responder_events_total", role=r, result=res)
        reg.touch("credshield_responder_revocations_total", role=r, result="ok")
        reg.touch("credshield_responder_revocations_total", role=r, result="error")
    return reg


def process(lines: Iterable[str], detector: Detector, revoker: Revoker, metrics: Optional[Registry] = None) -> int:
    n = 0
    for line in lines:
        ev = parse(line)
        if ev is None:
            continue
        if metrics:
            metrics.inc("credshield_responder_events_total", role=ev.role, result="allowed" if ev.allowed else "denied")
            metrics.set("credshield_responder_last_event_timestamp", ev.ts)
        for d in detector.feed(ev):
            ok = revoker.execute(d)
            n += 1
            if metrics:
                metrics.inc("credshield_responder_decisions_total", role=d.role, reason=d.reason)
                metrics.inc("credshield_responder_revocations_total", role=d.role, result="ok" if ok else "error")
    return n


def follow(path: str, poll: float = 0.5):
    """Чтение дописываемого файла журнала (аналог tail -F)."""
    while not os.path.exists(path):
        time.sleep(poll)
    with open(path, encoding="utf-8") as f:
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def main() -> int:
    env = os.environ
    profile: Dict[str, Set[str]] = {r: set(p) for r, p in json.loads(env["ROLE_PROFILE"]).items()}
    det = Detector(profile, window=float(env.get("WINDOW", "300")),
                   max_denials=int(env.get("MAX_DENIALS", "5")), max_issues=int(env.get("MAX_ISSUES", "30")),
                   limits=json.loads(env.get("ROLE_LIMITS", "{}")))
    log = lambda e: print(json.dumps(e, ensure_ascii=False), flush=True)
    token_file = env.get("ADMIN_TOKEN_FILE")
    while token_file and not os.path.exists(token_file):      # токен появляется после настройки хранилища
        time.sleep(1)

    def token():                                  # файл обновляется при перевыпуске токена, читаем при каждом отзыве
        if not token_file:
            return env["ADMIN_TOKEN"]
        with open(token_file) as f:
            return f.read().strip()
    rev = Revoker(VaultApi(env["VAULT_ADDR"]), token, log=log)
    reg = make_registry(profile)
    if env.get("METRICS_PORT"):
        reg.serve(int(env["METRICS_PORT"]))
    process(follow(env.get("AUDIT_LOG", "/audit/audit.log")), det, rev, reg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
