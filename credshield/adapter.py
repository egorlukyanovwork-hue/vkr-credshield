# -*- coding: utf-8 -*-
"""Адаптер журнала: запись журнала аудита хранилища (JSON) -> нормализованное событие детектора."""
import json
from datetime import datetime
from typing import Optional

from .detector import Event


def _ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def parse(line: str) -> Optional[Event]:
    """Возвращает событие для ответа хранилища на обращение к учётным данным, иначе None."""
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if rec.get("type") != "response":
        return None
    path = (rec.get("request") or {}).get("path", "")
    if not path.startswith("database/creds/"):
        return None
    err = rec.get("error") or ""
    if err and "permission denied" not in err:
        return None                      # сбой или перегрузка хранилища — не отказ в доступе, в правилах не учитывается
    meta = (rec.get("auth") or {}).get("metadata") or {}
    role = meta.get("role") or "unknown"
    return Event(ts=_ts(rec["time"]), role=role, path=path, allowed=not rec.get("error"))
