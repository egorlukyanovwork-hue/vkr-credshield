# -*- coding: utf-8 -*-
"""Исполнитель отзыва: по решению детектора отзывает аренды роли в хранилище."""
from typing import Callable, Dict

from .detector import Decision


class Revoker:
    def __init__(self, api, admin_token, db_mount: str = "database",
                 log: Callable[[dict], None] = print):
        self.api, self.db_mount, self.log = api, db_mount, log
        self._token = admin_token            # строка или функция, возвращающая актуальный токен
        self.done: Dict[str, float] = {}

    def execute(self, d: Decision) -> bool:
        if d.role == "unknown":
            self.log({"event": "revoke_skipped", "role": d.role, "reason": d.reason})
            return False
        try:
            token = self._token() if callable(self._token) else self._token
            self.api.revoke_prefix(token, "%s/creds/%s" % (self.db_mount, d.role))
        except Exception as e:                       # отзыв не удался: решение остаётся в журнале для ручного отзыва
            self.log({"event": "revoke_failed", "role": d.role, "reason": d.reason, "error": str(e)})
            return False
        self.done[d.role] = d.ts
        self.log({"event": "revoked", "role": d.role, "reason": d.reason})
        return True
