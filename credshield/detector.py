# -*- coding: utf-8 -*-
"""Выявление отклонений в журнале обращений к хранилищу учётных данных.

Вход: нормализованные события. Адаптер журнала хранилища приводит запись
журнала к виду Event; сам детектор от формата журнала не зависит.
Выход: решения о реакции (отзыв аренд роли). Вызов отзыва выполняет
отдельный исполнитель, детектор побочных действий не имеет.
"""
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set


@dataclass(frozen=True)
class Event:
    ts: float          # время события, секунды
    role: str          # роль выдачи
    path: str          # запрошенный путь, например database/creds/orders
    allowed: bool      # решение хранилища


@dataclass(frozen=True)
class Decision:
    ts: float
    role: str
    reason: str        # unknown_path | denial_burst | issue_rate


class Detector:
    def __init__(self, profile: Dict[str, Set[str]], window: float = 300.0,
                 max_denials: int = 5, max_issues: int = 30, limits: Optional[Dict[str, dict]] = None):
        self.profile = profile            # роль -> допустимые пути (из политик)
        self.window = window
        self.max_denials = max_denials
        self.max_issues = max_issues
        self.limits = limits or {}          # индивидуальные пороги ролей: {роль: {max_denials, max_issues}}
        self._denials: Dict[str, Deque[float]] = defaultdict(deque)
        self._issues: Dict[str, Deque[float]] = defaultdict(deque)
        self._flagged: Dict[str, Set[str]] = defaultdict(set)
        self._unknown_ts: Dict[str, float] = {}

    def _max_denials(self, role: str) -> int:
        return self.limits.get(role, {}).get("max_denials", self.max_denials)

    def _max_issues(self, role: str) -> int:
        return self.limits.get(role, {}).get("max_issues", self.max_issues)

    def _trim(self, q: Deque[float], now: float) -> None:
        while q and now - q[0] > self.window:
            q.popleft()

    def _flag(self, ev: Event, reason: str, out: List[Decision]) -> None:
        # одна причина по одной роли даёт одно решение, пока окно не очистится
        if reason not in self._flagged[ev.role]:
            self._flagged[ev.role].add(reason)
            out.append(Decision(ev.ts, ev.role, reason))

    def _refresh_flags(self, role: str, now: float) -> None:
        """Снять метки, если условие срабатывания в окне больше не выполняется."""
        den, iss = self._denials[role], self._issues[role]
        self._trim(den, now)
        self._trim(iss, now)
        if now - self._unknown_ts.get(role, now) > self.window:
            self._flagged[role].discard("unknown_path")
        if len(den) < self._max_denials(role):
            self._flagged[role].discard("denial_burst")
        if len(iss) <= self._max_issues(role):
            self._flagged[role].discard("issue_rate")

    def feed(self, ev: Event) -> List[Decision]:
        out: List[Decision] = []
        self._refresh_flags(ev.role, ev.ts)
        if ev.path not in self.profile.get(ev.role, set()):
            self._unknown_ts[ev.role] = ev.ts
            self._flag(ev, "unknown_path", out)
        if not ev.allowed:
            q = self._denials[ev.role]
            q.append(ev.ts)
            if len(q) >= self._max_denials(ev.role):
                self._flag(ev, "denial_burst", out)
        else:
            q = self._issues[ev.role]
            q.append(ev.ts)
            if len(q) > self._max_issues(ev.role):
                self._flag(ev, "issue_rate", out)
        return out
