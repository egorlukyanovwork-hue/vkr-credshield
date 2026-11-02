# -*- coding: utf-8 -*-
"""Имитация штатного трафика выдач для подбора порога max_issues (BR-05).

n экземпляров одной роли; каждый заменяет учётные данные через t = (ρ − j·u)·T, u ~ U[0; 1), со случайной начальной фазой.
Сутки модельного времени; решение считается ложным срабатыванием, если трафик штатный.
    python stand/threshold_sim.py  ->  stand/threshold_results.json
"""
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from credshield.detector import Detector, Event  # noqa: E402

T, RHO, J, WINDOW, DAY = 3600.0, 2 / 3, 0.05, 300.0, 86400.0
ROLE, PATH = "orders", "database/creds/orders"


def traffic(n, rnd):
    ev = []
    for _ in range(n):
        t = rnd.random() * (RHO - J / 2) * T
        while t < DAY:
            ev.append(t)
            t += (RHO - J * rnd.random()) * T
    return sorted(ev)


def false_positives(n, max_issues, seed=1):
    rnd = random.Random(seed)
    det = Detector({ROLE: {PATH}}, window=WINDOW, max_issues=max_issues)
    cnt = 0
    for t in traffic(n, rnd):
        cnt += len(det.feed(Event(t, ROLE, PATH, True)))
    return cnt


def main():
    mean_t = (RHO - J / 2) * T
    rows = []
    for n in (10, 50, 100, 200, 300, 1000, 2341):
        expected = n * WINDOW / mean_t
        scaled = max(30, math.ceil(2 * expected))
        rows.append({"n": n, "expected": round(expected, 1), "fp_default": false_positives(n, 30),
                     "scaled": scaled, "fp_scaled": false_positives(n, scaled),
                     "detect_s_at_5rps": round(scaled / 5.0, 1)})
        print(rows[-1], flush=True)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "threshold_results.json"), "w",
              encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
