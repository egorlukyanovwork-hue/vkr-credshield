# -*- coding: utf-8 -*-
"""Испытание: хранилище недоступно в интервале [BREAK, RESTORE] секунд от выдачи; печатает хронологию агента и сервиса."""
import json
import subprocess
import sys
import time

K = "kubectl --context kind-vkr -n credshield".split()
BREAK, RESTORE, END = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])


def kube(*a):
    return subprocess.run(K + list(a), capture_output=True, text=True, encoding="utf-8").stdout


subprocess.run(K + ["rollout", "restart", "deploy/orders"], capture_output=True)
time.sleep(45)
pod = kube("get", "pod", "-l", "app=orders", "--field-selector=status.phase=Running",
           "--sort-by=.metadata.creationTimestamp", "-o", "name").split()[-1]
t0 = json.loads(kube("logs", pod, "-c", "credentials-agent").splitlines()[0])["ts"]


def at(dt):
    d = t0 + dt - time.time()
    if d > 0:
        time.sleep(d)


at(BREAK)
kube("patch", "svc", "openbao", "-p", '{"spec":{"selector":{"app":"nobody"}}}')
at(RESTORE)
kube("patch", "svc", "openbao", "-p", '{"spec":{"selector":{"app":"openbao"}}}')
at(END)
print("WINDOW", json.dumps({"t0": round(t0), "break": round(t0 + BREAK), "restore": round(t0 + RESTORE), "end": round(time.time())}))
print("== агент (с от выдачи)")
for l in kube("logs", pod, "-c", "credentials-agent").splitlines():
    d = json.loads(l)
    print(round(d["ts"] - t0, 1), d["event"], d.get("attempt", ""), d.get("delay", ""))
print("== сервис (смена состояния)")
prev = None
for l in kube("logs", pod, "-c", "service").splitlines():
    d = json.loads(l)
    k = (d["ok"], d.get("user", "")[-11:])
    if k != prev:
        print(round(d["ts"] - t0, 1), k)
        prev = k
