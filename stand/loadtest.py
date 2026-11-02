# -*- coding: utf-8 -*-
"""Ступенчатая нагрузка на выдачу: python stand/loadtest.py 5 10 15 25 50 -> stand/load_results.json."""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
K = "kubectl --context kind-vkr -n credshield".split()
SECONDS = os.environ.get("SECONDS_PER_STEP", "60")


def kube(*a, inp=None):
    return subprocess.run(K + list(a), input=inp, capture_output=True, text=True, encoding="utf-8")


def main():
    rates = sys.argv[1:] or ["5", "10", "15", "25", "50"]
    manifest = open(os.path.join(HERE, "bench-job.yaml"), encoding="utf-8").read()
    results = []
    for rate in rates:
        kube("delete", "job", "bench", "--ignore-not-found")
        m = re.sub(r'(name: RATE, value: )"\d+"', r'\1"%s"' % rate, manifest)
        m = re.sub(r'(name: SECONDS, value: )"\d+"', r'\1"%s"' % SECONDS, m)
        t0 = time.time()
        kube("apply", "-f", "-", inp=m)
        kube("wait", "--for=condition=complete", "job/bench", "--timeout=300s")
        t1 = time.time()
        out = kube("logs", "job/bench").stdout.strip().splitlines()
        res = json.loads(out[-1]) if out else {}
        res.update({"start": round(t0), "end": round(t1)})
        results.append(res)
        print(json.dumps(res), flush=True)
        time.sleep(20)
    with open(os.path.join(HERE, "load_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
