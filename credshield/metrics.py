# -*- coding: utf-8 -*-
"""Метрики в текстовом формате Prometheus (стандартная библиотека): счётчики, измерители, гистограммы."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional, Tuple

BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _labels(d: Dict[str, str]) -> str:
    if not d:
        return ""
    return "{" + ",".join('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"'))
                          for k, v in sorted(d.items())) + "}"


class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._help: Dict[str, Tuple[str, str]] = {}
        self._counters: Dict[Tuple[str, Tuple], float] = {}
        self._gauges: Dict[Tuple[str, Tuple], float] = {}
        self._hist: Dict[Tuple[str, Tuple], list] = {}
        self._callbacks: Dict[str, Callable[[], Optional[float]]] = {}

    def describe(self, name: str, kind: str, text: str) -> None:
        self._help[name] = (kind, text)

    def inc(self, name: str, value: float = 1.0, **labels) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def touch(self, name: str, **labels) -> None:
        """Создать счётчик со значением 0, чтобы ряд появился до первого события."""
        self.inc(name, 0.0, **labels)

    def set(self, name: str, value: float, **labels) -> None:
        with self._lock:
            self._gauges[(name, tuple(sorted(labels.items())))] = value

    def gauge_func(self, name: str, fn: Callable[[], Optional[float]]) -> None:
        self._callbacks[name] = fn

    def observe(self, name: str, value: float, **labels) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            h = self._hist.setdefault(key, [[0] * len(BUCKETS), 0, 0.0])
            for i, b in enumerate(BUCKETS):
                if value <= b:
                    h[0][i] += 1
            h[1] += 1
            h[2] += value

    def render(self) -> str:
        out, seen = [], set()

        def head(name):
            if name not in seen and name in self._help:
                kind, text = self._help[name]
                out.append("# HELP %s %s" % (name, text))
                out.append("# TYPE %s %s" % (name, kind))
            seen.add(name)
        with self._lock:
            gauges = dict(self._gauges)
            for name, fn in self._callbacks.items():
                v = fn()
                if v is not None:
                    gauges[(name, ())] = v
            for (name, lab), v in sorted(self._counters.items()):
                head(name)
                out.append("%s%s %g" % (name, _labels(dict(lab)), v))
            for (name, lab), v in sorted(gauges.items()):
                head(name)
                out.append("%s%s %g" % (name, _labels(dict(lab)), v))
            for (name, lab), (cnt, n, s) in sorted(self._hist.items()):
                head(name)
                for b, c in zip(BUCKETS, cnt):
                    out.append("%s_bucket%s %d" % (name, _labels(dict(lab, le=("%g" % b))), c))
                out.append("%s_bucket%s %d" % (name, _labels(dict(lab, le="+Inf")), n))
                out.append("%s_sum%s %g" % (name, _labels(dict(lab)), s))
                out.append("%s_count%s %d" % (name, _labels(dict(lab)), n))
        return "\n".join(out) + "\n"

    def serve(self, port: int) -> ThreadingHTTPServer:
        reg = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = reg.render().encode()
                self.send_response(200 if self.path.startswith("/metrics") else 404)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("0.0.0.0", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
