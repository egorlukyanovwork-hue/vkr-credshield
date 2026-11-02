# -*- coding: utf-8 -*-
"""Имитатор API хранилища для модульных и интеграционных тестов (без реального хранилища)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeVault:
    def __init__(self, ttl: int = 3600, roles=("orders", "billing")):
        self.ttl, self.roles = ttl, set(roles)
        self.n = 0
        self.down = False            # имитация недоступности хранилища
        self.fail_login = False      # имитация отказа аутентификации
        self.calls = []              # (метод, путь)
        self.revoked_prefixes = []
        self.lock = threading.Lock()
        sim = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None):
                body = json.dumps(obj or {}).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                path = self.path.split("/v1/", 1)[1]
                with sim.lock:
                    sim.calls.append((self.command, path))
                    if sim.down:
                        return self._send(503, {"errors": ["unavailable"]})
                    if path == "auth/kubernetes/login":
                        if sim.fail_login or body.get("role") not in sim.roles:
                            return self._send(403, {"errors": ["permission denied"]})
                        return self._send(200, {"auth": {"client_token": "t-" + body["role"]}})
                    if path.startswith("database/creds/"):
                        role = path.rsplit("/", 1)[1]
                        if self.headers.get("X-Vault-Token") != "t-" + role:
                            return self._send(403, {"errors": ["permission denied"]})
                        sim.n += 1
                        return self._send(200, {"lease_id": "database/creds/%s/%d" % (role, sim.n),
                                                "lease_duration": sim.ttl,
                                                "data": {"username": "v-%s-%d" % (role, sim.n), "password": "pw%d" % sim.n}})  # scan:allow
                    if path.startswith("sys/leases/revoke-prefix/"):
                        sim.revoked_prefixes.append(path.split("revoke-prefix/", 1)[1])
                        return self._send(204)
                    if path == "sys/leases/revoke":
                        return self._send(204)
                    return self._send(404)

            do_GET = do_POST = do_PUT = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.addr = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
