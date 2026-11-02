# -*- coding: utf-8 -*-
"""Минимальный клиент HTTP-интерфейса хранилища, совместимого с Vault (стандартная библиотека)."""
import json
import ssl
import urllib.error
import urllib.request
from typing import Optional


class ApiError(Exception):
    def __init__(self, status: int, body: str = ""):
        super().__init__("HTTP %s: %s" % (status, body[:200]))
        self.status = status


class VaultApi:
    def __init__(self, addr: str, timeout: float = 5.0, ca_file: Optional[str] = None):
        self.addr = addr.rstrip("/")
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if addr.startswith("https") else None

    def _call(self, method: str, path: str, body=None, token: Optional[str] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.addr + "/v1/" + path.lstrip("/"), data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ApiError(0, str(e))
        return json.loads(raw) if raw else {}

    def login(self, role: str, jwt: str, mount: str = "kubernetes") -> str:
        r = self._call("POST", "auth/%s/login" % mount, {"role": role, "jwt": jwt})
        return r["auth"]["client_token"]

    def creds(self, token: str, role: str, mount: str = "database") -> dict:
        r = self._call("GET", "%s/creds/%s" % (mount, role), token=token)
        return {"username": r["data"]["username"], "password": r["data"]["password"],
                "lease_id": r["lease_id"], "ttl": int(r["lease_duration"])}

    def revoke_lease(self, token: str, lease_id: str) -> None:
        self._call("PUT", "sys/leases/revoke", {"lease_id": lease_id}, token)

    def revoke_prefix(self, token: str, prefix: str) -> None:
        self._call("PUT", "sys/leases/revoke-prefix/" + prefix.strip("/"), None, token)
