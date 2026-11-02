# -*- coding: utf-8 -*-
"""Контроль в конвейере сборки: поиск учётных данных в файлах (REQ-FUNC-012). Код возврата 1 — найдены."""
import os
import re
import sys

RULES = [
    ("uri_with_password", re.compile(r"[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:(?!\$\{|\{\{|<)[^\s@/'\"]{3,}@", re.I)),
    ("password_assignment", re.compile(
        r"(?i)[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|token)\w*['\"]?\s*[:=]\s*"
        r"(?:\"[^\"\s${<]{4,}\"|'[^'\s${<]{4,}'|[A-Za-z0-9_+/-]{6,}\s*$)")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
SKIP_DIRS = {".git", "__pycache__", "node_modules"}
SKIP_EXT = {".png", ".jpg", ".gz", ".zip", ".pyc"}
ALLOW_MARK = "scan:allow"          # строка с этой пометкой пропускается (тестовые данные, примеры)


def scan_text(text: str, name: str = ""):
    found = []
    for i, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for rule, rx in RULES:
            if rx.search(line):
                found.append((name, i, rule))
    return found


def scan_tree(root: str):
    res = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if os.path.splitext(f)[1].lower() in SKIP_EXT:
                continue
            p = os.path.join(dp, f)
            try:
                with open(p, encoding="utf-8") as fh:
                    res += scan_text(fh.read(), os.path.relpath(p, root))
            except (UnicodeDecodeError, OSError):
                continue
    return res


def main(argv=None) -> int:
    root = (argv or sys.argv[1:] or ["."])[0]
    found = scan_tree(root)
    for name, line, rule in found:
        print("%s:%d: %s" % (name, line, rule))
    print("найдено: %d" % len(found))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
