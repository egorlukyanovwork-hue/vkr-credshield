# -*- coding: utf-8 -*-
import os
import tempfile
import unittest

from credshield.scancheck import scan_text, scan_tree


class ScanTest(unittest.TestCase):
    def rules(self, text):
        return [r for _, _, r in scan_text(text)]

    def test_uri_with_password(self):
        self.assertEqual(self.rules("DSN=postgresql://app:S3cretPw@db:5432/orders"), ["uri_with_password"])  # scan:allow

    def test_password_assignment(self):
        self.assertIn("password_assignment", self.rules("DB_PASSWORD: hunter2hunter"))
        self.assertIn("password_assignment", self.rules('password = "abc12345"'))  # scan:allow

    def test_private_key(self):
        self.assertEqual(self.rules("-----BEGIN RSA PRIVATE KEY-----"), ["private_key"])  # scan:allow

    def test_placeholders_and_clean_text_pass(self):
        for s in ("password: ${DB_PASSWORD}", "url: postgresql://app:${PW}@db/x", "path: /run/credentials/db.json",
                  "password:", "token: <заполнить>", "import os"):
            self.assertEqual(self.rules(s), [], s)

    def test_allow_mark(self):
        self.assertEqual(self.rules("password = 'abc12345'  # scan:allow"), [])

    def test_tree_reports_file_and_line(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "a.yaml"), "w") as f:
            f.write("a: 1\nsecret: abcd1234\n")
        self.assertEqual(scan_tree(d), [("a.yaml", 2, "password_assignment")])


if __name__ == "__main__":
    unittest.main()
