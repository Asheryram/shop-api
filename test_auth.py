"""Focused HTTP tests for the customer authentication contract."""
import http.client
import json
import os
import sys
import threading
import types
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

if "psycopg" not in sys.modules:
    psycopg_stub = types.ModuleType("psycopg")
    psycopg_stub.connect = lambda *args, **kwargs: None
    sys.modules["psycopg"] = psycopg_stub

import app
from auth import hash_password, verify_password

WEB_ORIGIN = "https://shop.example.com"


class FakeCursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FakeDatabase:
    def __init__(self):
        self.customer = (7, "customer@example.com", hash_password("correct horse battery"))
        self.sessions = {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, query, params=()):
        if "FROM customers WHERE email" in query:
            return FakeCursor(self.customer if params[0] == self.customer[1] else None)
        if query.startswith("INSERT INTO customer_sessions"):
            self.sessions[params[0]] = (params[1], params[2])
            return FakeCursor()
        if "JOIN customers c ON c.id = s.customer_id" in query:
            record = self.sessions.get(params[0])
            if record and record[1] > params[1]:
                return FakeCursor((self.customer[0], self.customer[1]))
            return FakeCursor()
        if query.startswith("DELETE FROM customer_sessions"):
            self.sessions.pop(params[0], None)
            return FakeCursor()
        raise AssertionError(f"Unexpected SQL in test: {query}")


class CustomerAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.database = FakeDatabase()
        self.db_patch = patch("app.db", return_value=self.database)
        self.db_patch.start()
        self.env_patch = patch.dict(os.environ, {"WEB_ORIGIN": WEB_ORIGIN})
        self.env_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.addCleanup(self.env_patch.stop)

    def request(self, path, method="GET", payload=None, cookie=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Origin": WEB_ORIGIN}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            response = urlopen(request, timeout=2)
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            return response.status, response.headers, json.loads(body) if body else None

    def test_password_hash_is_salted_and_verified(self):
        first = hash_password("correct horse battery")
        second = hash_password("correct horse battery")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("correct horse battery", first))
        self.assertFalse(verify_password("wrong password", first))

    def test_successful_login_returns_customer_and_secure_cookie(self):
        status, headers, body = self.request(
            "/api/auth/login",
            method="POST",
            payload={"email": "CUSTOMER@example.com", "password": "correct horse battery"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {
            "authenticated": True,
            "customer": {"id": 7, "email": "customer@example.com"},
        })
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=None", cookie)
        self.assertNotIn("correct horse battery", cookie)

        session_status, _, session = self.request(
            "/api/auth/session",
            cookie=cookie.split(";", 1)[0],
        )
        self.assertEqual(session_status, 200)
        self.assertEqual(session["customer"], body["customer"])

    def test_invalid_credentials_are_generic_and_do_not_create_session(self):
        status, _, body = self.request(
            "/api/auth/login",
            method="POST",
            payload={"email": "customer@example.com", "password": "wrong password"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "Invalid email or password"})
        self.assertEqual(self.database.sessions, {})

    def test_malformed_input_is_rejected(self):
        status, _, body = self.request(
            "/api/auth/login",
            method="POST",
            payload={"email": [], "password": "secret"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "Expected a valid email and password"})
        self.assertEqual(self.database.sessions, {})

    def test_logout_revokes_the_session(self):
        _, headers, _ = self.request(
            "/api/auth/login",
            method="POST",
            payload={"email": "customer@example.com", "password": "correct horse battery"},
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, logout_headers, body = self.request(
            "/api/auth/logout", method="POST", cookie=cookie
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"authenticated": False})
        self.assertIn("Max-Age=0", logout_headers["Set-Cookie"])
        self.assertEqual(self.database.sessions, {})


if __name__ == "__main__":
    unittest.main()
