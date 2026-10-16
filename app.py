\
"""shop-api — a tiny product API backed by Postgres.

GET /health          liveness for the platform
GET /                where am I running? (env, branch, version, database)
GET /api/products    products from this environment's own database
"""
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import psycopg

from auth import DUMMY_PASSWORD_HASH, hash_password, normalize_email, session_digest, valid_email, verify_password

VERSION = "1.0.0"
SESSION_TTL = timedelta(days=7)
SESSION_COOKIE = "shop_session"
MAX_AUTH_BODY = 8192
logger = logging.getLogger(__name__)


def db():
    return psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=3)


def info():
    try:
        with db() as conn:
            name = conn.execute("SELECT current_database()").fetchone()
        database = {"ok": True, "name": name}
    except Exception as e:
        database = {"ok": False, "error": str(e).splitlines()}
    return {
        "service": "shop-api",
        "version": VERSION,
        "env": os.environ.get("APP_ENV"),
        "branch": os.environ.get("GIT_BRANCH"),
        "commit": (os.environ.get("GIT_COMMIT") or "")[:8],
        "database": database,
    }


def products():
    with db() as conn:
        rows = conn.execute("SELECT id, name, price FROM products ORDER BY id").fetchall()
    return [{"id": r, "name": r, "price": float(r)} for r in rows]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)   # stdout → platform logs

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/auth/session":
            self.handle_auth_session()
            return
        try:
            if path == "/health":
                body, code = {"ok": True}, 200
            elif path == "/":
                body, code = info(), 200
            elif path == "/api/products":
                body, code = products(), 200
            else:
                body, code = {"error": "not found"}, 404
        except Exception as e:
            body, code = {"error": str(e).splitlines()}, 500
        self.send_json(code, body)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/auth/login", "/api/auth/register", "/api/auth/logout"):
            self.send_json(404, {"error": "not found"})
            return
        if not self.authorize_browser_origin():
            return
        if path == "/api/auth/login":
            self.handle_auth_login()
        elif path == "/api/auth/register":
            self.handle_auth_register()
        else:
            self.handle_auth_logout()

    def do_OPTIONS(self):
        path = urlsplit(self.path).path
        if path not in (
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/logout",
            "/api/auth/session",
        ):
            self.send_json(204, None)
            return
        if not self.browser_origin_matches():
            self.send_json(403, {"error": "origin not allowed"}, auth=True)
            return
        self.send_response(204)
        self.add_auth_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def browser_origin_matches(self):
        configured = os.environ.get("WEB_ORIGIN", "").rstrip("/")
        origin = self.headers.get("Origin", "").rstrip("/")
        return bool(configured and origin and origin == configured)

    def authorize_browser_origin(self):
        if not os.environ.get("WEB_ORIGIN"):
            self.send_json(503, {"error": "Authentication is not configured"}, auth=True)
            return False
        if not self.browser_origin_matches():
            self.send_json(403, {"error": "origin not allowed"}, auth=True)
            return False
        return True

    def add_auth_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", os.environ["WEB_ORIGIN"].rstrip("/"))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")

    def send_json(self, code, body, auth=False, cookie=None, clear_cookie=False):
        data = b"" if body is None else json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if auth:
            if self.browser_origin_matches():
                self.add_auth_cors_headers()
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        if cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={cookie}; Path=/; Max-Age={int(SESSION_TTL.total_seconds())}; "
                "HttpOnly; Secure; SameSite=None",
            )
        elif clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None",
            )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def request_json(self):
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if content_length <= 0 or content_length > MAX_AUTH_BODY:
            return None
        if self.headers.get_content_type() != "application/json":
            return None
        try:
            body = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return body if isinstance(body, dict) else None

    def handle_auth_login(self):
        payload = self.request_json()
        if payload is None:
            self.send_json(400, {"error": "Expected a JSON email and password"}, auth=True)
            return
        email = payload.get("email")
        password = payload.get("password")
        if (
            not valid_email(email)
            or not isinstance(password, str)
            or not password
            or len(password) > 1024
        ):
            self.send_json(400, {"error": "Expected a valid email and password"}, auth=True)
            return

        try:
            email = normalize_email(email)
            with db() as conn:
                customer = conn.execute(
                    "SELECT id, email, password_hash FROM customers WHERE email = %s",
                    (email,),
                ).fetchone()
                
                if customer:
                    password_hash = customer[2]
                else:
                    password_hash = DUMMY_PASSWORD_HASH

                password_ok = verify_password(password, password_hash)
                if not customer or not password_ok:
                    self.send_json(401, {"error": "Invalid email or password"}, auth=True)
                    return

                customer_id = customer[0]
                
            with db() as conn:
                token = self.issue_session(conn, customer_id)
                
            self.send_authenticated_customer(customer, token)
        except Exception:
            logger.exception("Customer login failed")
            self.send_json(503, {"error": "Authentication service unavailable"}, auth=True)

    def handle_auth_register(self):
        payload = self.request_json()
        if payload is None:
            self.send_json(400, {"error": "Expected a JSON email and password"}, auth=True)
            return
        email = payload.get("email")
        password = payload.get("password")
        if (
            not valid_email(email)
            or not isinstance(password, str)
            or len(password) < 12
            or len(password) > 1024
        ):
            self.send_json(
                400,
                {"error": "Enter a valid email and a password with at least 12 characters"},
                auth=True,
            )
            return

        try:
            email = normalize_email(email)
            with db() as conn:
                customer = conn.execute(
                    "INSERT INTO customers (email, password_hash) VALUES (%s, %s) "
                    "ON CONFLICT (email) DO NOTHING RETURNING id, email",
                    (email, hash_password(password)),
                ).fetchone()
                
                if not customer:
                    self.send_json(
                        409,
                        {"error": "An account with this email already exists"},
                        auth=True,
                    )
                    return
                
                customer_id = customer[0]
                
            with db() as conn:
                token = self.issue_session(conn, customer_id)
                
            self.send_authenticated_customer(customer, token)
        except Exception:
            logger.exception("Customer registration failed")
            self.send_json(503, {"error": "Authentication service unavailable"}, auth=True)

    def issue_session(self, conn, customer_id):
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + SESSION_TTL
        conn.execute(
            "INSERT INTO customer_sessions (token_hash, customer_id, expires_at) "
            "VALUES (%s, %s, %s)",
            (session_digest(token), customer_id, expires_at),
        )
        return token

    def send_authenticated_customer(self, customer, token):
        self.send_json(
            200,
            {
                "authenticated": True,
                "customer": {"id": customer[0], "email": customer[1]},
            },
            auth=True,
            cookie=token,
        )

    def request_cookie(self):
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            return cookies[SESSION_COOKIE].value if SESSION_COOKIE in cookies else None
        except (KeyError, ValueError):
            return None

    def handle_auth_session(self):
        if not self.authorize_browser_origin():
            return
        token = self.request_cookie()
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]{40,}", token):
            self.send_json(200, {"authenticated": False}, auth=True, clear_cookie=bool(token))
            return
        try:
            with db() as conn:
                customer = conn.execute(
                    "SELECT c.id, c.email FROM customer_sessions s "
                    "JOIN customers c ON c.id = s.customer_id "
                    "WHERE s.token_hash = %s AND s.expires_at > %s",
                    (session_digest(token), datetime.now(timezone.utc)),
                ).fetchone()
            if not customer:
                self.send_json(200, {"authenticated": False}, auth=True, clear_cookie=True)
                return
            self.send_json(
                200,
                {
                    "authenticated": True,
                    "customer": {"id": customer[0], "email": customer[1]},
                },
                auth=True,
            )
        except Exception:
            logger.exception("Customer session lookup failed")
            self.send_json(503, {"error": "Authentication service unavailable"}, auth=True)

    def handle_auth_logout(self):
        token = self.request_cookie()
        try:
            if token and re.fullmatch(r"[A-Za-z0-9_-]{40,}", token):
                with db() as conn:
                    conn.execute(
                        "DELETE FROM customer_sessions WHERE token_hash = %s",
                        (session_digest(token),),
                    )
            self.send_json(200, {"authenticated": False}, auth=True, clear_cookie=True)
        except Exception:
            logger.exception("Customer logout failed")
            self.send_json(503, {"error": "Authentication service unavailable"}, auth=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"shop-api {VERSION} listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
