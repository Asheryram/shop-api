"""shop-api — a tiny product API backed by Postgres.

GET /health          liveness for the platform
GET /                where am I running? (env, branch, version, database)
GET /api/products    products from this environment's own database
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

VERSION = "1.1.0"


def db():
    return psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=3)


def info():
    try:
        with db() as conn:
            name = conn.execute("SELECT current_database()").fetchone()[0]
        database = {"ok": True, "name": name}
    except Exception as e:
        database = {"ok": False, "error": str(e).splitlines()[0]}
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
    return [{"id": r[0], "name": r[1], "price": float(r[2])} for r in rows]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)   # stdout → platform logs

    def do_GET(self):
        try:
            if self.path == "/health":
                body, code = {"ok": True}, 200
            elif self.path == "/":
                body, code = info(), 200
            elif self.path == "/api/products":
                body, code = products(), 200
            else:
                body, code = {"error": "not found"}, 404
        except Exception as e:
            body, code = {"error": str(e).splitlines()[0]}, 500
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")   # demo: any frontend preview may call us
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"shop-api {VERSION} listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
