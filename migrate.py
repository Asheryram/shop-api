"""Database migrations — the platform runs this (MIGRATE_CMD) before each new version goes live.
Must be safe to run again and again."""
import os

import psycopg

with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id    serial PRIMARY KEY,
            name  text NOT NULL,
            price numeric(10, 2) NOT NULL
        )""")
    if conn.execute("SELECT count(*) FROM products").fetchone()[0] == 0:
        conn.execute("INSERT INTO products (name, price) VALUES "
                     "('Coffee mug', 9.50), ('Notebook', 4.20), ('Sticker pack', 2.00)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id            serial PRIMARY KEY,
            email         text NOT NULL UNIQUE,
            password_hash text NOT NULL
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customer_sessions (
            token_hash text PRIMARY KEY,
            customer_id integer NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            expires_at timestamptz NOT NULL
        )""")
    conn.execute("""
        CREATE INDEX IF NOT EXISTS customer_sessions_expires_at_idx
        ON customer_sessions (expires_at)""")
print("migrations applied")
