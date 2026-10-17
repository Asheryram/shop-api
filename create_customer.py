"""Provision a customer account without placing plaintext passwords in command history."""
import getpass
import os
import sys

import psycopg

from auth import hash_password, normalize_email, valid_email


def main():
    if len(sys.argv) != 2 or not valid_email(sys.argv[1]):
        print("Usage: python create_customer.py customer@example.com", file=sys.stderr)
        return 2

    email = normalize_email(sys.argv[1])
    password = getpass.getpass("New customer password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 2
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    try:
        with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
            conn.execute(
                "INSERT INTO customers (email, password_hash) VALUES (%s, %s)",
                (email, hash_password(password)),
            )
    except psycopg.errors.UniqueViolation:
        print("A customer with that email already exists.", file=sys.stderr)
        return 1
    print(f"Customer account created for {email}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
