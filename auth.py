"""Password hashing helpers shared by the API and customer provisioning command."""
import base64
import hashlib
import hmac
import re
import secrets

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email):
    return email.strip().lower()


def valid_email(email):
    return isinstance(email, str) and len(email) <= 254 and EMAIL_RE.fullmatch(email) is not None


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password, encoded):
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$")
        if algorithm != "scrypt" or (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (AttributeError, ValueError, TypeError, UnicodeError):
        return False


def session_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))
