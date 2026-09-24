"""Stretch S2: optional password protection. Kept separate from the core CryptoEngine.

Only a salted scrypt hash is stored, never the password.
"""
import hashlib
import hmac
import os

SALT_LEN = 16
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}  # ~16 MB memory per check


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(SALT_LEN)
    return salt, hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    got = hashlib.scrypt(password.encode("utf-8"), salt=bytes(salt), **_SCRYPT)
    return hmac.compare_digest(got, bytes(expected))  # constant-time
