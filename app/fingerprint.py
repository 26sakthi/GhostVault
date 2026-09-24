"""Stretch S1: audit fingerprint. Kept separate from the core CryptoEngine.

The fingerprint is returned to the sender once and never stored: a stored hash of a
low-entropy secret could be brute-forced offline.
"""
import hashlib


def fingerprint(plaintext: str) -> str:
    return "sha256:" + hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
