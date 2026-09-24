import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_LEN, TAG_LEN = 12, 16


class TamperError(Exception):
    """Ciphertext, IV, tag or AAD failed authentication."""


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    iv: bytes
    tag: bytes


class CryptoEngine:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, aad: bytes) -> Sealed:
        iv = os.urandom(IV_LEN)  # fresh random IV for every secret
        out = self._aead.encrypt(iv, plaintext.encode("utf-8"), aad)
        return Sealed(ciphertext=out[:-TAG_LEN], iv=iv, tag=out[-TAG_LEN:])

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes) -> str:
        if not isinstance(iv, bytes) or len(iv) != IV_LEN or not isinstance(tag, bytes) or len(tag) != TAG_LEN:
            raise TamperError()
        try:
            return self._aead.decrypt(iv, bytes(ciphertext) + tag, aad).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, TypeError, ValueError):
            raise TamperError() from None
