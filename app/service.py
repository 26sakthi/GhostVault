import sqlite3
import time
from datetime import datetime, timezone

from .crypto import CryptoEngine, TamperError
from .errors import NotFound, PasswordError
from .fingerprint import fingerprint
from .ids import is_valid_id, new_id
from .password import hash_password, verify_password

MAX_PASSWORD_FAILURES = 5  # stretch S2: wrong guesses before the secret is destroyed


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def iso(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class VaultService:
    def __init__(self, repo, crypto: CryptoEngine, base_url: str, fingerprint_enabled: bool = False):
        self.repo, self.crypto, self.base_url = repo, crypto, base_url
        self.fingerprint_enabled = fingerprint_enabled

    def create(self, secret: str, ttl: int, views: int, password: str | None = None, e2e: bool = False) -> dict:
        # e2e (stretch S3): `secret` is already client-side ciphertext; the server encrypts it again
        # and never sees the plaintext or the key (which lives only in the link's #fragment).
        created = now_ms()
        expires = created + ttl * 1000
        pw_salt, pw_hash = hash_password(password) if password is not None else (None, None)
        for _ in range(3):
            sid = new_id()
            sealed = self.crypto.encrypt(secret, aad=sid.encode())
            try:
                self.repo.insert(sid, sealed.ciphertext, sealed.iv, sealed.tag, views, expires, created,
                                 pw_salt, pw_hash, e2e)
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise RuntimeError("id collision")
        out = {
            "id": sid,
            "view_url": f"{self.base_url}/view/{sid}",
            "expires_at": iso(expires),
            "views_remaining": views,
        }
        if self.fingerprint_enabled:
            out["fingerprint"] = fingerprint(secret)  # returned once, never stored
        return out

    def burn(self, sid: str, password: str | None = None) -> dict:
        if not is_valid_id(sid):
            raise NotFound()
        self._check_password(sid, password)  # read-only; runs before any view is consumed
        row = self.repo.burn_atomic(sid, now_ms())
        if row is None:
            raise NotFound()
        try:
            pt = self.crypto.decrypt(row["ciphertext"], row["iv"], row["auth_tag"], aad=sid.encode())
        except TamperError:
            self.repo.delete(sid)  # destroy the corrupted record
            raise NotFound() from None
        left = row["views_remaining"]
        out = {"secret": pt, "views_remaining": left, "burned": left == 0}
        if row["e2e"]:
            out["e2e"] = True  # `secret` is client ciphertext: decrypt with the key from the link
        return out

    def _check_password(self, sid: str, password: str | None) -> None:
        row = self.repo.get_password(sid, now_ms())
        if row is None:
            raise NotFound()
        if row["pw_hash"] is None:  # not password-protected
            return
        if password is None:
            raise PasswordError("Password required.")
        if not verify_password(password, row["pw_salt"], row["pw_hash"]):
            if self.repo.record_password_failure(sid, MAX_PASSWORD_FAILURES):
                raise NotFound()  # limit reached: the secret is destroyed
            raise PasswordError("Incorrect password.")

    def meta(self, sid: str):
        if not is_valid_id(sid):
            return None
        r = self.repo.get_meta(sid, now_ms())
        if r is None:
            return None
        return {
            "expires_at": iso(r["expires_at"]),
            "views_remaining": r["views_remaining"],
            "protected": bool(r["protected"]),
            "e2e": bool(r["e2e"]),
        }
