import sqlite3
import time
from datetime import datetime, timezone

from .crypto import CryptoEngine, TamperError
from .errors import NotFound
from .ids import is_valid_id, new_id


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def iso(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class VaultService:
    def __init__(self, repo, crypto: CryptoEngine, base_url: str):
        self.repo, self.crypto, self.base_url = repo, crypto, base_url

    def create(self, secret: str, ttl: int, views: int) -> dict:
        created = now_ms()
        expires = created + ttl * 1000
        for _ in range(3):
            sid = new_id()
            sealed = self.crypto.encrypt(secret, aad=sid.encode())
            try:
                self.repo.insert(sid, sealed.ciphertext, sealed.iv, sealed.tag, views, expires, created)
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise RuntimeError("id collision")
        return {
            "id": sid,
            "view_url": f"{self.base_url}/view/{sid}",
            "expires_at": iso(expires),
            "views_remaining": views,
        }

    def burn(self, sid: str) -> dict:
        if not is_valid_id(sid):
            raise NotFound()
        row = self.repo.burn_atomic(sid, now_ms())
        if row is None:
            raise NotFound()
        try:
            pt = self.crypto.decrypt(row["ciphertext"], row["iv"], row["auth_tag"], aad=sid.encode())
        except TamperError:
            self.repo.delete(sid)  # destroy the corrupted record
            raise NotFound() from None
        left = row["views_remaining"]
        return {"secret": pt, "views_remaining": left, "burned": left == 0}

    def meta(self, sid: str):
        if not is_valid_id(sid):
            return None
        r = self.repo.get_meta(sid, now_ms())
        if r is None:
            return None
        return {"expires_at": iso(r["expires_at"]), "views_remaining": r["views_remaining"]}
