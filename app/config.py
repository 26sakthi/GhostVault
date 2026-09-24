import logging
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("vault")


@dataclass(frozen=True)
class Settings:
    master_key: bytes
    db_path: str
    base_url: str
    sweep_interval: int
    max_secret_bytes: int
    max_ttl: int
    max_views: int
    max_body_bytes: int
    enable_docs: bool
    fingerprint: bool


def _load_key() -> bytes:
    raw = os.getenv("VAULT_MASTER_KEY", "").strip()
    if not raw:  # handout FAQ: env var OR generated at boot
        log.warning("VAULT_MASTER_KEY not set: using an ephemeral key; secrets will not survive restart")
        return secrets.token_bytes(32)
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit("VAULT_MASTER_KEY must be 64 hex chars") from None
    if len(key) != 32:
        raise SystemExit("VAULT_MASTER_KEY must decode to exactly 32 bytes")
    return key


@lru_cache
def get_settings() -> Settings:
    return Settings(
        master_key=_load_key(),
        db_path=os.getenv("VAULT_DB_PATH", "vault.db"),
        base_url=os.getenv("VAULT_BASE_URL", "http://localhost:3000").rstrip("/"),
        sweep_interval=min(max(int(os.getenv("VAULT_SWEEP_INTERVAL", "10")), 5), 30),
        max_secret_bytes=int(os.getenv("VAULT_MAX_SECRET_BYTES", "65536")),
        max_ttl=int(os.getenv("VAULT_MAX_TTL", "604800")),
        max_views=int(os.getenv("VAULT_MAX_VIEWS", "100")),
        max_body_bytes=int(os.getenv("VAULT_MAX_BODY_BYTES", "131072")),
        enable_docs=os.getenv("VAULT_ENABLE_DOCS", "0") == "1",
        fingerprint=os.getenv("VAULT_FINGERPRINT", "0") == "1",  # stretch S1, off by default
    )
