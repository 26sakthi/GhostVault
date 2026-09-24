import asyncio
import logging

from .service import now_ms

log = logging.getLogger("vault.sweeper")


def sweep_once(repo) -> int:
    n = repo.purge_expired(now_ms())
    try:
        repo.checkpoint()  # WAL truncate; failure is non-fatal
    except Exception:
        pass
    return n


async def sweeper_loop(repo, interval: int):
    while True:
        await asyncio.sleep(interval)
        try:
            n = await asyncio.to_thread(sweep_once, repo)
            if n:
                log.info("sweeper.purged n=%d", n)
        except Exception as e:  # keep sweeping even if one run fails
            log.error("sweeper.error %s", type(e).__name__)
