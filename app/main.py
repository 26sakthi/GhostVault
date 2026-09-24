import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers, MutableHeaders

from .config import get_settings
from .crypto import CryptoEngine
from .db import init_db
from .errors import generic_500
from .errors import install as install_errors
from .repository import SecretRepository
from .routes import api, pages
from .routes.pages import templates
from .security import SECURITY_HEADERS, BodyLimitMiddleware, is_bot
from .service import VaultService
from .sweeper import sweep_once, sweeper_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vault")
BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    init_db(s.db_path)
    repo = SecretRepository(s.db_path)
    app.state.repo = repo
    app.state.service = VaultService(repo, CryptoEngine(s.master_key), s.base_url, s.fingerprint)
    await asyncio.to_thread(sweep_once, repo)  # startup purge
    task = asyncio.create_task(sweeper_loop(repo, s.sweep_interval))
    try:
        yield
    finally:
        task.cancel()  # graceful shutdown
        with suppress(asyncio.CancelledError):
            await task


class GateMiddleware:
    """Bot gate + security headers + catch-all. Registered last, so it is the outermost middleware.

    Pure ASGI rather than BaseHTTPMiddleware, which roughly halves throughput (measured for S4).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers.setdefault(k, v)
            await send(message)

        ua = Headers(scope=scope).get("user-agent")
        if is_bot(ua):  # bots never change state
            path = scope["path"]
            if path.startswith("/view/"):
                resp = templates.TemplateResponse(Request(scope, receive), "bot.html", status_code=200)
            elif path.startswith("/api/"):
                resp = JSONResponse({"error": "Automated clients are not permitted."}, status_code=403)
            else:
                resp = Response(status_code=403)
            log.info("bot.blocked")
            return await resp(scope, receive, send_with_headers)

        started = False

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send_with_headers(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:  # no traceback in responses or logs
            log.error("unhandled error: %s", type(exc).__name__)
            if not started:
                await generic_500(Request(scope, receive))(scope, receive, send_with_headers)


def create_app() -> FastAPI:
    s = get_settings()  # key validated here (fail fast)
    app = FastAPI(
        lifespan=lifespan,
        docs_url="/docs" if s.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if s.enable_docs else None,
    )
    install_errors(app)
    app.add_middleware(BodyLimitMiddleware, max_bytes=s.max_body_bytes)
    app.add_middleware(GateMiddleware)  # registered last -> outermost
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    app.include_router(api.router)
    app.include_router(pages.router)
    return app


app = create_app()
