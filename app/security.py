import re

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# Handout minimum: bot, crawl, spider, Slackbot, facebookexternalhit.
# The rest are common link unfurlers (hardening).
BOT_UA = re.compile(
    r"bot|crawl|spider|slurp|facebookexternalhit|facebookcatalog|embedly|"
    r"slack|discord|whatsapp|telegram|skypeuripreview|teams|linkedin|"
    r"twitter|pinterest|vkshare|quora|outbrain|bitly|"
    r"preview|unfurl|google-inspectiontool|mastodon",
    re.I,
)


def is_bot(ua: str | None) -> bool:
    return bool(ua) and bool(BOT_UA.search(ua))


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
}


class BodyLimitMiddleware:
    """Buffers the request body (up to the limit) and returns 413 if it is larger.

    Buffering is used, rather than raising mid-read, because FastAPI turns exceptions
    raised while it reads the body into 400s.
    """

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app, self.max = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        too_large = JSONResponse({"error": "Payload too large."}, status_code=413)
        cl = dict(scope["headers"]).get(b"content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > self.max):
            return await too_large(scope, receive, send)
        body, more = b"", True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body += msg.get("body", b"")
            if len(body) > self.max:
                return await too_large(scope, receive, send)
            more = msg.get("more_body", False)

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
