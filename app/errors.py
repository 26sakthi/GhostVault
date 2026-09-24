from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .routes.pages import templates

NOT_FOUND_MSG = "Secret not found, expired, or already destroyed."  # identical for every miss


class NotFound(Exception):
    pass


def _is_api(request: Request) -> bool:
    return request.url.path.startswith("/api/")


def html_error(request: Request, status: int):
    name = "gone.html" if status == 404 else "error.html"
    return templates.TemplateResponse(request, name, status_code=status)


def generic_500(request: Request):
    if _is_api(request):
        return JSONResponse({"error": "Internal server error."}, status_code=500)
    return html_error(request, 500)


def install(app) -> None:
    @app.exception_handler(NotFound)  # raised only by /api routes
    async def _nf(request: Request, _: NotFound):
        return JSONResponse({"error": NOT_FOUND_MSG}, status_code=404)

    @app.exception_handler(RequestValidationError)  # 400 instead of FastAPI's 422
    async def _val(request: Request, exc: RequestValidationError):
        errs = exc.errors()
        e = errs[0] if errs else {}
        if e.get("type") == "json_invalid":
            return JSONResponse({"error": "Invalid request: malformed JSON"}, status_code=400)
        field = ".".join(str(p) for p in e.get("loc", []) if p != "body") or "body"
        # never echo e["input"]: it may contain the secret
        return JSONResponse({"error": f"Invalid request: {field}: {e.get('msg', 'invalid')}"}, status_code=400)

    @app.exception_handler(StarletteHTTPException)  # unknown routes, 405, etc.
    async def _http(request: Request, exc: StarletteHTTPException):
        if not _is_api(request):
            return html_error(request, exc.status_code)
        msg = NOT_FOUND_MSG if exc.status_code == 404 else {405: "Method not allowed."}.get(exc.status_code, "Error")
        return JSONResponse({"error": msg}, status_code=exc.status_code)
