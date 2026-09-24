from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")
router = APIRouter()


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


# async on purpose: the only DB work is one primary-key SELECT (microseconds; WAL readers never
# wait for writers), so it runs inline instead of paying a threadpool hop. Writes stay sync.
@router.get("/view/{sid}")
async def view(sid: str, request: Request):
    meta = request.app.state.service.meta(sid)  # SELECT only, never mutates
    if meta is None:
        return templates.TemplateResponse(request, "gone.html", status_code=404)
    fp = request.app.state.service.fingerprint_enabled
    return templates.TemplateResponse(request, "view.html", {"sid": sid, "fingerprint": fp, **meta})
