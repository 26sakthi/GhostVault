from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")
router = APIRouter()


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@router.get("/view/{sid}")
def view(sid: str, request: Request):
    meta = request.app.state.service.meta(sid)  # SELECT only, never mutates
    if meta is None:
        return templates.TemplateResponse(request, "gone.html", status_code=404)
    return templates.TemplateResponse(request, "view.html", {"sid": sid, **meta})
