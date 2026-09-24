from fastapi import APIRouter, Request

from ..schemas import BurnIn, BurnOut, CreateSecretIn, CreateSecretOut

router = APIRouter()


@router.get("/health")
async def health(request: Request):  # trivial read; inline (see pages.view)
    request.app.state.repo._c().execute("SELECT 1")
    return {"status": "ok"}


@router.post("/api/secret", status_code=201, response_model=CreateSecretOut, response_model_exclude_none=True)
def create_secret(body: CreateSecretIn, request: Request):
    return request.app.state.service.create(body.secret, body.ttl_seconds, body.max_views, body.password, body.e2e)


@router.post("/api/secret/{sid}/burn", response_model=BurnOut, response_model_exclude_none=True)
def burn_secret(sid: str, request: Request, body: BurnIn | None = None):
    return request.app.state.service.burn(sid, body.password if body else None)
