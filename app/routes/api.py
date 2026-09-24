from fastapi import APIRouter, Request

from ..schemas import BurnOut, CreateSecretIn, CreateSecretOut

router = APIRouter()


@router.get("/health")
def health(request: Request):
    request.app.state.repo._c().execute("SELECT 1")
    return {"status": "ok"}


@router.post("/api/secret", status_code=201, response_model=CreateSecretOut)
def create_secret(body: CreateSecretIn, request: Request):
    return request.app.state.service.create(body.secret, body.ttl_seconds, body.max_views)


@router.post("/api/secret/{sid}/burn", response_model=BurnOut)
def burn_secret(sid: str, request: Request):
    return request.app.state.service.burn(sid)
