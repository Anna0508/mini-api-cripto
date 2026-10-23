from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from fastapi import Request
from fastapi.responses import JSONResponse
from pkcs11.exceptions import NoSuchToken

import metricas
from router import router

app = FastAPI(title="Mini API de criptografia")
@app.exception_handler(NoSuchToken)
async def cofre_indisponivel(request: Request, exc: NoSuchToken):
    return JSONResponse(
        status_code=503,
        content={"detail": "Cofre indisponível no momento."},
    )
app.include_router(router)


@app.get("/saude")
def saude():
    return {"status": "ok"}

@app.middleware("http")
async def add_metrics(request: Request, call_next):
    metricas.registrar_operacao(request.url.path)
    response = await call_next(request)
    return response

app.mount("/", StaticFiles(directory="painel", html=True), name="painel")