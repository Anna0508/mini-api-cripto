from fastapi import FastAPI, Request
import metricas

from router import router

app = FastAPI(title="Mini API de criptografia")
app.include_router(router)


@app.get("/saude")
def saude():
    return {"status": "ok"}

@app.middleware("http")
async def add_metrics(request: Request, call_next):
    metricas.registrar_operacao(request.url.path)
    response = await call_next(request)
    return response