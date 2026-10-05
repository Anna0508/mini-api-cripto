from fastapi import APIRouter

import hsm

router = APIRouter()


@router.get("/cofre/status")
def cofre_status():
    with hsm.sessao_hsm() as sessao:
        return {"token": sessao.token.label}