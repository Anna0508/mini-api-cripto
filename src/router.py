import base64
from schemas import NomeEntrada, AssinarEntrada, VerificarEntrada, CifrarEntrada, DecifrarEntrada
from fastapi import APIRouter
import cripto
import hsm

router = APIRouter()


@router.get("/cofre/status")
def cofre_status():
    with hsm.sessao_hsm() as sessao:
        return {"token": sessao.token.label}
    
@router.post("/assinar")
def assinar_texto(dados: AssinarEntrada):
    assinatura = cripto.assinar(dados.nome, dados.texto)
    return {"assinatura": base64.b64encode(assinatura).decode()}

@router.post("/chaves/rsa")
def criar_chave_rsa(dados: NomeEntrada):
    publica = cripto.gerar_par_de_chaves(dados.nome)
    return {"chave_publica": publica}

@router.post("/verificar")
def verificar_assinatura(dados: VerificarEntrada):
    assinatura = base64.b64decode(dados. assinatura)
    valida = cripto.verificar(dados.nome, dados.texto, assinatura)
    return {"valida": valida}

@router.post("/chaves/aes")
def criar_chave_aes(dados: NomeEntrada):
    cripto.gerar_chave_aes(dados.nome)
    return {"mensagem": "chave AES criada"}

@router.post("/cifrar")
def cifrar_texto(dados: CifrarEntrada):
    iv, cifrado = cripto.cifrar(dados.nome, dados.texto)
    return {
        "iv": base64.b64encode(iv).decode(),
        "cifrado": base64.b64encode(cifrado).decode()
    }

@router.post("/decifrar")
def decifrar_texto(dados: DecifrarEntrada):
    iv = base64.b64decode(dados.iv)
    cifrado = base64.b64decode(dados.cifrado)
    texto = cripto.decifrar(dados.nome, iv, cifrado)
    return {"texto": texto}