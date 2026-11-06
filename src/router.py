import base64

from fastapi import APIRouter, HTTPException
from pkcs11.exceptions import NoSuchKey, NoSuchToken

import auditoria
import cripto
import hsm
import metricas
import schemas
from schemas import (
    AssinarEntrada,
    CifrarEntrada,
    DecifrarEntrada,
    NomeEntrada,
    VerificarEntrada,
)
from trava import TravaDeArquivo

router = APIRouter()
TRAVA_CRIACAO = TravaDeArquivo("criacao")


def verificar_limite():
    em_uso = metricas.chaves_em_uso()
    limite = metricas.LIMITE_CHAVES

    if em_uso >= limite:
        raise HTTPException(
            status_code=409,
            detail={
                "mensagem": "Criação recusada: limite máximo de chaves atingido",
                "limite": limite,
                "em_uso": em_uso,
            },
        )


@router.get("/cofre/status")
def cofre_status():
    with hsm.sessao_hsm() as sessao:
        return {"token": sessao.token.label}


@router.post("/assinar")
def assinar_texto(dados: AssinarEntrada):
    with auditoria.auditar("assinar", dados.nome):
        assinatura = cripto.assinar(dados.nome, dados.texto)
    return {"assinatura": base64.b64encode(assinatura).decode()}


@router.post("/chaves/rsa")
def criar_chave_rsa(dados: NomeEntrada):
    with auditoria.auditar("criar_chave_rsa", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            publica = cripto.gerar_par_de_chaves(dados.nome)
    return {"chave_publica": publica}


@router.post("/verificar")
def verificar_assinatura(dados: VerificarEntrada):
    assinatura = base64.b64decode(dados.assinatura)
    with auditoria.auditar("verificar", dados.nome):
        valida = cripto.verificar(dados.nome, dados.texto, assinatura)
    return {"valida": valida}


@router.post("/chaves/aes")
def criar_chave_aes(dados: NomeEntrada):
    with auditoria.auditar("criar_chave_aes", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            cripto.gerar_chave_aes(dados.nome)
    return {"mensagem": "chave AES criada"}


@router.post("/cifrar")
def cifrar_texto(dados: CifrarEntrada):
    with auditoria.auditar("cifrar", dados.nome):
        iv, cifrado = cripto.cifrar(dados.nome, dados.texto)
    return {
        "iv": base64.b64encode(iv).decode(),
        "cifrado": base64.b64encode(cifrado).decode(),
    }


@router.post("/decifrar")
def decifrar_texto(dados: DecifrarEntrada):
    iv = base64.b64decode(dados.iv)
    cifrado = base64.b64decode(dados.cifrado)
    with auditoria.auditar("decifrar", dados.nome):
        texto = cripto.decifrar(dados.nome, iv, cifrado)
    return {"texto": texto}


@router.post("/cofre/chaves/rsa")
def criar_chave_rsa_no_cofre(dados: NomeEntrada):
    with auditoria.auditar("cofre_criar_chave_rsa", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            publica = hsm.gerar_par_no_cofre(dados.nome)
    return {"chave_publica": base64.b64encode(publica).decode()}


@router.post("/cofre/assinar")
def assinar_texto_no_cofre(dados: AssinarEntrada):
    with auditoria.auditar("cofre_assinar", dados.nome):
        try:
            assinatura = hsm.assinar_no_cofre(dados.nome, dados.texto)
        except NoSuchKey:
            raise HTTPException(
                status_code=404,
                detail=f"Chave '{dados.nome}' não encontrada no cofre.",
            )
    return {"assinatura": base64.b64encode(assinatura).decode()}


@router.post("/cofre/verificar")
def verificar_assinatura_no_cofre(dados: VerificarEntrada):
    assinatura = base64.b64decode(dados.assinatura)
    with auditoria.auditar("cofre_verificar", dados.nome):
        valida = hsm.verificar_no_cofre(dados.nome, dados.texto, assinatura)
    return {"valida": valida}


@router.post("/cofre/chaves/aes")
def criar_chave_aes_no_cofre(dados: NomeEntrada):
    with auditoria.auditar("cofre_criar_chave_aes", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            hsm.gerar_chave_aes_no_cofre(dados.nome)
    return {"mensagem": "chaves AES criadas no cofre"}


@router.post("/cofre/cifrar")
def cifrar_texto_no_cofre(dados: CifrarEntrada):
    with auditoria.auditar("cofre_cifrar", dados.nome):
        iv, cifrado = hsm.cifrar_no_cofre(dados.nome, dados.texto)
    return {
        "iv": base64.b64encode(iv).decode(),
        "cifrado": base64.b64encode(cifrado).decode(),
    }


@router.post("/cofre/decifrar")
def decifrar_texto_no_cofre(dados: DecifrarEntrada):
    iv = base64.b64decode(dados.iv)
    cifrado = base64.b64decode(dados.cifrado)
    with auditoria.auditar("cofre_decifrar", dados.nome):
        texto = hsm.decifrar_no_cofre(dados.nome, iv, cifrado)
    return {"texto": texto}


@router.get("/cofre/chaves")
def listar_chaves():
    return {"chaves": hsm.listar_chaves()}


@router.get("/monitoramento", response_model=schemas.MonitoramentoSaida)
def monitoramento():
    tempo = metricas.tempo_no_ar()
    total_ops = metricas.total_operacoes
    ops_por_rota = dict(metricas.operacoes_por_rota)
    total_chaves = metricas.total_de_chaves()
    bytes_disco = metricas.bytes_em_disco()
    chaves_por_tipo = metricas.chaves_por_tipo()
    bytes_disco_legivel = metricas.formatar_bytes(bytes_disco)
    tempo_no_ar_legivel = metricas.formatar_tempo(tempo)
    try:
        chaves_do_cofre = metricas.chaves_do_cofre()
        chaves_em_uso = metricas.chaves_em_uso()
        cofre_disponivel = True
    except NoSuchToken:
        chaves_do_cofre = None
        chaves_em_uso = None
        cofre_disponivel = False

    return {
        "tempo_no_ar": tempo,
        "total_operacoes": total_ops,
        "operacoes_por_rota": ops_por_rota,
        "total_de_chaves": total_chaves,
        "bytes_em_disco": bytes_disco,
        "chaves_por_tipo": chaves_por_tipo,
        "bytes_em_disco_legivel": bytes_disco_legivel,
        "tempo_no_ar_legivel": tempo_no_ar_legivel,
        "chaves_do_cofre": chaves_do_cofre,
        "limite_chaves": metricas.LIMITE_CHAVES,
        "chaves_em_uso": chaves_em_uso,
        "cofre_disponivel": cofre_disponivel,
    }