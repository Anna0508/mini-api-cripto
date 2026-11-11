import base64
import binascii
from datetime import date

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pkcs11.exceptions import NoSuchKey, NoSuchToken

import alertas
import auditoria
import cripto
import hsm
import metricas
import schemas
from schemas import (
    AssinarEntrada,
    AssinarSeguroEntrada,
    CifrarEntrada,
    CifrarSeguroEntrada,
    DecifrarEntrada,
    DecifrarSeguroEntrada,
    NomeEntrada,
    NomeSeguroEntrada,
    VerificarEntrada,
    VerificarSeguroEntrada,
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


def _decodificar_base64(valor: str, campo: str) -> bytes:
    try:
        return base64.b64decode(valor, validate=True)
    except binascii.Error:
        raise HTTPException(
            status_code=422, detail=f"O campo '{campo}' não é base64 válido."
        ) from None


def _chave_nao_encontrada(nome: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Chave '{nome}' não encontrada.")


def _chave_ja_existe(nome: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail=f"Já existe uma chave com o nome '{nome}'. Escolha outro nome.",
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
            alertas.verificar()
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
            alertas.verificar()
    return {"mensagem": "chave AES criada"}

@router.post("/cifrar")
def cifrar_texto(dados: CifrarEntrada):
    with auditoria.auditar("cifrar", dados.nome):
        iv, cifrado = cripto.cifrar(dados.nome, dados.texto)
    return {
        "iv": base64.b64encode(iv).decode(),
        "cifrado": base64.b64encode(cifrado).decode()
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
            alertas.verificar()
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
            alertas.verificar()
    return {"mensagem": "chaves AES criadas no cofre"}

@router.post("/cofre/cifrar")
def cifrar_texto_no_cofre(dados: CifrarEntrada):
    with auditoria.auditar("cofre_cifrar", dados.nome):
        iv, cifrado = hsm.cifrar_no_cofre(dados.nome, dados.texto)
    return {
        "iv": base64.b64encode(iv).decode(),
        "cifrado": base64.b64encode(cifrado).decode()
    }

@router.post("/cofre/decifrar")
def decifrar_texto_no_cofre(dados: DecifrarEntrada):
    iv = base64.b64decode(dados.iv)
    cifrado = base64.b64decode(dados.cifrado)
    with auditoria.auditar("cofre_decifrar", dados.nome):
        texto = hsm.decifrar_no_cofre(dados.nome, iv, cifrado)
    return {"texto": texto}

@router.post("/chaves/chacha")
def criar_chave_chacha(dados: NomeSeguroEntrada):
    with auditoria.auditar("criar_chave_chacha", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            try:
                cripto.gerar_chave_chacha(dados.nome)
            except FileExistsError:
                raise _chave_ja_existe(dados.nome) from None
            alertas.verificar()
    return {"mensagem": "chave ChaCha20-Poly1305 criada"}


@router.post("/cifrar/chacha")
def cifrar_texto_chacha(dados: CifrarSeguroEntrada):
    with auditoria.auditar("cifrar_chacha", dados.nome):
        try:
            nonce, cifrado = cripto.cifrar_chacha(dados.nome, dados.texto)
        except FileNotFoundError:
            raise _chave_nao_encontrada(dados.nome) from None
    return {
        "iv": base64.b64encode(nonce).decode(),
        "cifrado": base64.b64encode(cifrado).decode(),
    }


@router.post("/decifrar/chacha")
def decifrar_texto_chacha(dados: DecifrarSeguroEntrada):
    nonce = _decodificar_base64(dados.iv, "iv")
    cifrado = _decodificar_base64(dados.cifrado, "cifrado")
    with auditoria.auditar("decifrar_chacha", dados.nome):
        try:
            texto = cripto.decifrar_chacha(dados.nome, nonce, cifrado)
        except FileNotFoundError:
            raise _chave_nao_encontrada(dados.nome) from None
        except (InvalidTag, ValueError):
            raise HTTPException(
                status_code=400,
                detail="Não foi possível decifrar: nonce, texto cifrado ou chave não conferem.",
            ) from None
    return {"texto": texto}


@router.post("/chaves/ed25519")
def criar_chave_ed25519(dados: NomeSeguroEntrada):
    with auditoria.auditar("criar_chave_ed25519", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            try:
                publica = cripto.gerar_par_ed25519(dados.nome)
            except FileExistsError:
                raise _chave_ja_existe(dados.nome) from None
            alertas.verificar()
    return {"chave_publica": publica}


@router.post("/assinar/ed25519")
def assinar_texto_ed25519(dados: AssinarSeguroEntrada):
    with auditoria.auditar("assinar_ed25519", dados.nome):
        try:
            assinatura = cripto.assinar_ed25519(dados.nome, dados.texto)
        except FileNotFoundError:
            raise _chave_nao_encontrada(dados.nome) from None
    return {"assinatura": base64.b64encode(assinatura).decode()}


@router.post("/verificar/ed25519")
def verificar_assinatura_ed25519(dados: VerificarSeguroEntrada):
    assinatura = _decodificar_base64(dados.assinatura, "assinatura")
    with auditoria.auditar("verificar_ed25519", dados.nome):
        try:
            valida = cripto.verificar_ed25519(dados.nome, dados.texto, assinatura)
        except FileNotFoundError:
            raise _chave_nao_encontrada(dados.nome) from None
    return {"valida": valida}


@router.post("/cofre/chaves/ec")
def criar_chave_ec_no_cofre(dados: NomeSeguroEntrada):
    with auditoria.auditar("cofre_criar_chave_ec", dados.nome):
        with TRAVA_CRIACAO:
            verificar_limite()
            try:
                publica = hsm.gerar_par_ec_no_cofre(dados.nome)
            except hsm.ChaveJaExiste:
                raise _chave_ja_existe(dados.nome) from None
            alertas.verificar()
    return {"chave_publica": base64.b64encode(publica).decode()}


@router.post("/cofre/assinar/ec")
def assinar_texto_ec_no_cofre(dados: AssinarSeguroEntrada):
    with auditoria.auditar("cofre_assinar_ec", dados.nome):
        try:
            assinatura = hsm.assinar_ec_no_cofre(dados.nome, dados.texto)
        except NoSuchKey:
            raise _chave_nao_encontrada(dados.nome) from None
    return {"assinatura": base64.b64encode(assinatura).decode()}


@router.post("/cofre/verificar/ec")
def verificar_assinatura_ec_no_cofre(dados: VerificarSeguroEntrada):
    assinatura = _decodificar_base64(dados.assinatura, "assinatura")
    with auditoria.auditar("cofre_verificar_ec", dados.nome):
        try:
            valida = hsm.verificar_ec_no_cofre(dados.nome, dados.texto, assinatura)
        except NoSuchKey:
            raise _chave_nao_encontrada(dados.nome) from None
    return {"valida": valida}


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

@router.get("/auditoria/exportar")
def exportar_auditoria(
    de: date | None = None, ate: date | None = None, operacao: str | None = None
):
    if de and ate and de > ate:
        raise HTTPException(status_code=422, detail="'de' não pode ser depois de 'ate'")
    nome = f"auditoria_{de or 'inicio'}_{ate or 'fim'}.csv"
    return StreamingResponse(
        auditoria.exportar_csv(de, ate, operacao),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nome}"'},
    )