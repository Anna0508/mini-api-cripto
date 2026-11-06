import hashlib
import json
from trava import TravaDeArquivo
from contextlib import contextmanager
from datetime import datetime, timezone

import cripto

AUTOR = "sistema"
HASH_INICIAL = "0" * 64
TRAVA_AUDITORIA = TravaDeArquivo("auditoria")


def caminho():
    return cripto.PASTA_CHAVES / ".auditoria.jsonl"


def calcular_hash(registro: dict, hash_anterior: str) -> str:
    conteudo = json.dumps(registro, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((hash_anterior + conteudo).encode()).hexdigest()


def ultimo_hash() -> str:
    arquivo = caminho()
    if not arquivo.exists():
        return HASH_INICIAL
    linhas = arquivo.read_text().splitlines()
    if not linhas:
        return HASH_INICIAL
    return json.loads(linhas[-1])["hash"]


def registrar(operacao: str, recurso: str, sucesso: bool, erro: str | None = None):
    with TRAVA_AUDITORIA:
        registro = {
            "quando": datetime.now(timezone.utc).isoformat(),
            "autor": AUTOR,
            "operacao": operacao,
            "recurso": recurso,
            "sucesso": sucesso,
            "erro": erro,
        }
        anterior = ultimo_hash()
        registro["hash_anterior"] = anterior
        registro["hash"] = calcular_hash(
            {k: v for k, v in registro.items() if k != "hash_anterior"}, anterior
        )
        with caminho().open("a") as f:
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")


@contextmanager
def auditar(operacao: str, recurso: str):
    try:
        yield
    except Exception as e:
        registrar(operacao, recurso, False, type(e).__name__)
        raise
    registrar(operacao, recurso, True)


def verificar_cadeia() -> tuple[bool, int | None]:
    arquivo = caminho()
    if not arquivo.exists():
        return True, None
    anterior = HASH_INICIAL
    for numero, linha in enumerate(arquivo.read_text().splitlines(), start=1):
        registro = json.loads(linha)
        esperado = calcular_hash(
            {k: v for k, v in registro.items() if k not in ("hash", "hash_anterior")},
            anterior,
        )
        if registro["hash_anterior"] != anterior or registro["hash"] != esperado:
            return False, numero
        anterior = registro["hash"]
    return True, None
