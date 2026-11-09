import os
import time
from collections import Counter
from pathlib import Path

import cripto
import hsm

LIMITE_CHAVES = int(os.getenv("LIMITE_CHAVES", "50"))
INICIO = time.time()
total_operacoes = 0
operacoes_por_rota = Counter()

def tempo_no_ar() -> float:

    return time.time() - INICIO 


def formatar_tempo(tempo: float) -> str:

    horas = int(tempo // 3600)
    minutos = int((tempo % 3600) // 60)
    segundos = int(tempo % 60)

    return f"{horas:02d}:{minutos:02d}:{segundos:02d}"

def registrar_operacao(rota: str) -> None:

    global total_operacoes
    total_operacoes += 1
    operacoes_por_rota[rota] += 1

    return total_operacoes, operacoes_por_rota


def total_de_chaves():
    arquivos = [a for a in cripto.PASTA_CHAVES.iterdir()
                if a.is_file() and not a.name.startswith(".")]
    return len(arquivos)

def bytes_em_disco():
    total_bytes = sum(a.stat().st_size for a in cripto.PASTA_CHAVES.iterdir()
                      if a.is_file() and not a.name.startswith("."))
    return total_bytes
def chaves_por_tipo():
    contagem = {"rsa": 0, "aes": 0, "chacha": 0, "ed25519": 0}

    for a in cripto.PASTA_CHAVES.iterdir():
        if not a.is_file() or a.name.startswith("."):
            continue

        if a.name.endswith("_ed25519_privada.pem"):
            contagem["ed25519"] += 1
        elif a.name.endswith("_privada.pem"):
            contagem["rsa"] += 1
        elif a.name.endswith("_aes.bin"):
            contagem["aes"] += 1
        elif a.name.endswith("_chacha.bin"):
            contagem["chacha"] += 1

    return contagem

    for a in cripto.PASTA_CHAVES.iterdir():
        if not a.is_file() or a.name.startswith("."):
            continue

        if a.name.endswith("_privada.pem"):
            contagem["rsa"] += 1
        elif a.name.endswith("_aes.bin"):
            contagem["aes"] += 1
        elif a.name.endswith("_chacha.bin"):
            contagem["chacha"] += 1

    return contagem


def formatar_bytes(tamanho: int) -> str:
    if tamanho < 1024:
        return f"{tamanho} B"
    elif tamanho < 1024 ** 2:
        return f"{tamanho / 1024:.2f} KB"
    elif tamanho < 1024 ** 3:
        return f"{tamanho / (1024 ** 2):.2f} MB"
    else:
        return f"{tamanho / (1024 ** 3):.2f} GB"
def chaves_do_cofre():
    lista = hsm.listar_chaves()
    return {
        "total": len(lista),
        "por_tipo": dict(Counter(c["tipo"] for c in lista)),
    }

def bytes_do_token(tokendir: str) -> int:
    return sum(a.stat().st_size for a in Path(tokendir).rglob("*") if a.is_file()) 

def chaves_em_uso() -> int:
    cofre = chaves_do_cofre()
    publicas = sum(
        n for tipo, n in cofre["por_tipo"].items() if tipo.endswith("pública")
    )
    uso_cofre = cofre["total"] - publicas
    uso_local = chaves_locais_logicas()
    return uso_cofre + uso_local

def limite_atingido() -> bool:

    return chaves_em_uso() >= LIMITE_CHAVES

def chaves_locais_logicas() -> int:
    return sum(chaves_por_tipo().values())