import time
from collections import Counter
from pathlib import Path

INICIO = time.time()
PASTA_CHAVES = Path("chaves")
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
    arquivos = [a for a in PASTA_CHAVES.iterdir()
                if a.is_file() and not a.name.startswith(".")]
    return len(arquivos)

def bytes_em_disco():
    total_bytes = sum(a.stat().st_size for a in PASTA_CHAVES.iterdir()
                      if a.is_file() and not a.name.startswith("."))
    return total_bytes
def chaves_por_tipo():
    contagem = {"rsa_privada": 0, "rsa_publica": 0, "aes": 0}

    for a in PASTA_CHAVES.iterdir():
        if not a.is_file() or a.name.startswith("."):
            continue

        if a.name.endswith("_privada.pem"):
            contagem["rsa_privada"] += 1
        elif a.name.endswith("_publica.pem"):
            contagem["rsa_publica"] += 1
        elif a.name.endswith("_aes.bin"):
            contagem["aes"] += 1

    return contagem