import time
from collections import Counter

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
    
