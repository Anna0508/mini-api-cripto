import multiprocessing
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient
import cripto
import metricas
import router
from main import app
from schemas import NomeEntrada
client = TestClient(app)

def test_pedidos_simultaneos(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 5)
    def criar_chave(i):
        return client.post("/chaves/rsa", json={"nome": f"teste{i}"})
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(criar_chave, i) for i in range(10)]
        results = [future.result() for future in futures]
    sucesso = sum(1 for r in results if r.status_code == 200)
    falha = sum(1 for r in results if r.status_code == 409)
    assert sucesso == 5
    assert falha == 5


def test_limite_de_chaves(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 3)
    # Cria 3 chaves com sucesso
    for i in range(3):
        response = client.post("/chaves/rsa", json={"nome": f"teste{i}"})
        assert response.status_code == 200

    # Tenta criar uma quarta chave e espera falha
    response = client.post("/chaves/rsa", json={"nome": "teste3"})
    assert response.status_code == 409


def criar_no_processo(pasta, barreira, resultados):
    try:
        cripto.PASTA_CHAVES = Path(pasta)
        metricas.chaves_do_cofre = lambda: {"total": 0, "por_tipo": {}}
        metricas.LIMITE_CHAVES = 1

        original = cripto.gerar_chave_aes

        def lenta(nome):
            time.sleep(0.3)
            original(nome)

        cripto.gerar_chave_aes = lenta

        barreira.wait(timeout=20)
        try:
            router.criar_chave_aes(NomeEntrada(nome=f"chave{os.getpid()}"))
            resultados.put(200)
        except HTTPException as erro:
            resultados.put(erro.status_code)
    except Exception as erro:
        resultados.put(f"erro no processo filho: {erro!r}")


def test_dois_processos_largam_juntos(tmp_path):
    barreira = multiprocessing.Barrier(2)
    resultados = multiprocessing.Queue()
    processos = [
        multiprocessing.Process(
            target=criar_no_processo, args=(str(tmp_path), barreira, resultados)
        )
        for _ in range(2)
    ]
    for p in processos:
        p.start()
    for p in processos:
        p.join(timeout=60)
        if p.is_alive():
            p.terminate()

    codigos = []
    for _ in processos:
        try:
            codigos.append(resultados.get(timeout=5))
        except Exception:
            codigos.append("sem resposta")
    chaves = list(tmp_path.glob("*_aes.bin"))
    assert sorted(map(str, codigos)) == ["200", "409"], codigos
    assert len(chaves) == 1
