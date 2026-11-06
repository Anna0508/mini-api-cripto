import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

import metricas
from main import app

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
