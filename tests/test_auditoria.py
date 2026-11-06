import json

from fastapi.testclient import TestClient

import auditoria
import metricas
from main import app

client = TestClient(app)


def ler_registros():
    return [
        json.loads(linha)
        for linha in auditoria.caminho().read_text().splitlines()
    ]


def test_registra_sucesso(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k1"})
    r = ler_registros()[0]
    assert r["operacao"] == "criar_chave_aes"
    assert r["recurso"] == "k1"
    assert r["sucesso"] is True
    assert r["autor"] == "sistema"


def test_registra_falha(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 0)
    resp = client.post("/chaves/aes", json={"nome": "k0"})
    assert resp.status_code == 409
    r = ler_registros()[0]
    assert r["sucesso"] is False
    assert r["erro"] == "HTTPException"


def test_nao_grava_texto_nem_chave(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k2"})
    client.post("/cifrar", json={"nome": "k2", "texto": "TEXTO-SECRETO-123"})
    conteudo = auditoria.caminho().read_text()
    assert "TEXTO-SECRETO-123" not in conteudo


def test_cadeia_integra(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k3"})
    client.post("/cifrar", json={"nome": "k3", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k3", "texto": "oi"})
    assert auditoria.verificar_cadeia() == (True, None)


def test_detecta_registro_alterado(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k4"})
    client.post("/cifrar", json={"nome": "k4", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k4", "texto": "oi"})
    linhas = auditoria.caminho().read_text().splitlines()
    registro = json.loads(linhas[1])
    registro["recurso"] = "outra"
    linhas[1] = json.dumps(registro)
    auditoria.caminho().write_text("\n".join(linhas) + "\n")
    assert auditoria.verificar_cadeia() == (False, 2)


def test_detecta_registro_removido(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k5"})
    client.post("/cifrar", json={"nome": "k5", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k5", "texto": "oi"})
    linhas = auditoria.caminho().read_text().splitlines()
    del linhas[1]
    auditoria.caminho().write_text("\n".join(linhas) + "\n")
    assert auditoria.verificar_cadeia()[0] is False