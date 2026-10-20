import time
import uuid

from fastapi.testclient import TestClient

import metricas
from main import app

client = TestClient(app)
TOKENDIR = "/var/lib/softhsm/tokens"

def test_monitoramento_responde_200():
    resposta = client.get("/monitoramento")

    assert resposta.status_code == 200
    assert "tempo_no_ar" in resposta.json()
    assert "total_operacoes" in resposta.json()
    assert "operacoes_por_rota" in resposta.json()
    assert "total_de_chaves" in resposta.json()
    assert "bytes_em_disco" in resposta.json()

def test_monitoramento_conta_operacoes():
    # Faz algumas requisições para gerar operações
    client.get("/saude")
    client.get("/saude")
    client.get("/cofre/status")

    resposta = client.get("/monitoramento")
    dados = resposta.json()

    assert dados["total_operacoes"] >= 3
    assert "/saude" in dados["operacoes_por_rota"]
    assert "/cofre/status" in dados["operacoes_por_rota"]

def test_monitoramento_tipos_corretos():
    resposta = client.get("/monitoramento")
    dados = resposta.json()

    assert isinstance(dados["tempo_no_ar"], float)
    assert isinstance(dados["total_operacoes"], int)
    assert isinstance(dados["operacoes_por_rota"], dict)
    assert isinstance(dados["total_de_chaves"], int)
    assert isinstance(dados["bytes_em_disco"], int)   

def test_monitoramento_tempo_no_ar_cresce():
    resposta1 = client.get("/monitoramento")
    tempo1 = resposta1.json()["tempo_no_ar"]

    # Aguarda um pouco antes de fazer a próxima requisição
    time.sleep(1)

    resposta2 = client.get("/monitoramento")
    tempo2 = resposta2.json()["tempo_no_ar"]

    assert tempo2 > tempo1


def test_monitoramento_valores_batem_com_metricas():
    resposta = client.get("/monitoramento")
    dados = resposta.json()

    assert dados["total_de_chaves"] == metricas.total_de_chaves()
    assert dados["bytes_em_disco"] == metricas.bytes_em_disco()


def test_gerar_chave_rsa_aumenta_total_de_chaves():
    nome = f"chave_teste_{uuid.uuid4().hex[:8]}"
    INCREMENTO_PAR_RSA = 2

    total_antes = metricas.total_de_chaves()

    resp = client.post("/chaves/rsa", json={"nome": nome})
    assert resp.status_code == 200, resp.text

    assert metricas.total_de_chaves() == total_antes + INCREMENTO_PAR_RSA


def test_gerar_chave_rsa_aumenta_bytes_em_disco():
    nome = f"chave_teste_{uuid.uuid4().hex[:8]}"

    bytes_antes = metricas.bytes_em_disco()

    resp = client.post("/chaves/rsa", json={"nome": nome})
    assert resp.status_code == 200, resp.text

    assert metricas.bytes_em_disco() > bytes_antes

def test_gerar_chave_rsa_no_cofre_aumenta_bytes_do_token():
    nome = f"chave_teste_{uuid.uuid4().hex[:8]}"

    antes = metricas.bytes_do_token(TOKENDIR)

    resp = client.post("/cofre/chaves/rsa", json={"nome": nome})
    assert resp.status_code == 200, resp.text

    depois = metricas.bytes_do_token(TOKENDIR)
    print(f"par RSA no cofre ocupou {depois - antes} bytes")   # rode com -s

    assert depois > antes

def test_gerar_chave_rsa_em_arquivo_bytes_do_par():
    nome = f"chave_teste_{uuid.uuid4().hex[:8]}"

    antes = metricas.bytes_em_disco()
    resp = client.post("/chaves/rsa", json={"nome":nome})
    assert resp.status_code == 200, resp.text
    depois = metricas.bytes_em_disco()

    print(f"par RSA em arquivo ocupou {depois - antes} bytes")

    assert depois > antes