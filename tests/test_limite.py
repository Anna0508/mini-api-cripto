import pytest
from fastapi.testclient import TestClient

import hsm
import metricas
from main import app

client = TestClient(app)


def preencher(pasta, rsa=0, aes=0):
    for i in range(rsa):
        (pasta / f"fake{i}_privada.pem").write_text("x")
    for i in range(aes):
        (pasta / f"fake{i}_aes.bin").write_text("x")

def definir_limite(monkeypatch, valor):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", valor)

def nomes_na_pasta(pasta):
    return sorted(p.name for p in pasta.iterdir())

def test_abaixo_do_limite(ambiente, monkeypatch):
    definir_limite(monkeypatch, 3)
    preencher(ambiente, rsa=1, aes=1)
    assert metricas.chaves_em_uso() == 2
    assert metricas.limite_atingido() is False

def test_no_limite(ambiente, monkeypatch):
    definir_limite(monkeypatch, 3)
    preencher(ambiente, rsa=2, aes=1)
    assert metricas.chaves_em_uso() == 3
    assert metricas.limite_atingido() is True

def test_acima_do_limite(ambiente, monkeypatch):
    definir_limite(monkeypatch, 3)
    preencher(ambiente, rsa=3, aes=2)
    assert metricas.chaves_em_uso() == 5

def test_rota_barra_no_limite_com_409(ambiente, monkeypatch):
    definir_limite(monkeypatch, 2)
    preencher(ambiente, rsa=1, aes=1)          
    r = client.post("/chaves/rsa", json={"nome": "novo"})
    assert r.status_code == 409
    corpo = r.json()["detail"]                 
    assert corpo["limite"] == 2
    assert corpo["em_uso"] == 2
    assert "mensagem" in corpo


def test_rota_abaixo_do_limite_cria(ambiente, monkeypatch):
    definir_limite(monkeypatch, 5)
    r = client.post("/chaves/aes", json={"nome": "novo"})
    assert r.status_code == 200
    assert (ambiente / "novo_aes.bin").exists()  


def test_limite_ja_ultrapassado_nao_apaga_nada(ambiente, monkeypatch):
    definir_limite(monkeypatch, 2)
    preencher(ambiente, rsa=3, aes=2)          
    antes = nomes_na_pasta(ambiente)
    r = client.post("/chaves/aes", json={"nome": "novo"})
    assert r.status_code == 409
    assert nomes_na_pasta(ambiente) == antes


@pytest.mark.parametrize(
    "rota",
    ["/chaves/rsa", "/chaves/aes", "/cofre/chaves/rsa", "/cofre/chaves/aes"],
)
def test_toda_rota_de_criacao_barra_no_limite(ambiente, monkeypatch, rota):
    definir_limite(monkeypatch, 2)
    preencher(ambiente, rsa=1, aes=1)        
    def nao_deveria_chamar(*args, **kwargs):
        raise AssertionError("criou chave mesmo acima do limite")

    monkeypatch.setattr(hsm, "gerar_par_no_cofre", nao_deveria_chamar)
    monkeypatch.setattr(hsm, "gerar_chave_aes_no_cofre", nao_deveria_chamar)

    antes = nomes_na_pasta(ambiente)
    r = client.post(rota, json={"nome": "novo"})

    assert r.status_code == 409
    assert nomes_na_pasta(ambiente) == antes




def test_monitoramento_expoe_limite_e_uso(ambiente, monkeypatch):
    definir_limite(monkeypatch, 4)
    preencher(ambiente, rsa=1, aes=1)         
    r = client.get("/monitoramento")
    assert r.status_code == 200
    assert r.json()["limite_chaves"] == 4
    assert r.json()["chaves_em_uso"] == 2


def test_monitoramento_com_uso_acima_do_limite(ambiente, monkeypatch):
    definir_limite(monkeypatch, 2)
    preencher(ambiente, rsa=3, aes=2)         
    r = client.get("/monitoramento")
    assert r.status_code == 200               
    assert r.json()["chaves_em_uso"] == 5
    assert r.json()["limite_chaves"] == 2