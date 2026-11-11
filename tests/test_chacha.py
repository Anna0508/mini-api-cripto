import pytest
from fastapi.testclient import TestClient

import metricas
from main import app

client = TestClient(app)


def criar(nome):
    return client.post("/chaves/chacha", json={"nome": nome})


def test_chacha_ida_e_volta(ambiente, limite_alto):
    assert criar("c1").status_code == 200
    r = client.post("/cifrar/chacha", json={"nome": "c1", "texto": "olá mundo"})
    assert r.status_code == 200
    corpo = r.json()
    r2 = client.post(
        "/decifrar/chacha",
        json={"nome": "c1", "iv": corpo["iv"], "cifrado": corpo["cifrado"]},
    )
    assert r2.status_code == 200
    assert r2.json()["texto"] == "olá mundo"


def test_cifrar_duas_vezes_da_resultados_diferentes(ambiente, limite_alto):
    criar("c2")
    a = client.post("/cifrar/chacha", json={"nome": "c2", "texto": "igual"}).json()
    b = client.post("/cifrar/chacha", json={"nome": "c2", "texto": "igual"}).json()
    assert a["iv"] != b["iv"]
    assert a["cifrado"] != b["cifrado"]


def test_chave_inexistente_da_404(ambiente, limite_alto):
    r = client.post("/cifrar/chacha", json={"nome": "nao", "texto": "x"})
    assert r.status_code == 404
    r = client.post(
        "/decifrar/chacha", json={"nome": "nao", "iv": "AAAAAAAAAAAAAAAA", "cifrado": "AAAA"}
    )
    assert r.status_code == 404


def test_iv_trocado_da_400(ambiente, limite_alto):
    criar("c3")
    a = client.post("/cifrar/chacha", json={"nome": "c3", "texto": "um"}).json()
    b = client.post("/cifrar/chacha", json={"nome": "c3", "texto": "dois"}).json()
    r = client.post(
        "/decifrar/chacha",
        json={"nome": "c3", "iv": a["iv"], "cifrado": b["cifrado"]},
    )
    assert r.status_code == 400


def test_base64_invalido_da_422(ambiente, limite_alto):
    criar("c4")
    r = client.post(
        "/decifrar/chacha", json={"nome": "c4", "iv": "@@@", "cifrado": "AAAA"}
    )
    assert r.status_code == 422


def test_nome_repetido_da_409_e_nao_troca_a_chave(ambiente, limite_alto):
    criar("c5")
    antes = (ambiente / "c5_chacha.bin").read_bytes()
    assert criar("c5").status_code == 409
    assert (ambiente / "c5_chacha.bin").read_bytes() == antes


@pytest.mark.parametrize("nome", ["../fora", "a/b", "", "nome com espaco", "x" * 65])
def test_nome_invalido_da_422(ambiente, limite_alto, nome):
    assert criar(nome).status_code == 422


def test_chacha_respeita_o_limite(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 1)
    assert criar("c6").status_code == 200
    assert criar("c7").status_code == 409


def test_monitoramento_conta_chacha(ambiente, limite_alto):
    criar("c8")
    r = client.get("/monitoramento")
    assert r.json()["chaves_por_tipo"]["chacha"] == 1
    assert r.json()["chaves_em_uso"] == 1


def test_operacoes_ficam_no_log_sem_o_texto(ambiente, limite_alto):
    import auditoria

    criar("c9")
    client.post("/cifrar/chacha", json={"nome": "c9", "texto": "SEGREDO-XYZ"})
    log = auditoria.caminho().read_text()
    assert "criar_chave_chacha" in log
    assert "cifrar_chacha" in log
    assert "SEGREDO-XYZ" not in log
