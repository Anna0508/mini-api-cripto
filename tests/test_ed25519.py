import base64

import pytest
from fastapi.testclient import TestClient

import metricas
from main import app

client = TestClient(app)


def criar(nome):
    return client.post("/chaves/ed25519", json={"nome": nome})


def assinar(nome, texto):
    return client.post("/assinar/ed25519", json={"nome": nome, "texto": texto})


def verificar(nome, texto, assinatura):
    return client.post(
        "/verificar/ed25519",
        json={"nome": nome, "texto": texto, "assinatura": assinatura},
    )


def test_assinar_e_verificar(ambiente, limite_alto):
    assert criar("e1").status_code == 200
    assinatura = assinar("e1", "oi").json()["assinatura"]
    assert verificar("e1", "oi", assinatura).json() == {"valida": True}


def test_texto_alterado_reprova(ambiente, limite_alto):
    criar("e2")
    assinatura = assinar("e2", "oi").json()["assinatura"]
    assert verificar("e2", "oy", assinatura).json() == {"valida": False}


def test_assinatura_tem_64_bytes_e_e_deterministica(ambiente, limite_alto):
    criar("e3")
    a = assinar("e3", "oi").json()["assinatura"]
    b = assinar("e3", "oi").json()["assinatura"]
    assert a == b
    assert len(base64.b64decode(a)) == 64


def test_assinatura_de_outra_chave_reprova(ambiente, limite_alto):
    criar("e4")
    criar("e5")
    assinatura = assinar("e4", "oi").json()["assinatura"]
    assert verificar("e5", "oi", assinatura).json() == {"valida": False}


def test_chave_inexistente_da_404(ambiente, limite_alto):
    assert assinar("nao", "oi").status_code == 404
    assert verificar("nao", "oi", "AAAA").status_code == 404


def test_base64_invalido_da_422(ambiente, limite_alto):
    criar("e6")
    assert verificar("e6", "oi", "@@@").status_code == 422


def test_nome_repetido_da_409_e_nao_troca_a_chave(ambiente, limite_alto):
    criar("e7")
    antes = (ambiente / "e7_ed25519_privada.pem").read_bytes()
    assert criar("e7").status_code == 409
    assert (ambiente / "e7_ed25519_privada.pem").read_bytes() == antes


@pytest.mark.parametrize("nome", ["../fora", "a/b", "", "nome com espaco", "x" * 65])
def test_nome_invalido_da_422(ambiente, limite_alto, nome):
    assert criar(nome).status_code == 422


def test_ed25519_respeita_o_limite(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 1)
    assert criar("e8").status_code == 200
    assert criar("e9").status_code == 409


def test_monitoramento_nao_confunde_ed25519_com_rsa(ambiente, limite_alto):
    criar("e10")
    tipos = client.get("/monitoramento").json()["chaves_por_tipo"]
    assert tipos["ed25519"] == 1
    assert tipos["rsa"] == 0


def test_par_ed25519_conta_como_uma_chave_em_uso(ambiente, limite_alto):
    criar("e11")
    assert client.get("/monitoramento").json()["chaves_em_uso"] == 1


def test_log_nao_tem_o_texto(ambiente, limite_alto):
    import auditoria

    criar("e12")
    assinar("e12", "SEGREDO-XYZ")
    log = auditoria.caminho().read_text()
    assert "assinar_ed25519" in log
    assert "SEGREDO-XYZ" not in log


def test_par_pela_metade_da_409_e_nao_cria_arquivo_novo(ambiente, limite_alto):
    criar("e13")
    (ambiente / "e13_ed25519_privada.pem").unlink()
    assert criar("e13").status_code == 409
    assert not (ambiente / "e13_ed25519_privada.pem").exists()
