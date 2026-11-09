import base64
import uuid

import pytest
from fastapi.testclient import TestClient
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import AttributeSensitive

import hsm
import metricas
from main import app

client = TestClient(app)


@pytest.fixture
def label_unico():
    nome = f"teste_{uuid.uuid4().hex[:8]}"
    yield nome

    with hsm.sessao_hsm() as sessao:
        for objeto in sessao.get_objects({Attribute.LABEL: nome}):
            objeto.destroy()


def test_ec_ida_e_volta_pelas_rotas(ambiente, limite_alto, label_unico):
    r = client.post("/cofre/chaves/ec", json={"nome": label_unico})
    assert r.status_code == 200
    assert len(base64.b64decode(r.json()["chave_publica"])) > 0

    assinatura = client.post(
        "/cofre/assinar/ec", json={"nome": label_unico, "texto": "oi"}
    ).json()["assinatura"]
    assert len(base64.b64decode(assinatura)) == 64

    ok = client.post(
        "/cofre/verificar/ec",
        json={"nome": label_unico, "texto": "oi", "assinatura": assinatura},
    )
    assert ok.json() == {"valida": True}

    alterado = client.post(
        "/cofre/verificar/ec",
        json={"nome": label_unico, "texto": "oy", "assinatura": assinatura},
    )
    assert alterado.json() == {"valida": False}


def test_assinar_com_chave_inexistente_da_404(ambiente, limite_alto, label_unico):
    r = client.post("/cofre/assinar/ec", json={"nome": label_unico, "texto": "x"})
    assert r.status_code == 404


def test_verificar_com_chave_inexistente_da_404(ambiente, limite_alto, label_unico):
    sig = base64.b64encode(b"0" * 64).decode()
    r = client.post(
        "/cofre/verificar/ec",
        json={"nome": label_unico, "texto": "x", "assinatura": sig},
    )
    assert r.status_code == 404


def test_base64_invalido_da_422(ambiente, limite_alto, label_unico):
    r = client.post(
        "/cofre/verificar/ec",
        json={"nome": label_unico, "texto": "x", "assinatura": "@@@"},
    )
    assert r.status_code == 422


def test_nome_repetido_da_409(ambiente, limite_alto, label_unico):
    assert client.post("/cofre/chaves/ec", json={"nome": label_unico}).status_code == 200
    assert client.post("/cofre/chaves/ec", json={"nome": label_unico}).status_code == 409


@pytest.mark.parametrize("nome", ["../fora", "a/b", "", "nome com espaco", "x" * 65])
def test_nome_invalido_da_422(ambiente, limite_alto, nome):
    assert client.post("/cofre/chaves/ec", json={"nome": nome}).status_code == 422


def test_ec_respeita_o_limite(ambiente, monkeypatch, label_unico):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 0)
    assert client.post("/cofre/chaves/ec", json={"nome": label_unico}).status_code == 409


def test_privada_nao_pode_ser_lida_nem_exportada(label_unico):
    hsm.gerar_par_ec_no_cofre(label_unico)

    with hsm.sessao_hsm() as sessao:
        privada = sessao.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.EC,
            label=label_unico,
        )
        with pytest.raises(AttributeSensitive):
            privada[Attribute.VALUE]
        assert privada[Attribute.EXTRACTABLE] is False


def test_assinatura_de_outra_chave_reprova(label_unico):
    outro = label_unico + "_b"
    try:
        hsm.gerar_par_ec_no_cofre(label_unico)
        hsm.gerar_par_ec_no_cofre(outro)
        assinatura_de_a = hsm.assinar_ec_no_cofre(label_unico, "oi")

        assert hsm.verificar_ec_no_cofre(outro, "oi", assinatura_de_a) is False
    finally:
        with hsm.sessao_hsm() as sessao:
            for objeto in sessao.get_objects({Attribute.LABEL: outro}):
                objeto.destroy()


def test_rsa_e_ec_com_o_mesmo_label_nao_se_misturam(label_unico):
    hsm.gerar_par_no_cofre(label_unico)
    hsm.gerar_par_ec_no_cofre(label_unico)

    sig_rsa = hsm.assinar_no_cofre(label_unico, "oi")
    sig_ec = hsm.assinar_ec_no_cofre(label_unico, "oi")

    assert len(sig_rsa) == 256
    assert len(sig_ec) == 64
    assert hsm.verificar_no_cofre(label_unico, "oi", sig_rsa) is True
    assert hsm.verificar_ec_no_cofre(label_unico, "oi", sig_ec) is True


def test_listar_chaves_mostra_ec_com_o_tipo_certo(label_unico):
    hsm.gerar_par_ec_no_cofre(label_unico)

    tipos = {c["tipo"] for c in hsm.listar_chaves() if c["label"] == label_unico}

    assert tipos == {"EC privada", "EC pública"}


def test_par_ec_do_cofre_conta_como_uma_chave_em_uso(ambiente, monkeypatch):
    monkeypatch.setattr(
        metricas,
        "chaves_do_cofre",
        lambda: {
            "total": 5,
            "por_tipo": {
                "EC privada": 1,
                "EC pública": 1,
                "RSA privada": 1,
                "RSA pública": 1,
                "AES": 1,
            },
        },
    )

    assert metricas.chaves_em_uso() == 3


def test_log_nao_tem_o_texto(ambiente, limite_alto, label_unico):
    import auditoria

    client.post("/cofre/chaves/ec", json={"nome": label_unico})
    client.post("/cofre/assinar/ec", json={"nome": label_unico, "texto": "SEGREDO-XYZ"})
    log = auditoria.caminho().read_text()
    assert "cofre_assinar_ec" in log
    assert "SEGREDO-XYZ" not in log