from datetime import datetime, timedelta, timezone

import jwt

import token_jwt


def _token_manual(segredo=None, algoritmo="HS256", **campos):
    agora = datetime.now(timezone.utc)
    dados = {"sub": "anna", "exp": agora + timedelta(minutes=5)}
    dados.update(campos)
    dados = {k: v for k, v in dados.items() if v is not None}
    return jwt.encode(dados, segredo or token_jwt.SEGREDO, algorithm=algoritmo)


def test_token_criado_e_verificado():
    token = token_jwt.criar_token("anna")

    assert token_jwt.verificar_token(token) == "anna"


def test_token_vencido_e_recusado(monkeypatch):
    monkeypatch.setattr(token_jwt, "VALIDADE_MINUTOS", -1)
    token = token_jwt.criar_token("anna")

    assert token_jwt.verificar_token(token) is None


def test_token_assinado_com_outro_segredo_e_recusado():
    token = _token_manual(segredo="x" * 40)

    assert token_jwt.verificar_token(token) is None


def test_token_adulterado_e_recusado():
    token = token_jwt.criar_token("anna")
    cabecalho, corpo, assinatura = token.split(".")
    outro = token_jwt.criar_token("beto").split(".")[1]

    assert token_jwt.verificar_token(f"{cabecalho}.{outro}.{assinatura}") is None
    assert corpo != outro


def test_token_sem_assinatura_algoritmo_none_e_recusado():
    sem_assinatura = jwt.encode(
        {"sub": "anna", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        key=None,
        algorithm="none",
    )

    assert token_jwt.verificar_token(sem_assinatura) is None


def test_token_sem_validade_e_recusado():
    token = jwt.encode({"sub": "anna"}, token_jwt.SEGREDO, algorithm="HS256")

    assert token_jwt.verificar_token(token) is None


def test_token_sem_usuario_e_recusado():
    token = _token_manual(sub=None)

    assert token_jwt.verificar_token(token) is None


def test_token_com_outro_algoritmo_e_recusado():
    token = _token_manual(algoritmo="HS512")

    assert token_jwt.verificar_token(token) is None


def test_lixo_e_recusado():
    for lixo in ["", "abc", "a.b.c", "Bearer xyz"]:
        assert token_jwt.verificar_token(lixo) is None