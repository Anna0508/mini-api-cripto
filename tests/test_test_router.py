from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_listar_chaves_do_cofre_responde_200():
    resposta = client.get("/cofre/chaves")

    assert resposta.status_code == 200
    assert "chaves" in resposta.json()