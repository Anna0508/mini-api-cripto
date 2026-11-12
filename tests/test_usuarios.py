import json
import stat

import pytest

import usuarios


def test_cria_usuario_e_autentica(ambiente):
    usuarios.criar("anna", "senha-forte-123")

    assert usuarios.autenticar("anna", "senha-forte-123") is True


def test_senha_errada_nao_autentica(ambiente):
    usuarios.criar("anna", "senha-forte-123")

    assert usuarios.autenticar("anna", "senha-errada-123") is False


def test_usuario_inexistente_nao_autentica(ambiente):
    assert usuarios.autenticar("ninguem", "qualquer-senha") is False


def test_senha_nao_fica_guardada_em_texto(ambiente):
    usuarios.criar("anna", "senha-forte-123")

    conteudo = usuarios.caminho().read_text()

    assert "senha-forte-123" not in conteudo
    assert json.loads(conteudo)["anna"]["senha"].startswith("scrypt$")


def test_mesma_senha_gera_hashes_diferentes(ambiente):
    usuarios.criar("anna", "senha-forte-123")
    usuarios.criar("beto", "senha-forte-123")

    dados = json.loads(usuarios.caminho().read_text())

    assert dados["anna"]["senha"] != dados["beto"]["senha"]


def test_usuario_repetido_e_recusado(ambiente):
    usuarios.criar("anna", "senha-forte-123")

    with pytest.raises(usuarios.UsuarioJaExiste):
        usuarios.criar("anna", "outra-senha-123")

    # a senha antiga continua valendo
    assert usuarios.autenticar("anna", "senha-forte-123") is True


@pytest.mark.parametrize("nome", ["", "ab", "a" * 33, "com espaço", "../x", "a/b"])
def test_nome_invalido_e_recusado(ambiente, nome):
    with pytest.raises(ValueError):
        usuarios.criar(nome, "senha-forte-123")


def test_senha_curta_e_recusada(ambiente):
    with pytest.raises(ValueError):
        usuarios.criar("anna", "curta")


def test_arquivo_so_o_dono_le(ambiente):
    usuarios.criar("anna", "senha-forte-123")

    modo = stat.S_IMODE(usuarios.caminho().stat().st_mode)

    assert modo == 0o600


def test_hash_corrompido_nao_autentica_nem_quebra(ambiente):
    assert usuarios.conferir_senha("qualquer", "lixo") is False