import pytest
import cripto
from cryptography.exceptions import InvalidTag

def test_cifrar_mesmo_texto_duas_vezes_da_resultado_diferente(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_chave_aes("teste")

    iv1, cifrado1 = cripto.cifrar("teste", "mensagem_secreta")
    iv2, cifrado2 = cripto.cifrar("teste", "mensagem_secreta")
    assert iv1 != iv2
    assert cifrado1 != cifrado2

def test_decifrar_com_iv_errado_falha(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_chave_aes("teste")

    iv1, cifrado1 = cripto.cifrar("teste", "mensagem_secreta")
    iv2, cifrado2 = cripto.cifrar("teste", "mensagem_secreta")

    with pytest.raises(InvalidTag):
        cripto.decifrar("teste", iv1, cifrado2)
        cripto.decifrar("teste", iv2, cifrado1)


def test_cifrar_decifrar_devolve_texto_original(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_chave_aes("teste")

    iv, cifrado = cripto.cifrar("teste", "mensagem_secreta")
    texto = cripto.decifrar("teste", iv, cifrado)
    assert texto == "mensagem_secreta"

def test_texto_alterado_em_uma_letra_reprova_na_verificacao(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_chave_aes("teste")

    iv, cifrado = cripto.cifrar("teste", "mensagem_secreta")


    # Alterar um caractere da mensagem cifrada
    cifrado_alterado = bytearray(cifrado)
    cifrado_alterado[0] ^= 0x01 # Inverte o primeiro bit do primeiro byte       
    with pytest.raises(InvalidTag):
        cripto.decifrar("teste", iv, bytes(cifrado_alterado))

def test_assinar_e_verificar_o_mesmo_texto_devolve_verdadeiro(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_par_de_chaves("teste")

    assinatura = cripto.assinar("teste", "mensagem_secreta")
    assert cripto.verificar("teste", "mensagem_secreta", assinatura) is True


def test_gerar_par_de_chaves_cria_os_dois_arquivos(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)

    cripto.gerar_par_de_chaves("teste")

    assert(tmp_path.joinpath("teste_privada.pem").exists())
    assert(tmp_path.joinpath("teste_publica.pem").exists())

    