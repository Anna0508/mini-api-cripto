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