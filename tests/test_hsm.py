import uuid
import pytest
import hsm 
from pkcs11 import Attribute, ObjectClass, Mechanism
from pkcs11.exceptions import AttributeSensitive

@pytest.fixture
def label_unico():
    nome = f"teste_{uuid.uuid4().hex[:8]}"
    yield nome

    with hsm.sessao_hsm() as sessao:
        for objeto in sessao.get_objects({Attribute.LABEL: nome}):
            objeto.destroy()

def test_listar_chaves_devolve_as_que_foram_criadas(label_unico):
    hsm.gerar_par_no_cofre(label_unico)
    hsm.gerar_chave_aes_no_cofre(label_unico)

    chaves = hsm.listar_chaves()
    tipos = {chave["tipo"] for chave in chaves if chave["label"] == label_unico}
    assert tipos == {"RSA privada", "RSA pública", "AES"}

def test_listar_nao_mostra_chave_que_nao_existe(label_unico):
    chaves = hsm.listar_chaves()
    assert not any(c["label"] == label_unico for c in chaves)

def test_cifrar_decifrar_devolve_texto_original(label_unico):
    hsm.gerar_chave_aes_no_cofre(label_unico)

    iv,cifrado = hsm.cifrar_no_cofre(label_unico, "mensagem_secreta")
    texto = hsm.decifrar_no_cofre(label_unico, iv, cifrado)
    assert texto == "mensagem_secreta"

def test_texto_alterado_reprova_na_verificacao(label_unico):
    hsm.gerar_chave_aes_no_cofre(label_unico)

    iv,cifrado = hsm.cifrar_no_cofre(label_unico, "mensagem_secreta")

    # Alterar um caractere da mensagem cifrada
    cifrado_alterado = bytearray(cifrado)
    cifrado_alterado[0] ^= 0x01 # Inverte o primeiro bit do primeiro byte       
    with pytest.raises(Exception):
        hsm.decifrar_no_cofre(label_unico, iv, bytes(cifrado_alterado))

def test_assinar_e_verificar_pelo_cofre_funciona(label_unico):
    hsm.gerar_par_no_cofre(label_unico)

    assinatura = hsm.assinar_no_cofre(label_unico, "mensagem_secreta")
    assert hsm.verificar_no_cofre(label_unico, "mensagem_secreta", assinatura) is True

def test_a_chave_privada_nao_pode_ser_lida_nem_exportada(label_unico):
    hsm.gerar_par_no_cofre(label_unico)

    with hsm.sessao_hsm() as sessao:
        privada = sessao.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label=label_unico,
        )
        with pytest.raises(AttributeSensitive):
            privada[Attribute.PRIVATE_EXPONENT]

        assert privada[Attribute.EXTRACTABLE] is False


def test_gerar_chave_no_cofre_devolve_a_publica(label_unico):
    publica = hsm.gerar_par_no_cofre(label_unico)

    assert isinstance(publica, bytes)
    assert len(publica) == 256
    
def test_sessao_hsm_abre_o_token_certo():
    with hsm.sessao_hsm() as sessao:
        assert sessao.token.label == "cofre-treino"