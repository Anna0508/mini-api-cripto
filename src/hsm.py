import os
from contextlib import contextmanager

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import GCMParams

CAMINHO_BIBLIOTECA = "/usr/lib/softhsm/libsofthsm2.so"
LABEL_TOKEN = "cofre-treino"
PIN = os.getenv("HSM_PIN")


@contextmanager
def sessao_hsm():

    lib = pkcs11.lib(CAMINHO_BIBLIOTECA)
    token = lib.get_token(token_label=LABEL_TOKEN)

    sessao = token.open(user_pin=PIN, rw=True)
    try:
        yield sessao
    finally:
        sessao.close()



def gerar_par_no_cofre(label: str) -> bytes:
  
    with sessao_hsm() as sessao:
        publica, _privada = sessao.generate_keypair(
            KeyType.RSA,
            2048,
            store=True,          
            label=label,
            private_template={
                Attribute.TOKEN: True,
                Attribute.PRIVATE: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SIGN: True,
                Attribute.LABEL: label,
            },
            public_template={
                Attribute.TOKEN: True,
                Attribute.VERIFY: True,
                Attribute.LABEL: label,
            },
        )
        return bytes(publica[Attribute.MODULUS])


def assinar_no_cofre(label: str, texto: str) -> bytes:
    with sessao_hsm() as sessao:
        privada = sessao.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label=label,
        )
        return privada.sign(texto.encode(), mechanism=Mechanism.SHA256_RSA_PKCS)


def verificar_no_cofre(label: str, texto: str, assinatura: bytes) -> bool:
    with sessao_hsm() as sessao:
        publica = sessao.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            label=label,
        )
        return publica.verify(
            texto.encode(), assinatura, mechanism=Mechanism.SHA256_RSA_PKCS
        )


def gerar_chave_aes_no_cofre(label: str) -> None:

    with sessao_hsm() as sessao:
        sessao.generate_key(
            KeyType.AES,
            256,
            store=True,
            label=label,
            template={
                Attribute.TOKEN: True,
                Attribute.PRIVATE: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )


def cifrar_no_cofre(label: str, texto: str) -> tuple[bytes, bytes]:
  
    with sessao_hsm() as sessao:
        chave = sessao.get_key(
            object_class=ObjectClass.SECRET_KEY,
            label=label,
        )
        iv = os.urandom(12)
        cifrado = chave.encrypt(
            texto.encode(),
            mechanism=Mechanism.AES_GCM,
            mechanism_param=GCMParams(iv),
        )
        return iv, bytes(cifrado)


def decifrar_no_cofre(label: str, iv: bytes, cifrado: bytes) -> str:
    
    with sessao_hsm() as sessao:
        chave = sessao.get_key(
            object_class=ObjectClass.SECRET_KEY,
            label=label,
        )
        texto = chave.decrypt(
            cifrado,
            mechanism=Mechanism.AES_GCM,
            mechanism_param=GCMParams(iv),
        )
        return bytes(texto).decode()

def listar_chaves() -> list[dict]:
   
    chaves = []
    with sessao_hsm() as sessao:
        for classe, tipo in [
            (ObjectClass.PRIVATE_KEY, "RSA privada"),
            (ObjectClass.PUBLIC_KEY, "RSA pública"),
            (ObjectClass.SECRET_KEY, "AES"),
        ]:
            for objeto in sessao.get_objects({Attribute.CLASS: classe}):
                chaves.append({"label": objeto.label, "tipo": tipo})
    return chaves


                               
        