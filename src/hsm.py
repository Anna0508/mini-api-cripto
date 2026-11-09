import hashlib
import os
from contextlib import contextmanager

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import GCMParams
from pkcs11.util.ec import encode_named_curve_parameters

from trava import TravaDeArquivo
CAMINHO_BIBLIOTECA = "/usr/lib/softhsm/libsofthsm2.so"
LABEL_TOKEN = "cofre-treino"
FILA_HSM = TravaDeArquivo("hsm")
PIN = os.getenv("HSM_PIN")
if not PIN:
    raise RuntimeError(
        "Variável de ambiente HSM_PIN não definida. "
        "Defina o PIN do cofre (ex.: no docker-compose.yml) antes de iniciar a API."
    )

_sessao = None


def fechar_sessao():
    global _sessao
    if _sessao is not None:
        try:
            _sessao.close()
        except Exception:
            pass
        _sessao = None


@contextmanager
def sessao_hsm():
    global _sessao
    with FILA_HSM:
        if _sessao is None:
            lib = pkcs11.lib(CAMINHO_BIBLIOTECA)
            token = lib.get_token(token_label=LABEL_TOKEN)
            _sessao = token.open(user_pin=PIN, rw=True)
        try:
            yield _sessao
        except BaseException:
            fechar_sessao()
            raise


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
            key_type=KeyType.RSA,
            label=label,
        )
        
        return privada.sign(texto.encode(), mechanism=Mechanism.SHA256_RSA_PKCS)


def verificar_no_cofre(label: str, texto: str, assinatura: bytes) -> bool:
    with sessao_hsm() as sessao:
        publica = sessao.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.RSA,
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

def _nome_do_tipo(classe, tipo_da_chave) -> str:
    if classe == ObjectClass.SECRET_KEY:
        return "AES" if tipo_da_chave == KeyType.AES else tipo_da_chave.name
    lado = "privada" if classe == ObjectClass.PRIVATE_KEY else "pública"
    return f"{tipo_da_chave.name} {lado}"


def listar_chaves() -> list[dict]:
    chaves = []
    with sessao_hsm() as sessao:
        for classe in (
            ObjectClass.PRIVATE_KEY,
            ObjectClass.PUBLIC_KEY,
            ObjectClass.SECRET_KEY,
        ):
            for objeto in sessao.get_objects({Attribute.CLASS: classe}):
                chaves.append(
                    {
                        "label": objeto.label,
                        "tipo": _nome_do_tipo(classe, objeto.key_type),
                    }
                )
    return chaves


class ChaveJaExiste(Exception):
    pass


def gerar_par_ec_no_cofre(label: str) -> bytes:
    with sessao_hsm() as sessao:
        ja_existe = list(
            sessao.get_objects(
                {Attribute.LABEL: label, Attribute.KEY_TYPE: KeyType.EC}
            )
        )
        if ja_existe:
            raise ChaveJaExiste(label)

        curva = sessao.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        publica, _privada = curva.generate_keypair(
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
        return bytes(publica[Attribute.EC_POINT])


def _hash_do_texto(texto: str) -> bytes:
    return hashlib.sha256(texto.encode()).digest()


def assinar_ec_no_cofre(label: str, texto: str) -> bytes:
    with sessao_hsm() as sessao:
        privada = sessao.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.EC,
            label=label,
        )
        return privada.sign(_hash_do_texto(texto), mechanism=Mechanism.ECDSA)


def verificar_ec_no_cofre(label: str, texto: str, assinatura: bytes) -> bool:
    with sessao_hsm() as sessao:
        publica = sessao.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.EC,
            label=label,
        )
        return publica.verify(
            _hash_do_texto(texto), assinatura, mechanism=Mechanism.ECDSA
        )
