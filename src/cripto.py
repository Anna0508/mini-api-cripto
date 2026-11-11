import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

PASTA_CHAVES = Path("/app/chaves")


def gerar_par_de_chaves(nome: str) -> str:
    """Gera um par RSA e salva os dois arquivos na pasta chaves/.

    Devolve a chave pública em texto (formato PEM).
    """
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Salva a privada em arquivo (INSEGURO é só para aprender)
    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (PASTA_CHAVES / f"{nome}_privada.pem").write_bytes(pem_privada)

    # Salva a pública também
    pem_publica = chave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (PASTA_CHAVES / f"{nome}_publica.pem").write_bytes(pem_publica)

    return pem_publica.decode()


def assinar(nome: str, texto: str) -> bytes:
    """Assina um texto com a chave privada."""
    pem = (PASTA_CHAVES / f"{nome}_privada.pem").read_bytes()
    chave_privada = serialization.load_pem_private_key(pem, password=None)

    assinatura = chave_privada.sign(
        texto.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return assinatura


from cryptography.exceptions import InvalidSignature


def verificar(nome: str, texto: str, assinatura: bytes) -> bool:
    """Confere se a assinatura corresponde ao texto. Usa a chave PÚBLICA."""
    pem = (PASTA_CHAVES / f"{nome}_publica.pem").read_bytes()
    chave_publica = serialization.load_pem_public_key(pem)

    try:
        chave_publica.verify(
            assinatura,
            texto.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def gerar_chave_aes(nome: str) -> None:
    """Gera uma chave AES-256 e salva em arquivo."""
    chave = AESGCM.generate_key(bit_length=256)
    (PASTA_CHAVES / f"{nome}_aes.bin").write_bytes(chave)


def cifrar(nome: str, texto: str) -> tuple[bytes, bytes]:
    """Cifra um texto. Devolve (iv, texto_cifrado)."""
    chave = (PASTA_CHAVES / f"{nome}_aes.bin").read_bytes()
    aesgcm = AESGCM(chave)

    iv = os.urandom(12)  # NUNCA repetir o IV com a mesma chave
    cifrado = aesgcm.encrypt(iv, texto.encode(), None)

    return iv, cifrado


def decifrar(nome: str, iv: bytes, cifrado: bytes) -> str:
    """Decifra. Precisa do MESMO iv usado para cifrar."""
    chave = (PASTA_CHAVES / f"{nome}_aes.bin").read_bytes()
    aesgcm = AESGCM(chave)

    return aesgcm.decrypt(iv, cifrado, None).decode()


def _gravar_sem_sobrescrever(caminho: Path, conteudo: bytes) -> None:
    with open(caminho, "xb") as arquivo:
        arquivo.write(conteudo)


def gerar_chave_chacha(nome: str) -> None:
    chave = ChaCha20Poly1305.generate_key()
    _gravar_sem_sobrescrever(PASTA_CHAVES / f"{nome}_chacha.bin", chave)


def cifrar_chacha(nome: str, texto: str) -> tuple[bytes, bytes]:
    chave = (PASTA_CHAVES / f"{nome}_chacha.bin").read_bytes()
    chacha = ChaCha20Poly1305(chave)

    nonce = os.urandom(12)
    cifrado = chacha.encrypt(nonce, texto.encode(), None)

    return nonce, cifrado


def decifrar_chacha(nome: str, nonce: bytes, cifrado: bytes) -> str:
    chave = (PASTA_CHAVES / f"{nome}_chacha.bin").read_bytes()
    chacha = ChaCha20Poly1305(chave)

    return chacha.decrypt(nonce, cifrado, None).decode()


def gerar_par_ed25519(nome: str) -> str:
    caminho_privada = PASTA_CHAVES / f"{nome}_ed25519_privada.pem"
    caminho_publica = PASTA_CHAVES / f"{nome}_ed25519_publica.pem"
    if caminho_privada.exists() or caminho_publica.exists():
        raise FileExistsError(nome)

    chave_privada = ed25519.Ed25519PrivateKey.generate()

    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _gravar_sem_sobrescrever(caminho_privada, pem_privada)

    pem_publica = chave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _gravar_sem_sobrescrever(caminho_publica, pem_publica)

    return pem_publica.decode()


def assinar_ed25519(nome: str, texto: str) -> bytes:
    pem = (PASTA_CHAVES / f"{nome}_ed25519_privada.pem").read_bytes()
    chave_privada = serialization.load_pem_private_key(pem, password=None)

    return chave_privada.sign(texto.encode())


def verificar_ed25519(nome: str, texto: str, assinatura: bytes) -> bool:
    pem = (PASTA_CHAVES / f"{nome}_ed25519_publica.pem").read_bytes()
    chave_publica = serialization.load_pem_public_key(pem)

    try:
        chave_publica.verify(assinatura, texto.encode())
        return True
    except InvalidSignature:
        return False
