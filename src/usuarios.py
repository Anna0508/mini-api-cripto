import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone

import cripto
from trava import TravaDeArquivo

NOME_VALIDO = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
SENHA_MINIMA = 8

CUSTO_N = 2**14
CUSTO_R = 8
CUSTO_P = 1

TRAVA_USUARIOS = TravaDeArquivo("usuarios")

class UsuarioJaExiste(Exception):
    pass

def caminho():
    return cripto.PASTA_CHAVES / ".usuarios.json"

def gerar_hash(senha: str) -> str:
    sal = os.urandom(16)
    resumo = hashlib.scrypt(
        senha.encode(), salt=sal, n=CUSTO_N, r=CUSTO_R, p=CUSTO_P
    )
    return "$".join(
        [
            "scrypt",
            str(CUSTO_N),
            str(CUSTO_R),
            str(CUSTO_P),
            base64.b64encode(sal).decode(),
            base64.b64encode(resumo).decode(),
        ]
    )

def conferir_senha(senha: str, guardado: str) -> bool:
    try:
        _, n, r, p, sal, resumo = guardado.split("$")
        esperado = base64.b64decode(resumo)
        calculado = hashlib.scrypt(
            senha.encode(),
            salt=base64.b64decode(sal),
            n=int(n),
            r=int(r),
            p=int(p),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calculado, esperado)

def _ler() -> dict:
    try:
        return json.loads(caminho().read_text())
    except FileNotFoundError:
        return{}
    
def _gravar(usuarios: dict):
    arquivo = caminho()
    temporario = arquivo.with_name(arquivo.name + ".tmp")
    temporario.write_text(json.dumps(usuarios, indent=2))
    os.chmod(temporario,0o600)
    os.replace(temporario, arquivo)

def criar(nome:str, senha: str):
    if not NOME_VALIDO.match(nome):
        raise ValueError("Nome: 3 a 32 caracteres (letras, números, _ , - ).")
    if len(senha) < SENHA_MINIMA:
        raise ValueError(f"A senha precisa ter pelo menos {SENHA_MINIMA} caracteres.")
    with TRAVA_USUARIOS:
        usuarios = _ler()
        if nome in usuarios:
            raise UsuarioJaExiste(nome)
        usuarios[nome] = {
            "senha": gerar_hash(senha),
            "criado_em": datetime.now(timezone.utc).isoformat(),
        }
        _gravar(usuarios)

_HASH_FALSO = gerar_hash("senha-que-ninguem-usa")

def autenticar(nome: str, senha: str) -> bool:
    usuario = _ler().get(nome)
    if usuario is None:
        conferir_senha(senha, _HASH_FALSO)
        return False
    return conferir_senha(senha, usuario["senha"])

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "criar":
        sys.exit("uso: python src/usuarios.py criar NOME")
    senha = getpass.getpass("Senha: ")
    if senha != getpass.getpass("Repita a senha: "):
        sys.exit("As senhas não são iguais.")
    try:
        criar(sys.argv[2], senha)
    except (ValueError, UsuarioJaExiste) as erro:
        sys.exit(f"Não foi possível criar: {erro}")
    print(f"Usuário '{sys.argv[2]}' criado.")