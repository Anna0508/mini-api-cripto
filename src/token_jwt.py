import os
from datetime import datetime, timedelta, timezone

import jwt

SEGREDO = os.getenv("JWT_SEGREDO", "")
if len(SEGREDO) < 32:
    raise RuntimeError(
        "Variavel de ambiente JWT_SEGREDO não definido (ou curta demais:" \
        "use pelo menos 32 caracteres). Veja docs/login.md."
    )

ALGORITMO = "HS256"
VALIDADE_MINUTOS = int(os.getenv("TOKEN_MINUTOS", "30"))
def criar_token(usuario: str) -> str:
    agora = datetime.now(timezone.utc)
    dados = {
        "sub": usuario,  # "sub" = de quem é o token
        "iat": agora,  # quando foi criado
        "exp": agora + timedelta(minutes=VALIDADE_MINUTOS),  # quando vence
    }
    return jwt.encode(dados, SEGREDO, algorithm=ALGORITMO)

def verificar_token(token: str) -> str | None:
    try:
        dados = jwt.decode(
            token,
            SEGREDO,
            algorithms=[ALGORITMO],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        return None
    usuario = dados["sub"]
    return usuario if isinstance(usuario, str) else None