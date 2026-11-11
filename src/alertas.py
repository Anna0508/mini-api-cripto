import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

import auditoria
import cripto
import metricas
from trava import TravaDeArquivo

# Para onde o alerta vai. Vazio = alertas desligados.
ALERTA_URL = os.getenv("ALERTA_URL", "")

# Estados: 0 = ok, 1 = atenção (>= 50%), 2 = crítico (100%)
NOMES = {0: "ok", 1: "atencao", 2: "critico"}
SOBE_ATENCAO = 0.5
SOBE_CRITICO = 1.0
# Histerese: para voltar a poder alertar, precisa cair BEM abaixo do limiar.
VOLTA_ATENCAO = 0.4
VOLTA_CRITICO = 0.9

TENTATIVAS = 4
ESPERA_INICIAL = 1.0  # segundos; dobra a cada tentativa (1, 2, 4)
TEMPO_LIMITE = 2.0  # segundos que cada envio pode demorar

TRAVA_ALERTA = TravaDeArquivo("alerta")
_envios: list[threading.Thread] = []


def caminho_estado():
    return cripto.PASTA_CHAVES / ".alerta_estado.json"


def novo_nivel(proporcao: float, atual: int) -> int:
    """Decide o estado do cofre. Só alerta quem SOBE; descer apenas rearma."""
    if proporcao >= SOBE_CRITICO:
        return 2
    if atual == 2:
        if proporcao >= VOLTA_CRITICO:
            return 2
        atual = 1  # saiu do crítico: cai para atenção e continua a avaliar
    if proporcao >= SOBE_ATENCAO:
        return 1
    if atual == 1 and proporcao >= VOLTA_ATENCAO:
        return 1  # zona de histerese (40% a 50%): fica quieto, não rearma
    return 0


def _ler_nivel() -> int:
    try:
        return int(json.loads(caminho_estado().read_text())["nivel"])
    except (FileNotFoundError, ValueError, KeyError):
        return 0


def _gravar_nivel(nivel: int):
    arquivo = caminho_estado()
    temporario = arquivo.with_name(arquivo.name + ".tmp")
    temporario.write_text(
        json.dumps({"nivel": nivel, "desde": datetime.now(timezone.utc).isoformat()})
    )
    os.replace(temporario, arquivo)  # troca de uma vez: nunca fica meio escrito


def _atualizar_estado(em_uso: int, limite: int):
    """Devolve o alerta a enviar (se o estado subiu) ou None."""
    proporcao = em_uso / limite if limite > 0 else 0.0
    with TRAVA_ALERTA:
        atual = _ler_nivel()
        novo = novo_nivel(proporcao, atual)
        if novo != atual:
            _gravar_nivel(novo)
        if novo > atual:
            return {
                "evento": "limite_de_chaves",
                "nivel": NOMES[novo],
                "percentual": round(proporcao * 100, 1),
                "em_uso": em_uso,
                "limite": limite,
                "quando": datetime.now(timezone.utc).isoformat(),
            }
    return None


def enviar_http(alerta: dict):
    pedido = urllib.request.Request(
        ALERTA_URL,
        data=json.dumps(alerta).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(pedido, timeout=TEMPO_LIMITE):
        pass  # urlopen já levanta erro se o destino responder 4xx/5xx


def _registrar(operacao: str, alerta: dict, sucesso: bool, erro, tentativas: int):
    recurso = (
        f"nivel={alerta['nivel']};em_uso={alerta['em_uso']};"
        f"limite={alerta['limite']};tentativas={tentativas}"
    )
    try:
        auditoria.registrar(operacao, recurso, sucesso, erro)
    except Exception:
        pass  # nem o log pode derrubar a thread do alerta


def _enviar_com_tentativas(alerta: dict):
    espera = ESPERA_INICIAL
    erro = None
    for tentativa in range(1, TENTATIVAS + 1):
        try:
            enviar_http(alerta)
        except Exception as e:
            erro = type(e).__name__
            if tentativa < TENTATIVAS:
                time.sleep(espera)
                espera *= 2
        else:
            _registrar("alerta_enviado", alerta, True, None, tentativa)
            return
    _registrar("alerta_falhou", alerta, False, erro, TENTATIVAS)


def _disparar(alerta: dict):
    """Manda em outra thread: quem criou a chave não espera o destino responder."""
    _envios[:] = [t for t in _envios if t.is_alive()]
    thread = threading.Thread(target=_enviar_com_tentativas, args=(alerta,), daemon=True)
    _envios.append(thread)
    thread.start()


def esperar_envios(tempo_maximo: float = 10.0):
    """Só para os testes: espera as threads de envio terminarem."""
    for thread in list(_envios):
        thread.join(tempo_maximo)


def verificar():
    """Chamada depois de criar uma chave. NUNCA levanta erro."""
    try:
        alerta = _atualizar_estado(metricas.chaves_em_uso(), metricas.LIMITE_CHAVES)
        if alerta and ALERTA_URL:
            _disparar(alerta)
    except Exception as e:
        _registrar_falha_interna(e)


def _registrar_falha_interna(erro: Exception):
    try:
        auditoria.registrar("alerta_verificar", "estado", False, type(erro).__name__)
    except Exception:
        pass