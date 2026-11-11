import csv
import hashlib
import io
import json
from contextlib import contextmanager
from datetime import datetime, timezone

import cripto
from trava import TravaDeArquivo

AUTOR = "sistema"
HASH_INICIAL = "0" * 64
TRAVA_AUDITORIA = TravaDeArquivo("auditoria")


def caminho():
    return cripto.PASTA_CHAVES / ".auditoria.jsonl"


def calcular_hash(registro: dict, hash_anterior: str) -> str:
    conteudo = json.dumps(registro, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((hash_anterior + conteudo).encode()).hexdigest()


def ultimo_hash() -> str:
    arquivo = caminho()
    if not arquivo.exists():
        return HASH_INICIAL
    with arquivo.open("rb") as f:
        f.seek(0, 2)
        posicao = f.tell()
        dados = b""
        while posicao > 0 and dados.count(b"\n") < 2:
            leitura = min(4096, posicao)
            posicao -= leitura
            f.seek(posicao)
            dados = f.read(leitura) + dados
    linhas = dados.splitlines()
    if not linhas:
        return HASH_INICIAL
    return json.loads(linhas[-1])["hash"]


def registrar(operacao: str, recurso: str, sucesso: bool, erro: str | None = None):
    with TRAVA_AUDITORIA:
        registro = {
            "quando": datetime.now(timezone.utc).isoformat(),
            "autor": AUTOR,
            "operacao": operacao,
            "recurso": recurso,
            "sucesso": sucesso,
            "erro": erro,
        }
        anterior = ultimo_hash()
        registro["hash_anterior"] = anterior
        registro["hash"] = calcular_hash(
            {k: v for k, v in registro.items() if k != "hash_anterior"}, anterior
        )
        with caminho().open("a") as f:
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")


@contextmanager
def auditar(operacao: str, recurso: str):
    try:
        yield
    except Exception as e:
        registrar(operacao, recurso, False, type(e).__name__)
        raise
    registrar(operacao, recurso, True)


def verificar_cadeia() -> tuple[bool, int | None]:
    """Devolve (True, None) se a cadeia está íntegra, ou (False, nº da linha com problema)."""
    arquivo = caminho()
    if not arquivo.exists():
        return True, None
    anterior = HASH_INICIAL
    with arquivo.open() as f:
        for numero, linha in enumerate(f, start=1):
            registro = json.loads(linha)
            esperado = calcular_hash(
                {k: v for k, v in registro.items() if k not in ("hash", "hash_anterior")},
                anterior,
            )
            if registro["hash_anterior"] != anterior or registro["hash"] != esperado:
                return False, numero
            anterior = registro["hash"]
    return True, None


COLUNAS = ["quando", "autor", "operacao", "recurso", "sucesso", "erro", "hash_anterior", "hash"]


def _registros_ate(limite: int):
    """Lê o log linha a linha, só até 'limite' bytes (a foto do arquivo)."""
    with caminho().open("rb") as f:
        lidos = 0
        for linha in f:
            lidos += len(linha)
            if lidos > limite:
                return
            yield json.loads(linha)


def _passa_no_filtro(registro: dict, de, ate, operacao) -> bool:
    dia = registro["quando"][:10]  # "2026-11-09"
    if de and dia < de.isoformat():
        return False
    if ate and dia > ate.isoformat():
        return False
    if operacao and registro["operacao"] != operacao:
        return False
    return True


def _proteger(valor):
    """Evita 'injeção de fórmula': o Excel executa texto que começa com = + - @."""
    texto = "" if valor is None else str(valor)
    if texto[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + texto
    return texto


def _linha_csv(valores) -> str:
    saida = io.StringIO()
    csv.writer(saida, lineterminator="\n").writerow(valores)
    return saida.getvalue()


def exportar_csv(de=None, ate=None, operacao=None):
    """Gera o CSV do log linha a linha (nunca carrega o arquivo inteiro)."""
    # 0) A "foto": só vale o que existe agora. Novas linhas durante a exportação ficam de fora.
    with TRAVA_AUDITORIA:
        arquivo = caminho()
        limite = arquivo.stat().st_size if arquivo.exists() else 0

    # 1) Primeira passada: conta as linhas do filtro e confere a cadeia (só guarda números).
    total_no_log = 0
    total_filtrado = 0
    anterior = HASH_INICIAL
    quebrada_em = None
    if limite:
        for numero, registro in enumerate(_registros_ate(limite), start=1):
            total_no_log += 1
            if quebrada_em is None:
                esperado = calcular_hash(
                    {k: v for k, v in registro.items() if k not in ("hash", "hash_anterior")},
                    anterior,
                )
                if registro["hash_anterior"] != anterior or registro["hash"] != esperado:
                    quebrada_em = numero
                anterior = registro["hash"]
            if _passa_no_filtro(registro, de, ate, operacao):
                total_filtrado += 1

    # 2) Exportar é saída de dados: fica registrado no próprio log (depois da foto).
    filtro = f"de={de or '-'};ate={ate or '-'};operacao={operacao or '-'};linhas={total_filtrado}"
    registrar("exportar_auditoria", filtro, True)

    # 3) Cabeçalho que diz o que é o arquivo.
    periodo = f"{de or 'inicio'} a {ate or 'fim'}"
    cadeia = "INTEGRA" if quebrada_em is None else f"QUEBRADA na linha {quebrada_em}"
    yield "# Exportacao do log de auditoria\n"
    yield f"# exportado_por: {AUTOR}\n"
    yield f"# exportado_em: {datetime.now(timezone.utc).isoformat()}\n"
    yield f"# periodo: {periodo}\n"
    yield f"# filtro_operacao: {operacao or 'todas'}\n"
    yield f"# total_linhas: {total_filtrado}\n"
    yield f"# total_no_log_na_exportacao: {total_no_log}\n"
    yield f"# cadeia_de_hash: {cadeia}\n"
    yield _linha_csv(COLUNAS)

    # 4) Segunda passada: escreve só as linhas do filtro, uma de cada vez.
    if limite:
        for registro in _registros_ate(limite):
            if _passa_no_filtro(registro, de, ate, operacao):
                yield _linha_csv([_proteger(registro.get(c)) for c in COLUNAS])
