import json

import pytest
from fastapi.testclient import TestClient

import auditoria
import metricas
from main import app

client = TestClient(app)


def ler_registros():
    return [
        json.loads(linha)
        for linha in auditoria.caminho().read_text().splitlines()
    ]


def test_registra_sucesso(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k1"})
    r = ler_registros()[0]
    assert r["operacao"] == "criar_chave_aes"
    assert r["recurso"] == "k1"
    assert r["sucesso"] is True
    assert r["autor"] == "sistema"


def test_registra_falha(ambiente, monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 0)
    resp = client.post("/chaves/aes", json={"nome": "k0"})
    assert resp.status_code == 409
    r = ler_registros()[0]
    assert r["sucesso"] is False
    assert r["erro"] == "HTTPException"


def test_nao_grava_texto_nem_chave(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k2"})
    client.post("/cifrar", json={"nome": "k2", "texto": "TEXTO-SECRETO-123"})
    conteudo = auditoria.caminho().read_text()
    assert "TEXTO-SECRETO-123" not in conteudo


def test_cadeia_integra(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k3"})
    client.post("/cifrar", json={"nome": "k3", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k3", "texto": "oi"})
    assert auditoria.verificar_cadeia() == (True, None)


def test_detecta_registro_alterado(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k4"})
    client.post("/cifrar", json={"nome": "k4", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k4", "texto": "oi"})
    linhas = auditoria.caminho().read_text().splitlines()
    registro = json.loads(linhas[1])
    registro["recurso"] = "outra"
    linhas[1] = json.dumps(registro)
    auditoria.caminho().write_text("\n".join(linhas) + "\n")
    assert auditoria.verificar_cadeia() == (False, 2)


def test_detecta_registro_removido(ambiente, limite_alto):
    client.post("/chaves/aes", json={"nome": "k5"})
    client.post("/cifrar", json={"nome": "k5", "texto": "oi"})
    client.post("/cifrar", json={"nome": "k5", "texto": "oi"})
    linhas = auditoria.caminho().read_text().splitlines()
    del linhas[1]
    auditoria.caminho().write_text("\n".join(linhas) + "\n")
    assert auditoria.verificar_cadeia()[0] is False


def test_ultimo_hash_nao_le_o_arquivo_inteiro(ambiente, limite_alto, monkeypatch):
    from pathlib import Path

    for i in range(30):
        auditoria.registrar("teste", f"k{i}", True)
    esperado = json.loads(auditoria.caminho().read_text().splitlines()[-1])["hash"]

    def proibido(*args, **kwargs):
        raise AssertionError("leu o arquivo inteiro")

    monkeypatch.setattr(Path, "read_text", proibido)

    assert auditoria.ultimo_hash() == esperado


@pytest.mark.parametrize("quantidade", [0, 1, 2, 3, 100])
def test_ultimo_hash_com_varios_tamanhos(ambiente, limite_alto, quantidade):
    for i in range(quantidade):
        auditoria.registrar("teste", f"k{i}", True)
    linhas = auditoria.caminho().read_text().splitlines() if quantidade else []
    esperado = json.loads(linhas[-1])["hash"] if linhas else auditoria.HASH_INICIAL

    assert auditoria.ultimo_hash() == esperado


def test_ultimo_hash_com_linha_maior_que_um_bloco(ambiente, limite_alto):
    auditoria.registrar("teste", "x" * 10_000, True)
    auditoria.registrar("teste", "y" * 10_000, True)
    esperado = json.loads(auditoria.caminho().read_text().splitlines()[-1])["hash"]

    assert auditoria.ultimo_hash() == esperado
    assert auditoria.verificar_cadeia() == (True, None)


def _exportar(**filtros):
    return "".join(auditoria.exportar_csv(**filtros))


def _dados(texto):
    """Separa os comentários (#) do CSV de verdade."""
    import csv
    import io

    linhas = texto.splitlines()
    comentarios = [l for l in linhas if l.startswith("#")]
    tabela = list(csv.DictReader(io.StringIO("\n".join(l for l in linhas if not l.startswith("#")))))
    return comentarios, tabela


def test_exportar_cabecalho_diz_o_que_e(ambiente, limite_alto):
    for i in range(3):
        auditoria.registrar("criar_chave", f"k{i}", True)
    comentarios, tabela = _dados(_exportar())

    assert "# total_linhas: 3" in comentarios
    assert "# periodo: inicio a fim" in comentarios
    assert "# filtro_operacao: todas" in comentarios
    assert "# cadeia_de_hash: INTEGRA" in comentarios
    assert len(tabela) == 3


def test_exportar_filtra_por_periodo_e_operacao(ambiente, limite_alto):
    from datetime import date

    auditoria.registrar("criar_chave", "a", True)
    auditoria.registrar("assinar", "b", True)
    hoje = date.today()
    # período que não inclui hoje
    _, vazio = _dados(_exportar(ate=date(2000, 1, 1)))
    assert vazio == []
    # período de hoje + só uma operação
    comentarios, tabela = _dados(_exportar(de=hoje, ate=hoje, operacao="assinar"))
    assert [l["recurso"] for l in tabela] == ["b"]
    assert "# total_linhas: 1" in comentarios
    assert f"# periodo: {hoje} a {hoje}" in comentarios


def test_exportar_e_auditado(ambiente, limite_alto):
    auditoria.registrar("criar_chave", "a", True)
    _exportar(operacao="criar_chave")
    registros = [json.loads(l) for l in auditoria.caminho().read_text().splitlines()]

    assert registros[-1]["operacao"] == "exportar_auditoria"
    assert registros[-1]["autor"] == "sistema"
    assert "operacao=criar_chave" in registros[-1]["recurso"]
    assert "linhas=1" in registros[-1]["recurso"]
    assert auditoria.verificar_cadeia() == (True, None)


def test_exportar_avisa_cadeia_quebrada(ambiente, limite_alto):
    for i in range(4):
        auditoria.registrar("criar_chave", f"k{i}", True)
    arquivo = auditoria.caminho()
    arquivo.write_text(arquivo.read_text().replace('"k1"', '"adulterado"'))

    comentarios, tabela = _dados(_exportar())

    assert "# cadeia_de_hash: QUEBRADA na linha 2" in comentarios
    assert len(tabela) == 4


def test_exportar_ignora_linhas_que_chegam_durante_a_exportacao(ambiente, limite_alto):
    for i in range(3):
        auditoria.registrar("criar_chave", f"k{i}", True)
    gerador = auditoria.exportar_csv()
    primeira = next(gerador)  # a foto já foi tirada
    auditoria.registrar("criar_chave", "chegou_depois", True)
    texto = primeira + "".join(gerador)
    comentarios, tabela = _dados(texto)

    assert "# total_linhas: 3" in comentarios
    assert len(tabela) == 3
    assert "chegou_depois" not in texto


def test_exportar_protege_contra_formula_no_excel(ambiente, limite_alto):
    auditoria.registrar("criar_chave", "=1+1", True)
    _, tabela = _dados(_exportar())

    assert tabela[0]["recurso"] == "'=1+1"


def test_exportar_sem_log(ambiente, limite_alto):
    comentarios, tabela = _dados(_exportar())

    assert "# total_linhas: 0" in comentarios
    assert tabela == []


def test_rota_exportar_devolve_csv_para_download(ambiente, limite_alto):
    auditoria.registrar("criar_chave", "k1", True)
    resposta = TestClient(app).get("/auditoria/exportar")

    assert resposta.status_code == 200
    assert resposta.headers["content-type"].startswith("text/csv")
    assert "attachment" in resposta.headers["content-disposition"]
    assert "auditoria_inicio_fim.csv" in resposta.headers["content-disposition"]
    assert "# total_linhas: 1" in resposta.text
    assert "criar_chave" in resposta.text


def test_rota_exportar_filtra_e_valida_datas(ambiente, limite_alto):
    auditoria.registrar("criar_chave", "k1", True)
    cliente = TestClient(app)

    vazio = cliente.get("/auditoria/exportar?de=2000-01-01&ate=2000-01-02")
    assert "# total_linhas: 0" in vazio.text
    assert "auditoria_2000-01-01_2000-01-02.csv" in vazio.headers["content-disposition"]

    assert cliente.get("/auditoria/exportar?de=2026-02-01&ate=2026-01-01").status_code == 422
    assert cliente.get("/auditoria/exportar?de=ontem").status_code == 422


def test_rota_exportar_fica_no_log(ambiente, limite_alto):
    TestClient(app).get("/auditoria/exportar?operacao=assinar")
    ultimo = json.loads(auditoria.caminho().read_text().splitlines()[-1])

    assert ultimo["operacao"] == "exportar_auditoria"
    assert "operacao=assinar" in ultimo["recurso"]
