import json

import pytest

import alertas
import auditoria
import metricas


@pytest.fixture
def enviados(monkeypatch):
    """Liga os alertas e troca o envio de verdade por uma lista."""
    lista = []
    monkeypatch.setattr(alertas, "ALERTA_URL", "http://teste")
    monkeypatch.setattr(alertas, "enviar_http", lambda alerta: lista.append(alerta))
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 10)
    return lista


def usar(monkeypatch, em_uso):
    monkeypatch.setattr(metricas, "chaves_em_uso", lambda: em_uso)
    alertas.verificar()
    alertas.esperar_envios()


def niveis(enviados):
    return [a["nivel"] for a in enviados]


def operacoes_do_log():
    linhas = auditoria.caminho().read_text().splitlines()
    return [json.loads(l) for l in linhas]


# ---------- a regra (sem arquivo, sem rede) ----------


@pytest.mark.parametrize(
    "proporcao, atual, esperado",
    [
        (0.0, 0, 0),
        (0.49, 0, 0),
        (0.50, 0, 1),
        (0.99, 0, 1),
        (1.0, 0, 2),
        (1.5, 0, 2),
        (0.45, 1, 1),   # zona de histerese: continua em atenção
        (0.40, 1, 1),
        (0.39, 1, 0),   # caiu abaixo de 40%: rearma
        (0.95, 2, 2),   # ainda perto do limite: continua crítico
        (0.90, 2, 2),
        (0.89, 2, 1),   # saiu do crítico, continua em atenção
        (0.45, 2, 1),
        (0.30, 2, 0),
    ],
)
def test_novo_nivel(proporcao, atual, esperado):
    assert alertas.novo_nivel(proporcao, atual) == esperado


# ---------- alertar na mudança, não no estado ----------


def test_alerta_ao_passar_de_50_por_cento(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 4)
    assert enviados == []
    usar(monkeypatch, 5)

    assert niveis(enviados) == ["atencao"]
    assert enviados[0]["percentual"] == 50.0
    assert enviados[0]["em_uso"] == 5
    assert enviados[0]["limite"] == 10


def test_continuar_acima_de_50_nao_repete_o_alerta(ambiente, enviados, monkeypatch):
    for _ in range(1440):  # um dia de checagens a cada 60 s
        usar(monkeypatch, 6)

    assert niveis(enviados) == ["atencao"]


def test_alerta_critico_ao_chegar_em_100(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 5)
    usar(monkeypatch, 10)
    usar(monkeypatch, 10)

    assert niveis(enviados) == ["atencao", "critico"]


def test_pulo_direto_para_100_manda_um_alerta_so(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 10)

    assert niveis(enviados) == ["critico"]


def test_voltar_abaixo_de_40_e_subir_de_novo_alerta_outra_vez(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 6)
    usar(monkeypatch, 3)   # 30%: rearmou
    usar(monkeypatch, 6)

    assert niveis(enviados) == ["atencao", "atencao"]


def test_oscilar_entre_40_e_50_nao_alerta(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 6)   # alerta
    for em_uso in [4, 5, 4, 5, 4, 5]:  # 40% e 50%: zona quieta
        usar(monkeypatch, em_uso)

    assert niveis(enviados) == ["atencao"]


def test_cair_do_critico_e_voltar_alerta_o_critico_de_novo(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 10)
    usar(monkeypatch, 9)    # 90%: ainda crítico, quieto
    usar(monkeypatch, 10)
    usar(monkeypatch, 8)    # 80%: saiu do crítico
    usar(monkeypatch, 10)

    assert niveis(enviados) == ["critico", "critico"]


def test_o_estado_fica_no_arquivo(ambiente, enviados, monkeypatch):
    usar(monkeypatch, 6)
    estado = json.loads(alertas.caminho_estado().read_text())

    assert estado["nivel"] == 1
    # "outro processo": só enxerga o arquivo e não repete o alerta
    assert alertas._ler_nivel() == 1
    usar(monkeypatch, 6)
    assert niveis(enviados) == ["atencao"]


def test_alertas_desligados_sem_url_nao_enviam_nem_registram(ambiente, monkeypatch):
    chamadas = []
    monkeypatch.setattr(alertas, "enviar_http", lambda a: chamadas.append(a))
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 10)
    usar(monkeypatch, 10)

    assert chamadas == []
    assert not auditoria.caminho().exists()


# ---------- falha no destino não derruba a operação ----------


def test_tenta_de_novo_e_acaba_conseguindo(ambiente, enviados, monkeypatch):
    tentativas = []

    def falha_duas_vezes(alerta):
        tentativas.append(1)
        if len(tentativas) < 3:
            raise TimeoutError()
        enviados.append(alerta)

    monkeypatch.setattr(alertas, "enviar_http", falha_duas_vezes)
    usar(monkeypatch, 6)

    assert niveis(enviados) == ["atencao"]
    operacoes = [r["operacao"] for r in operacoes_do_log()]
    assert operacoes == ["alerta_enviado"]
    assert "tentativas=3" in operacoes_do_log()[0]["recurso"]


def test_alerta_com_defeito_interno_nao_levanta_erro(ambiente, enviados, monkeypatch):
    def quebra():
        raise RuntimeError("cofre caiu")

    monkeypatch.setattr(metricas, "chaves_em_uso", quebra)
    alertas.verificar()  # não pode levantar

    assert operacoes_do_log()[-1]["operacao"] == "alerta_verificar"


def test_o_log_do_alerta_nao_guarda_o_endereco_do_destino(ambiente, monkeypatch):
    monkeypatch.setattr(alertas, "ALERTA_URL", "http://segredo.exemplo/token123")
    monkeypatch.setattr(alertas, "enviar_http", lambda a: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 10)
    usar(monkeypatch, 10)

    assert "segredo" not in auditoria.caminho().read_text()
    assert "token123" not in auditoria.caminho().read_text()