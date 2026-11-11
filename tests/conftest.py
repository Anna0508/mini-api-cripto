
import pytest

import cripto
import metricas


@pytest.fixture
def ambiente(tmp_path, monkeypatch):
    monkeypatch.setattr(cripto, "PASTA_CHAVES", tmp_path)
    monkeypatch.setattr(
        metricas, "chaves_do_cofre", lambda: {"total": 0, "por_tipo": {}}
    )
    return tmp_path


@pytest.fixture
def limite_alto(monkeypatch):
    monkeypatch.setattr(metricas, "LIMITE_CHAVES", 10_000)

@pytest.fixture(autouse=True)
def auditoria_isolada(tmp_path, monkeypatch):
    import auditoria

    pasta = tmp_path / "auditoria"
    pasta.mkdir()
    monkeypatch.setattr(auditoria, "caminho", lambda: pasta / ".auditoria.jsonl")

@pytest.fixture(autouse=True)
def sessao_hsm_limpa():
    import hsm

    hsm.fechar_sessao()
    yield
    hsm.fechar_sessao()

@pytest.fixture(autouse=True)
def alertas_isoladas(tmp_path, monkeypatch):
    import alertas

    monkeypatch.setattr(alertas, "caminho_estado", lambda: tmp_path / "alerta_estado.json")
    monkeypatch.setattr(alertas, "ALERTA_URL", "")
    monkeypatch.setattr(alertas, "ESPERA_INICIAL", 0)
    yield
    alertas.esperar_envios()