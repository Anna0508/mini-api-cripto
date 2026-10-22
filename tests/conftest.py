
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