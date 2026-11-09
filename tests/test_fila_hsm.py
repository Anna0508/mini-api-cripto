import multiprocessing
import threading
import time

import hsm
from trava import TravaDeArquivo

class SessaoFalsa:
    def close(self):
        pass

class TokenFalso:
    def open(self, **kwargs):
        return SessaoFalsa()

class BibliotecaFalsa:
    def get_token(self, **kwargs):
        return TokenFalso()

def test_so_um_acesso_ao_hsm_por_vez(monkeypatch):
    # Substitui a biblioteca real por uma falsa
    monkeypatch.setattr(hsm.pkcs11, "lib", lambda caminho: BibliotecaFalsa())
    dentro = 0
    maximo = 0
    contador = threading.Lock()

    def usar_hsm():
        nonlocal dentro, maximo
        with hsm.sessao_hsm():
            with contador:
                dentro += 1
                if dentro > maximo:
                    maximo = dentro
            time.sleep(0.1)  # Simula algum tempo de uso do HSM
            with contador:
                dentro -= 1

    threads = [threading.Thread(target=usar_hsm) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert maximo == 1, "Houve acesso simultaneo ao HSM"

def somar(arquivo, nome_trava, vezes):
    trava = TravaDeArquivo(nome_trava)
    for _ in range(vezes):
        with trava:
            valor = int(open(arquivo).read())
            time.sleep(0.001)
            open(arquivo, "w").write(str(valor + 1))


def test_dois_processos_nao_se_atropelam(tmp_path):
    arquivo = tmp_path / "contador.txt"
    arquivo.write_text("0")
    processos = [
        multiprocessing.Process(target=somar, args=(str(arquivo), "teste-trava", 20))
        for _ in range(2)
    ]
    for p in processos:
        p.start()
    for p in processos:
        p.join()
    assert int(arquivo.read_text()) == 40


def test_a_mesma_thread_pode_entrar_duas_vezes():
    trava = TravaDeArquivo("teste-reentrada")
    with trava:
        with trava:
            pass

def preparar_contagem(monkeypatch):
    aberturas =[]

    class SessaoContada:
        def close(self):
            pass

    class Tokencontado:
        def open(self, **kwargs):
            aberturas.append(1)
            return SessaoContada()

    class BibliotecaContada:
        def get_token(self, **kwargs):
            return Tokencontado()

    monkeypatch.setattr(hsm.pkcs11, "lib", lambda caminho: BibliotecaContada())
    return aberturas

def test_sessao_e_reaproveitada(monkeypatch):
    aberturas = preparar_contagem(monkeypatch)
    for _ in range(5):
        with hsm.sessao_hsm():
            pass
    assert len(aberturas) == 1, "Sessão não foi reaproveitada"

def test_sessao_e_reaberta_depois_de_erro(monkeypatch):
    aberturas = preparar_contagem(monkeypatch)
    try:
        with hsm.sessao_hsm():
            raise RuntimeError("Erro proposital")
    except RuntimeError:
        pass
    with hsm.sessao_hsm():
        pass
    assert len(aberturas) == 2, "Sessão não foi reaberta depois de erro"