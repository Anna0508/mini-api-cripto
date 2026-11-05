import threading
import time

import hsm

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