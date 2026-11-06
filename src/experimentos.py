import collections
import os
import statistics
import subprocess
import sys
import threading
import time

import httpx

import auditoria
import cripto
import hsm
import metricas

LABEL = "medicao-hsm"
OPERACOES = 30
RODADAS = 10

PORTA = 8100
URL = f"http://127.0.0.1:{PORTA}"
PEDIDOS = 40
VAGAS = 5


def assinar_varias(vezes):
    for _ in range(vezes):
        hsm.assinar_no_cofre(LABEL, "texto para medir")


def medir(usuarios):
    threads = [
        threading.Thread(target=assinar_varias, args=(OPERACOES,))
        for _ in range(usuarios)
    ]
    inicio = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return time.perf_counter() - inicio


def experimento_hsm():
    hsm.gerar_par_no_cofre(LABEL)
    try:
        medir(1)
        tempos_1 = [medir(1) for _ in range(RODADAS)]
        tempos_2 = [medir(2) for _ in range(RODADAS)]
    finally:
        with hsm.sessao_hsm() as sessao:
            for objeto in sessao.get_objects({hsm.Attribute.LABEL: LABEL}):
                objeto.destroy()

    t1 = statistics.median(tempos_1)
    t2 = statistics.median(tempos_2)
    print(f"1 usuário  : mediana {t1:.3f} s  (mín {min(tempos_1):.3f}, máx {max(tempos_1):.3f})")
    print(f"2 usuários : mediana {t2:.3f} s  (mín {min(tempos_2):.3f}, máx {max(tempos_2):.3f})")
    print(f"proporção  : {t2 / t1:.2f}x")


def subir_api(extra_env, limite):
    env = {**os.environ, "LIMITE_CHAVES": str(limite), **extra_env}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--port", str(PORTA),
         "--workers", "2"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        try:
            if httpx.get(f"{URL}/saude", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("A API com 2 workers não subiu.")


def rajada(caminho, corpo):
    barreira = threading.Barrier(PEDIDOS)
    status = []

    def pedir(i):
        with httpx.Client(timeout=60) as c:
            barreira.wait()
            status.append(c.post(f"{URL}{caminho}", json=corpo(i)).status_code)

    threads = [threading.Thread(target=pedir, args=(i,)) for i in range(PEDIDOS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return collections.Counter(status)


def limpar():
    for arquivo in cripto.PASTA_CHAVES.glob("worker-*"):
        arquivo.unlink()


def testar_workers(titulo, extra_env):
    log = auditoria.caminho()
    copia = log.read_bytes() if log.exists() else None
    limpar()
    limite = metricas.chaves_em_uso() + VAGAS
    proc = subir_api(extra_env, limite)
    try:
        limite_resultado = rajada(
            "/chaves/aes", lambda i: {"nome": f"worker-chave-{i}"}
        )
        criadas = len(list(cripto.PASTA_CHAVES.glob("worker-chave-*")))
        httpx.post(f"{URL}/chaves/aes", json={"nome": "worker-log"}, timeout=30)
        rajada("/cifrar", lambda i: {"nome": "worker-log", "texto": "x"})
        cadeia = auditoria.verificar_cadeia()
    finally:
        proc.terminate()
        proc.wait()
        limpar()
        if copia is None:
            log.unlink(missing_ok=True)
        else:
            log.write_bytes(copia)
    print(f"\n== {titulo}")
    print(f"limite de chaves ({VAGAS} vagas): respostas {dict(limite_resultado)}, "
          f"chaves criadas: {criadas}")
    print(f"log de auditoria: cadeia {'ÍNTEGRA' if cadeia[0] else 'QUEBRADA'}")


def experimento_workers():
    testar_workers("2 workers, travas só em memória", {"TRAVA_SO_EM_MEMORIA": "1"})
    testar_workers("2 workers, travas de arquivo", {})


EXPERIMENTOS = {"hsm": experimento_hsm, "workers": experimento_workers}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in EXPERIMENTOS:
        print("Uso: python src/experimentos.py hsm | workers")
        sys.exit(1)
    EXPERIMENTOS[sys.argv[1]]()