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
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

LABEL = "medicao-hsm"
OPERACOES = 30
RODADAS = 10

PORTA = 8100
URL = f"http://127.0.0.1:{PORTA}"
PEDIDOS = 40
VAGAS = 5

TOKENS_TESTE = ["teste-seg-1", "teste-seg-2"]
RODADAS_SEG = 20
OPERACOES_SEG = 40
TEMPO_MAXIMO = 60


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


def criar_tokens_teste():
    for nome in TOKENS_TESTE:
        subprocess.run(
            ["softhsm2-util", "--init-token", "--free", "--label", nome,
             "--so-pin", "1234", "--pin", hsm.PIN],
            check=True, capture_output=True, timeout=30,
        )


def apagar_tokens_teste():
    for nome in TOKENS_TESTE:
        try:
            subprocess.run(
                ["softhsm2-util", "--delete-token", "--token", nome],
                capture_output=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            print(f"(não consegui apagar o cofre {nome}: travou)")


def cenario_cofres(modo, tokens):
    biblioteca = pkcs11.lib(hsm.CAMINHO_BIBLIOTECA)
    fila = threading.RLock()

    def abrir(nome):
        return biblioteca.get_token(token_label=nome).open(user_pin=hsm.PIN, rw=True)

    def assinar(nome):
        with abrir(nome) as sessao:
            chave = sessao.get_key(object_class=ObjectClass.PRIVATE_KEY, label="seg")
            chave.sign(b"x", mechanism=Mechanism.SHA256_RSA_PKCS)

    def trabalho(nome):
        for _ in range(OPERACOES_SEG):
            if modo == "com_fila":
                with fila:
                    assinar(nome)
            else:
                assinar(nome)

    for nome in set(tokens):
        with abrir(nome) as sessao:
            sessao.generate_keypair(
                KeyType.RSA, 2048, store=True, label="seg",
                private_template={Attribute.TOKEN: True, Attribute.PRIVATE: True,
                                  Attribute.SENSITIVE: True, Attribute.SIGN: True,
                                  Attribute.LABEL: "seg"},
                public_template={Attribute.TOKEN: True, Attribute.VERIFY: True,
                                 Attribute.LABEL: "seg"},
            )
    threads = [threading.Thread(target=trabalho, args=(nome,)) for nome in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def rodar_cenario(titulo, modo, tokens):
    resultados = collections.Counter()
    print(f"{titulo:<34}: ", end="", flush=True)
    for _ in range(RODADAS_SEG):
        apagar_tokens_teste()
        criar_tokens_teste()
        try:
            proc = subprocess.run(
                [sys.executable, __file__, "_cenario", modo, ",".join(tokens)],
                capture_output=True, timeout=TEMPO_MAXIMO,
            )
        except subprocess.TimeoutExpired:
            resultados["travou"] += 1
            print("T", end="", flush=True)
            continue
        if proc.returncode == 0:
            resultados["ok"] += 1
            print(".", end="", flush=True)
        elif proc.returncode < 0:
            resultados["Segmentation fault"] += 1
            print("X", end="", flush=True)
        else:
            resultados["outro erro"] += 1
            print("?", end="", flush=True)
    print(f" {dict(resultados)}")


def experimento_cofres():
    t1, t2 = TOKENS_TESTE
    try:
        rodar_cenario("mesmo cofre, sem fila", "sem_fila", [t1, t1])
        rodar_cenario("cofres diferentes, sem fila", "sem_fila", [t1, t2])
        rodar_cenario("cofres diferentes, com fila", "com_fila", [t1, t2])
    finally:
        apagar_tokens_teste()


EXPERIMENTOS = {
    "hsm": experimento_hsm,
    "workers": experimento_workers,
    "cofres": experimento_cofres,
}


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "_cenario":
        cenario_cofres(sys.argv[2], sys.argv[3].split(","))
    elif len(sys.argv) == 2 and sys.argv[1] in EXPERIMENTOS:
        EXPERIMENTOS[sys.argv[1]]()
    else:
        print("Uso: python src/experimentos.py hsm | workers | cofres")
        sys.exit(1)
