import collections
import hashlib
import json
import os
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

import auditoria
import cripto
import hsm
import metricas
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from http.server import BaseHTTPRequestHandler, HTTPServer

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
TAMANHOS_LOG = [50_000, 150_000, 300_000]
OPERACOES_LOG = ["criar_chave", "assinar", "verificar", "cifrar"]
PORTA_RECEPTOR = 9000


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


def gerar_log_grande(caminho, linhas):
    """Cria um log de auditoria falso, mas com a cadeia de hash válida."""
    anterior = auditoria.HASH_INICIAL
    with open(caminho, "w") as f:
        for i in range(linhas):
            registro = {
                "quando": f"2026-11-{1 + i % 9:02d}T12:00:00+00:00",
                "autor": auditoria.AUTOR,
                "operacao": OPERACOES_LOG[i % 4],
                "recurso": f"chave{i}",
                "sucesso": True,
                "erro": None,
                "hash_anterior": anterior,
            }
            registro["hash"] = auditoria.calcular_hash(
                {k: v for k, v in registro.items() if k != "hash_anterior"}, anterior
            )
            anterior = registro["hash"]
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")


def exportar_tudo_na_memoria(destino, operacao):
    """O jeito ingênuo: carrega o log inteiro, monta o CSV inteiro e só então grava."""
    registros = [
        json.loads(linha) for linha in auditoria.caminho().read_text().splitlines()
    ]
    anterior = auditoria.HASH_INICIAL
    for r in registros:
        esperado = auditoria.calcular_hash(
            {k: v for k, v in r.items() if k not in ("hash", "hash_anterior")}, anterior
        )
        assert r["hash_anterior"] == anterior and r["hash"] == esperado
        anterior = r["hash"]
    filtrados = [
        r for r in registros if auditoria._passa_no_filtro(r, None, None, operacao)
    ]
    saida = [f"# total_linhas: {len(filtrados)}\n", auditoria._linha_csv(auditoria.COLUNAS)]
    for r in filtrados:
        saida.append(
            auditoria._linha_csv(
                [auditoria._proteger(r.get(c)) for c in auditoria.COLUNAS]
            )
        )
    Path(destino).write_text("".join(saida))


def exportar_linha_a_linha(destino, operacao):
    with open(destino, "w") as f:
        for parte in auditoria.exportar_csv(operacao=operacao):
            f.write(parte)


def medir_memoria(modo, caminho_log, destino, operacao):
    """Roda em um processo só dele, para o pico de memória não se misturar."""
    auditoria.caminho = lambda: Path(caminho_log)
    antes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    inicio = time.perf_counter()
    if modo == "inteiro":
        exportar_tudo_na_memoria(destino, operacao)
    else:
        exportar_linha_a_linha(destino, operacao)
    tempo = time.perf_counter() - inicio
    total = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    pico = total - antes
    # impressão digital das linhas de dados, para provar que os dois geram o mesmo CSV
    sha = hashlib.sha256()
    with open(destino) as f:
        for linha in f:
            if not linha.startswith("#"):
                sha.update(linha.encode())
    print(json.dumps({"tempo": tempo, "pico_mb": pico / 1024, "total_mb": total / 1024, "sha": sha.hexdigest()}))


def rodar_memoria(modo, original, pasta, operacao):
    trabalho = Path(pasta) / "copia.jsonl"
    shutil.copyfile(original, trabalho)  # cada rodada começa com o mesmo log
    saida = subprocess.run(
        [sys.executable, __file__, "_memoria", modo, str(trabalho),
         str(Path(pasta) / "saida.csv"), operacao or "-"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(saida.stdout.strip().splitlines()[-1])


def experimento_memoria():
    pasta = tempfile.mkdtemp(prefix="medicao-export-")
    original = Path(pasta) / "log.jsonl"
    try:
        print("| linhas | log (MB) | filtro | jeito | memória extra (MB) | memória total (MB) | tempo (s) |")
        print("|---:|---:|---|---|---:|---:|---:|")
        for linhas in TAMANHOS_LOG:
            gerar_log_grande(original, linhas)
            tamanho = original.stat().st_size / 1024 / 1024
            filtros = [None, "assinar"] if linhas == TAMANHOS_LOG[-1] else [None]
            for operacao in filtros:
                resultados = {}
                for modo in ("inteiro", "linha"):
                    resultados[modo] = rodar_memoria(modo, original, pasta, operacao)
                    r = resultados[modo]
                    nome = "arquivo inteiro" if modo == "inteiro" else "linha a linha"
                    print(
                        f"| {linhas:,} | {tamanho:.0f} | {operacao or 'nenhum'} | {nome} "
                        f"| {r['pico_mb']:.1f} | {r['total_mb']:.1f} | {r['tempo']:.1f} |"
                    )
                assert resultados["inteiro"]["sha"] == resultados["linha"]["sha"], (
                    "os dois jeitos geraram CSVs diferentes"
                )
        print("\nOs dois jeitos geraram exatamente as mesmas linhas de dados.")
    finally:
        shutil.rmtree(pasta, ignore_errors=True)

def receptor_alertas():
    """Destino de mentira dos alertas: só imprime o que recebe. Ctrl+C desliga."""

    class Receptor(BaseHTTPRequestHandler):
        def do_POST(self):
            corpo = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            print(f"ALERTA RECEBIDO: {corpo.decode()}", flush=True)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass  # sem o barulho padrão do servidor

    print(f"Receptor em http://0.0.0.0:{PORTA_RECEPTOR}  (Ctrl+C para desligar)", flush=True)
    HTTPServer(("0.0.0.0", PORTA_RECEPTOR), Receptor).serve_forever()

EXPERIMENTOS = {
    "hsm": experimento_hsm,
    "workers": experimento_workers,
    "cofres": experimento_cofres,
    "memoria": experimento_memoria,
    "receptor": receptor_alertas,
}


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "_memoria":
        medir_memoria(
            sys.argv[2], sys.argv[3], sys.argv[4],
            None if sys.argv[5] == "-" else sys.argv[5],
        )
    elif len(sys.argv) == 4 and sys.argv[1] == "_cenario":
        cenario_cofres(sys.argv[2], sys.argv[3].split(","))
    elif len(sys.argv) == 2 and sys.argv[1] in EXPERIMENTOS:
        EXPERIMENTOS[sys.argv[1]]()
    else:
        print("Uso: python src/experimentos.py hsm | workers | cofres | memoria | receptor")
        sys.exit(1)
