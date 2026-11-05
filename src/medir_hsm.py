import statistics
import threading
import time

import hsm

LABEL = "medicao-hsm"
OPERACOES = 30
RODADAS = 5


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


def main():
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
    print(f"1 usuário  : {t1:.3f} s  ({OPERACOES} assinaturas)")
    print(f"2 usuários : {t2:.3f} s  ({OPERACOES} assinaturas cada)")
    print(f"proporção  : {t2 / t1:.2f}x")


if __name__ == "__main__":
    main()