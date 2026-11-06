import fcntl
import os
import tempfile
import threading
from pathlib import Path


class TravaDeArquivo:
    def __init__(self, nome: str):
        self.caminho = Path(tempfile.gettempdir()) / f"mini-api-{nome}.lock"
        self._thread = threading.RLock()
        self._nivel = 0
        self._arquivo = None
        self._usar_arquivo = not os.getenv("TRAVA_SO_EM_MEMORIA")

    def __enter__(self):
        self._thread.acquire()
        if self._nivel == 0 and self._usar_arquivo:
            self._arquivo = open(self.caminho, "w")
            fcntl.flock(self._arquivo, fcntl.LOCK_EX)
        self._nivel += 1
        return self

    def __exit__(self, *args):
        self._nivel -= 1
        if self._nivel == 0 and self._arquivo is not None:
            fcntl.flock(self._arquivo, fcntl.LOCK_UN)
            self._arquivo.close()
            self._arquivo = None
        self._thread.release()
        