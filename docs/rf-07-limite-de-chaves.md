# RF-07 – Limite máximo de chaves

Mini API de criptografia (FastAPI + SoftHSM) · Decisões, testes e pontos em aberto · 22/10/2026

## 1. O que foi implementado

A API agora tem um limite máximo de chaves, configurável sem mexer no código.

- O limite vem da variável de ambiente `LIMITE_CHAVES`. Se ela não existir, o valor padrão é **50**.
- As rotas que criam chaves (`/chaves/rsa`, `/chaves/aes` e as do cofre) recusam a criação quando o limite é atingido.
- A rota `GET /monitoramento` mostra `limite_chaves` e `chaves_em_uso`.
- O painel mostra "em uso / limite" (por exemplo, `54 / 50`): laranja quando atinge o limite e vermelho com o excedente quando passa dele.
- O PIN do cofre saiu do `hsm.py` e agora vem de variável de ambiente (no container, pelo `docker-compose.yml`).
- A pasta de chaves foi unificada: `metricas.py` passou a usar `cripto.PASTA_CHAVES`.

## 2. Decisões tomadas

### 2.1 Status HTTP ao atingir o limite: 409 (Conflict)

O 507 (Insufficient Storage) foi descartado porque confunde com disco cheio. O 429 também foi descartado: ele fala de muitas requisições em pouco tempo, e aqui o problema não é a frequência.

O **409** foi escolhido porque o estado atual do sistema está cheio: o limite é uma quantidade total de chaves, e a nova chave entra em conflito com esse estado. Repetir a mesma requisição só funciona depois que alguém liberar espaço.

### 2.2 O que o limite conta: chaves lógicas

Um par RSA conta como **1 chave**, não como 2 arquivos.

**Motivo:** se o par contasse como 2, cada criação de RSA consumiria o limite em dobro, e o limite real seria metade do número configurado. Contando como 1, o número configurado é o número de chaves que o usuário enxerga.

O total em uso soma as chaves em arquivo e as chaves do cofre.

### 2.3 Limite já ultrapassado: só recusa, nunca apaga

Se o uso já está acima do limite (por exemplo, o limite foi reduzido depois, ou o uso é `54` e o limite é `50`), a API **recusa novas criações e mantém todas as chaves existentes**.

**Motivo:** apagar chaves automaticamente é irreversível e pode destruir uma chave que ainda está em uso. Quem deve decidir o que apagar é uma pessoa.

## 3. Testes

A suíte tem **36 testes passando**, e o `ruff` está limpo.

Os testes de fronteira cobrem os casos abaixo, e cada teste declara o próprio limite:

- abaixo do limite: a criação funciona (200);
- exatamente no limite: a criação é recusada (409), porque o critério é `>=`;
- acima do limite: a criação é recusada (409);
- `/monitoramento` expõe `limite_chaves` e `chaves_em_uso`;
- limite já ultrapassado: 409 e nada é apagado.

Para isolar os testes, o `conftest.py` (em `tests/`) tem as fixtures `ambiente` e `limite_alto`. Elas usam `monkeypatch` e `tmp_path`, então os testes **não escrevem mais na pasta real de chaves**.

## 4. TOCTOU: o que é e por que importa aqui

**TOCTOU** significa *time of check to time of use*: o intervalo entre **verificar** uma condição e **usar** o resultado dessa verificação.

### O problema, passo a passo

A criação de chave tem duas etapas separadas:

1. **Verificar:** `chaves_em_uso() < LIMITE_CHAVES`?
2. **Criar:** gerar a chave e gravar.

Imagine `LIMITE_CHAVES = 50` e 49 chaves em uso. Duas requisições chegam ao mesmo tempo:

1. A requisição A verifica: 49 < 50, pode criar.
2. A requisição B verifica: ainda 49 < 50, pode criar.
3. A cria a chave 50.
4. B cria a chave 51.

O limite foi ultrapassado, mesmo com a verificação correta em cada requisição. Cada verificação estava certa quando foi feita, mas ficou desatualizada antes de ser usada.

### Por que isso importa nesse caso

- O 409 só garante o limite se a verificação e a criação acontecerem como **uma única operação**.
- O excedente seria pequeno (poucas chaves), mas o limite deixaria de ser uma garantia e passaria a ser uma aproximação.
- Como o requisito não diz se o limite é rígido, esse comportamento precisa estar documentado.

### Como reduzir o risco

- **Trava (lock):** colocar a verificação e a criação dentro do mesmo `Lock`, para que só uma requisição por vez passe por esse trecho.
- **Vários processos:** se a API rodar com mais de um worker, uma trava em memória não basta, e seria preciso uma trava compartilhada (por exemplo, no arquivo ou no banco).
- **Verificar de novo depois de criar:** se o total passou do limite, desfazer a criação que acabou de acontecer.

> **Situação atual:** o código não tem trava (`Lock`) entre a verificação do limite e a criação da chave. Por isso, o TOCTOU é uma **limitação conhecida**: duas requisições simultâneas podem ultrapassar o limite em poucas chaves.

## 5. Limitações conhecidas

- O uso real está acima do limite (`54 / 50`) por causa de chaves de testes antigos (`chave_teste_*` na pasta `chaves/` e chaves de teste no cofre). A API continua respondendo 409 em toda criação até alguém liberar espaço. Esse é o comportamento esperado.
- O TOCTOU descrito na seção 4.
- O contador de operações do `/monitoramento` fica em memória e zera quando a API reinicia (decisão do RF-08, já documentada na página dele).
