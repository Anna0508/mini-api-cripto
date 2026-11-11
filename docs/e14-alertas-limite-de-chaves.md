# E14 – Alertas de uso do limite de chaves

Mini API de criptografia (FastAPI + SoftHSM) · Decisões, testes e limites conhecidos · 11/11/2026

## 1. O que foi implementado

A API avisa um destino externo quando o uso de chaves chega a **50%** e a **100%** do limite (`LIMITE_CHAVES`).

- O aviso é enviado por HTTP `POST` com JSON para a URL da variável de ambiente `ALERTA_URL`.
- Se `ALERTA_URL` estiver vazia, os alertas ficam **desligados** (a API funciona normalmente).
- A verificação acontece **só quando uma chave é criada** (as 7 rotas de criação chamam `alertas.verificar()`).
- Cada envio e cada falha ficam registrados no log de auditoria.

### Exemplo do que o destino recebe

```json
{
  "evento": "limite_de_chaves",
  "nivel": "atencao",
  "percentual": 50.0,
  "em_uso": 5,
  "limite": 10,
  "quando": "2026-11-11T14:03:22+00:00"
}
```

`nivel` é `atencao` (50%) ou `critico` (100%).

## 2. Decisões tomadas

### 2.1 Qual é o denominador

O percentual é calculado assim:

**`metricas.chaves_em_uso()` ÷ `LIMITE_CHAVES`**

- Conta o **cofre inteiro**: chaves em arquivo + chaves no SoftHSM.
- Um par RSA conta como **1 chave** (mesma regra do RF-07).
- Chaves públicas **não** entram na conta.
- **Não é por usuário**: a API ainda não tem login, então não existe "chaves de um usuário".

### 2.2 Alerta na travessia, não no estado

O alerta é enviado quando o uso **cruza** o limite, e não toda vez que está acima dele. Se o sistema ficar em 60% por um mês, é **1 alerta**, não um por chave criada.

O estado fica guardado em `chaves/.alerta_estado.json` (gravação atômica, com trava de arquivo), então reiniciar a API não repete o alerta.

### 2.3 Histerese (evita alerta repetido na beira do limite)

Níveis: `ok` → `atencao` (≥ 50%) → `critico` (≥ 100%).

| Situação | O que acontece |
|---|---|
| Sobe de nível | Envia 1 alerta |
| Desce para menos de **40%** | Volta para `ok` (rearma o alerta de 50%) |
| Desce para menos de **90%** | `critico` volta para `atencao` (rearma o alerta de 100%) |
| Fica entre 40% e 50% | Quieto, sem alerta |
| Pula de 0% direto para 100% | Envia **1** alerta `critico` (não dois) |

Sem isso, quem cria e apaga uma chave perto de 50% receberia um alerta a cada vez.

### 2.4 Falha no envio nunca quebra a criação de chave

- O envio roda em uma **thread separada** (a resposta da API não espera o destino).
- Até **4 tentativas**, com espera de 1 s, 2 s e 4 s entre elas, e **2 s** de tempo limite por tentativa.
- Se as 4 falharem, registra `alerta_falhou` no log de auditoria e **desiste**: o alerta não é reenviado depois.
- Qualquer erro interno do módulo de alertas é capturado: `verificar()` nunca levanta exceção.
- A URL do destino **não** vai para o log (pode conter token).

### 2.5 Eventos no log de auditoria

| Operação | Quando |
|---|---|
| `alerta_enviado` | O destino recebeu (informa o nível e quantas tentativas foram precisas) |
| `alerta_falhou` | As 4 tentativas falharam (informa o erro) |
| `alerta_verificar` | Erro interno ao verificar |

## 3. Como testar na mão

1. No `docker-compose.yml`: `LIMITE_CHAVES=10` e `ALERTA_URL=http://127.0.0.1:9000/alerta`.
2. Em um terminal separado, suba o receptor mínimo (imprime o que recebe):
   `docker compose exec api python src/experimentos.py receptor`
3. Crie chaves até passar de 5 (50%) e depois até 10 (100%).
4. Teste o destino **desligado**: pare o receptor e crie chaves. A criação continua funcionando e o log mostra `alerta_falhou` com 4 tentativas.
5. Antes de uma nova rodada, apague `chaves/.alerta_estado.json` (senão o alerta não repete, por desenho).
6. Ao terminar, volte `LIMITE_CHAVES=50`.

## 4. Testes

A suíte tem **143 testes passando**; 28 são de alertas (`tests/test_alertas.py`): máquina de estados, não repetir em 1440 verificações seguidas, histerese, nova travessia, pulo para 100%, estado persistido, desligado sem URL, sucesso na 3ª tentativa, erro interno, URL fora do log, destino fora do ar sem quebrar a criação, destino lento sem segurar a resposta.

## 5. Limites conhecidos

- O alerta só é checado **ao criar chave**. Se o limite for reduzido ou chaves forem apagadas por fora da API, nada dispara até a próxima criação.
- Se as 4 tentativas falharem, ou o processo parar durante as tentativas, o alerta é **perdido** (não há fila nem reenvio).
- O limite é do cofre inteiro, não por usuário.
- O destino precisa aceitar `POST` com JSON; não há assinatura nem autenticação no envio.