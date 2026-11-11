# E13 – Exportação do log de auditoria em CSV

Mini API de criptografia (FastAPI + SoftHSM) · Decisões, testes e limites conhecidos · 11/11/2026

## 1. O que foi implementado

Rota `GET /auditoria/exportar` que devolve o log de auditoria como arquivo CSV, em **streaming** (não carrega o log todo na memória).

| Parâmetro | Significado |
|---|---|
| `de` | Data inicial (`AAAA-MM-DD`), inclusive |
| `ate` | Data final (`AAAA-MM-DD`), inclusive |
| `operacao` | Só linhas dessa operação (igualdade exata) |

Sem parâmetros, exporta tudo. O arquivo se chama `auditoria_{de|inicio}_{ate|fim}.csv`.

### Cabeçalho do arquivo

Antes das linhas de dados, vêm linhas de comentário com `#`:

- `exportado_por`, `exportado_em`
- `periodo` e `filtro_operacao`
- `total_linhas` (linhas exportadas) e `total_no_log_na_exportacao`
- `cadeia_de_hash`: `INTEGRA` ou `QUEBRADA na linha N`

Depois vem a linha de colunas: `quando, autor, operacao, recurso, sucesso, erro, hash_anterior, hash`.

## 2. Decisões tomadas

### 2.1 Filtro de data é por dia em UTC

O log guarda `quando` em UTC e o filtro compara só o dia (`quando[:10]`), com início e fim **inclusivos**. No Brasil (UTC−3), um evento às 22h de 10/11 aparece como dia 11 no log. `de` maior que `ate` ou data inválida devolve **422**.

### 2.2 Streaming e duas passadas

O cabeçalho precisa do total de linhas antes das linhas. Por isso o arquivo é lido em duas passadas: a 1ª conta as linhas do filtro e verifica a cadeia; a 2ª escreve as linhas. Um "tamanho em bytes" fixado no início, sob a trava do log, garante que as duas passadas veem o mesmo conteúdo mesmo se entrarem eventos novos durante a exportação.

### 2.3 A exportação também é auditada

Cada exportação registra `exportar_auditoria` no log (com `de`, `ate`, `operacao` e número de linhas). O evento é registrado **depois** da 1ª passada e **antes** da escrita, então o próprio evento não entra no arquivo exportado, mas aparece no `total_no_log_na_exportacao`.

### 2.4 Cadeia quebrada: exporta e avisa

Se a cadeia de hash estiver quebrada, o arquivo é exportado mesmo assim e o cabeçalho declara `QUEBRADA na linha N`. Recusar a exportação esconderia justamente a evidência que a pessoa precisa investigar.

### 2.5 Proteção contra injeção de fórmula

Campos que começam com `=`, `+`, `-`, `@`, tab ou retorno de linha recebem um `'` na frente, para o Excel não executar o conteúdo como fórmula.

### 2.6 Memória

Comparação de ler o log inteiro × linha a linha, medida em processos separados: veja `docs/medicao-memoria-export.md`. Resumo: linha a linha usou cerca de 38 MB, contra 127–571 MB lendo tudo (cresce com o tamanho do log).

## 3. Testes

Os testes de exportação ficam em `tests/test_auditoria.py` (23 testes no arquivo, junto com os da cadeia de hash). A suíte completa tem **143 testes passando**.

## 4. Limites conhecidos

- A rota **não tem autenticação** (a API não tem login ainda): qualquer um que alcance a API baixa o log.
- O filtro de dia é em UTC, não em horário de Brasília.
- Em uma medição, a exportação pela rota levou cerca de 18 s contra cerca de 5 s no script de teste; a causa ainda não foi investigada.