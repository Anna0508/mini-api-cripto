
1. O que implementei

Tempo no ar. A rota informa há quanto tempo a API está no ar, em segundos (tempo_no_ar) e em formato legível (tempo_no_ar_legivel). O valor vem de tempo_no_ar(), em metricas.py.

Operações. A rota informa quantas requisições a API recebeu (total_operacoes) e quantas foram para cada rota (operacoes_por_rota). A contagem é feita por um middleware no main.py, que registra cada requisição antes de ela ser processada. Por isso a própria /monitoramento entra na contagem.

Chaves em arquivo. A rota informa o total de chaves na pasta chaves (total_de_chaves) e o total separado por tipo: rsa_privada, rsa_publica e aes (chaves_por_tipo). Arquivos escondidos, como o .gitkeep, são ignorados. Um par RSA conta como duas chaves.

Disco e cofre. A rota informa quantos bytes a pasta chaves ocupa (bytes_em_disco), também em formato legível, como “8.51 KB” (bytes_em_disco_legivel). Informa ainda quantas chaves existem no cofre SoftHSM, por tipo (chaves_do_cofre), consultadas por hsm.listar_chaves().



2. O que não implementei e por quê

Histórico completo de operações
O contador fica na memória da API e zera ao reiniciar. No teste com docker compose restart api, ele recomeçou do zero. O requisito
 pede o histórico completo de operações, então isso não atende. Tipo de limitação: da mini API. Para resolver, seria preciso gravar as operações em arquivo ou banco. Escolhi só documentar.

Uso de memória
A rota não mede memória. O requisito pede “uso de memória e disco”, mas não diz memória de quê (do processo da API, do container, da máquina ou do HSM). Tipo de limitação: requisito não está claro.

Total de chaves e disco por partição
A mini API não tem partições. Ela tem uma pasta chaves e um token do SoftHSM. A rota mostra o total de chaves e o disco da pasta, mas não separa por partição. Tipo de limitação: requisito não está claro, e a mini API não tem esse conceito.

Tempo real ou intervalo máximo de 60 segundos
A rota calcula tudo no momento da consulta, então o valor é sempre atual. Mas ela não se atualiza sozinha e não avisa quando algo muda. Quem quiser acompanhar precisa consultar a rota de novo, porque ela não envia atualizações.
Espaço de uma chave no cofre
Medi um par RSA-2048:

Em arquivos .pem: 2155 bytes.
No token do SoftHSM: 3068 bytes, igual em duas execuções.

O cofre ocupou 913 bytes a mais, cerca de 42%. Os valores são tamanhos lógicos (st_size), não o espaço alocado no disco, que costuma ser maior por causa do tamanho de bloco. A diferença provavelmente vem de o cofre guardar o objeto completo, com seus atributos. Isso é uma hipótese, não verifiquei.

Não consegui descobrir o tamanho por chave nem o limite de armazenamento do HSM real da empresa. Essa informação depende do modelo e deve vir do fabricante ou do administrador. Tipo de limitação: do ambiente.




3 Decisões que tomei

Decisão 1: um par RSA conta como uma chave ou duas?

Escolhi contar como duas chaves, a privada e a pública separadas. Escolhi assim para englobar todo o conteúdo da pasta: cada arquivo de chave entra na contagem. Por isso chaves_por_tipo mostra rsa_privada e rsa_publica à parte, e gerar um par aumenta o total em 2. O teste confere esse aumento.

Consequência: se o requisito do HSM contar o par como uma chave só, o número da API fica o dobro do esperado para RSA.

Decisão 2: a /monitoramento conta a si mesma?

Escolhi que sim, ela conta. Fiz três chamadas em outra rota e depois chamei a /monitoramento: ela apareceu na própria contagem. Entendi que isso é comportamento correto, porque ela também é uma operação que a API atendeu. Para garantir isso, o middleware registra a operação antes de processar a requisição.

Consequência: a primeira consulta já mostra pelo menos 1 operação, mesmo com a API recém-iniciada.

Decisão 3: o que acontece com o contador quando a API reinicia?

O contador fica na memória e zera ao reiniciar. No teste, depois do docker compose restart api, o tempo no ar voltou para cerca de 10 segundos e o total de operações recomeçou. Isso não atende o requisito, que pede o histórico completo de operações. Escolhi só documentar a limitação, sem implementar persistência.

Consequência: depois de qualquer reinício, o histórico anterior se perde. Para resolver, seria preciso gravar as operações em arquivo ou banco.


4. Perguntas para quem escreveu o requisito

Pergunta 1: memória

O requisito pede “uso de memória e disco”. Na mini API, medi só o disco.

De qual memória você está falando: do processo da API, do container, da máquina ou do próprio HSM?

Pergunta 2: partição

O requisito pede “total de chaves por partição” e “disco por partição”. Na mini API, só existem uma pasta chaves e um token do SoftHSM.

Partição aqui é uma divisão lógica do cofre (por cliente ou por aplicação) ou uma partição física do disco?

Pergunta 3: tempo real

O requisito diz “tempo real ou intervalo máximo de 60 segundos”. Minha rota calcula tudo quando alguém a consulta, mas não se atualiza sozinha.

O painel pode ser só uma consulta sob demanda, ou precisa atualizar sozinho a cada 60 segundos? Se alguém consulta a cada 5 minutos, isso atende?

Pergunta 4: número de operações

O requisito pede “número de operações realizadas”. Na mini API, o contador zera quando a API reinicia.

“Operações realizadas” quer dizer desde que o sistema subiu ou o histórico completo? E operação é qualquer requisição ou só as de chave (gerar, assinar, cifrar)?

Pergunta 5: chaves

O requisito pede “número de chaves”. Na decisão 1, contei o par RSA como duas chaves.

No HSM oficial, um par RSA conta como uma chave ou duas?

Pergunta 6: tamanho no HSM real

Medi um par RSA-2048 no SoftHSM (3068 bytes) e em arquivo (2155 bytes). Não achei o limite de armazenamento do HSM real da empresa.

Qual é o tamanho por chave e o limite de armazenamento do modelo de HSM que vai ser usado, e quem pode me passar essa informação?

