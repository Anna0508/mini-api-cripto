async function atualizar() {
  try {
    const resposta = await fetch("/monitoramento");
    if (!resposta.ok) {
      throw new Error("Resposta com erro: " + resposta.status);
    }
    const dados = await resposta.json();

    document.getElementById("chaves").textContent = dados.total_de_chaves;
    document.getElementById("operacoes").textContent = dados.total_operacoes;
    document.getElementById("disco").textContent = dados.bytes_em_disco_legivel;
    document.getElementById("tempo").textContent = dados.tempo_no_ar_legivel;

    document.getElementById("hora").textContent = new Date().toLocaleTimeString("pt-BR");
    document.getElementById("status").textContent = "";
  } catch (erro) {
    document.getElementById("status").textContent = "⚠ Conexão perdida com a API. Os números abaixo podem estar desatualizados.";
  }
}

atualizar();
setInterval(atualizar, 5000);