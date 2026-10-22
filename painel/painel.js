async function atualizar() {
  try {
    const resposta = await fetch("/monitoramento");
    if (!resposta.ok) {
      throw new Error("Resposta com erro: " + resposta.status);
    }
    const dados = await resposta.json();

    const emUso = dados.chaves_em_uso;
    const limite = dados.limite_chaves;
    const chaves = document.getElementById("chaves");
    const aviso = document.getElementById("aviso-limite");

    chaves.textContent = emUso + " / " + limite;

    if (emUso > limite) {
      chaves.style.color = "red";
      chaves.style.fontWeight = "bold";
      aviso.textContent = "⚠ Limite excedido em " + (emUso - limite) + " chave(s). Novas criações retornam 409.";
    } else if (emUso === limite) {
      chaves.style.color = "darkorange";
      chaves.style.fontWeight = "bold";
      aviso.textContent = "Limite atingido. Novas criações retornam 409.";
    } else {
      chaves.style.color = "";
      chaves.style.fontWeight = "";
      aviso.textContent = "";
    }

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