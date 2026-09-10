# Escalação de Privilégios em Linux — Teoria e Como Aparece em CTF

> Complementa o [guia prático de comandos](cheatsheets/privesc_linux.md) — aqui o foco é **entender o porquê** de cada mecanismo, e como isso se traduz no design de desafios Boot2Root.

---

## Parte 1 — Os conceitos

### 1.1 Por que escalação de privilégio existe

No Linux, todo processo roda com a identidade de um usuário (**UID**) e um ou mais grupos (**GID**). O kernel decide o que esse processo pode fazer — ler um arquivo, abrir uma porta, matar outro processo — baseado nessa identidade. O usuário `root` tem UID `0` e ignora praticamente todas as checagens de permissão: é o "super usuário".

**Escalação de privilégio** é, na prática, encontrar um jeito de fazer um processo (uma shell, um script) **trocar sua identidade efetiva** de um usuário comum para root, sem ter a senha de root diretamente. Em nenhum dos mecanismos abaixo você está "quebrando" o sistema tecnicamente — está usando um privilégio legítimo, concedido para uma tarefa específica, de um jeito mais amplo do que o administrador pretendia.

---

### 1.2 SUID (Set User ID)

**O problema que resolve:** o comando `passwd` precisa escrever em `/etc/shadow`, que só root pode editar. Mas qualquer usuário comum precisa poder trocar a própria senha. Como resolver isso sem dar root ao usuário o tempo todo?

**A solução:** o bit **SUID** é uma permissão especial em um **arquivo executável**. Quando marcado, o processo não roda com o UID de quem o executou — roda com o UID **do dono do arquivo**.

```
-rwsr-xr-x 1 root root 55000 /usr/bin/passwd
     ↑
   o 's' no lugar do 'x' do dono = bit SUID ativo
```

Quando um usuário comum (UID 1000) executa `/usr/bin/passwd`, o processo roda com UID `0` (root) — porque o *dono do arquivo* é root. Depois que o processo termina, os comandos seguintes do usuário voltam ao normal. É um "empréstimo de identidade" só durante a execução daquele binário.

**Onde mora a vulnerabilidade:** `passwd` foi escrito com cuidado para só fazer uma coisa específica, mesmo rodando como root. Mas se alguém coloca SUID num binário **genérico** — `find`, `vim`, `python`, um script customizado — esse binário agora tem poder de root para **qualquer coisa que seja capaz de fazer**, não só a tarefa pretendida. `find` sabe executar comandos arbitrários (`-exec`); se tem SUID, abrir um shell root vira trivial.

---

### 1.3 SGID (Set Group ID)

Mesma lógica do SUID, mas herda o **grupo** do dono do arquivo, não o usuário:

```
-rwxr-sr-x 1 root shadow  arquivo
        ↑
      SGID
```

Geralmente menos poderoso que SUID (grupos costumam ter menos privilégio que root direto), mas se o grupo em questão é privilegiado (ex: grupo `shadow`, que pode ler `/etc/shadow`), ainda vale a pena investigar.

---

### 1.4 Linux Capabilities

**O problema que resolve:** SUID é "tudo ou nada" — o processo vira root completo. Isso é um martelo grande demais para a maioria dos casos. Se um binário só precisa de **uma** permissão específica de root (ex: "abrir portas abaixo de 1024"), dar root inteiro é desnecessariamente perigoso.

**A solução:** capabilities quebram o poder de "ser root" em **pedaços menores e nomeados**, atribuídos a um binário específico:

```bash
setcap cap_net_bind_service+ep /usr/bin/meu-servidor
```

**Capabilities perigosas para privesc:**
- **`cap_setuid`** — o processo pode chamar `setuid(0)` e virar root a qualquer momento
- **`cap_dac_override`** / **`cap_dac_read_search`** — ignora checagem de permissão de arquivo (lê/escreve qualquer coisa, inclusive `/etc/shadow`)
- **`cap_sys_admin`** — quase um "root genérico" para operações administrativas

---

### 1.5 sudo -l

Diferente dos anteriores, isso não é sobre um bit no arquivo — é sobre uma **regra de configuração** (`/etc/sudoers`) dizendo "o usuário X pode rodar o binário Y como root, sem senha".

```
User ada may run: (root) NOPASSWD: /usr/bin/find
```

A exploração segue a mesma ideia (abusar de uma função do binário que sai do escopo pretendido), mas o mecanismo de concessão é uma **regra explícita**, não uma propriedade do arquivo.

---

### 1.6 Por que o GTFOBins existe

Memorizar "esse binário X, com SUID, dá shell root assim" para centenas de binários é inviável. O **[GTFOBins](https://gtfobins.github.io)** é um catálogo curado: você acha o binário lá, e ele já indica o payload certo para cada contexto (SUID, sudo, capabilities). É basicamente um dicionário de "função inesperada que esse binário tem".

---

### 1.7 Resumo dos mecanismos

| Mecanismo | O que é | Onde mora o poder |
|---|---|---|
| **SUID** | Bit no arquivo que faz o processo rodar com UID do dono | No dono do arquivo (geralmente root) |
| **SGID** | Igual ao SUID, mas para o grupo | No grupo do arquivo |
| **Capabilities** | Fatias granulares do poder de root | Na capability específica concedida |
| **sudo -l** | Regra de configuração sobre o que rodar como root | Na regra do `/etc/sudoers` |

---

## Parte 2 — Como isso aparece em desafios CTF

### 2.1 O vetor quase nunca é "puro" — é uma cadeia

Uma máquina Boot2Root raramente é "ache o SUID e pronto". O padrão típico de progressão:

```
Vulnerabilidade Web → shell como www-data (usuário de serviço, quase sem privilégio)
    ↓
Enumeração local → encontra algo que www-data pode usar
    ↓
Vira um segundo usuário "de verdade" (ex: "ada")
    ↓
Enumeração de novo → agora como "ada", encontra o vetor de root
    ↓
root
```

Ou seja: normalmente você escala privilégio **duas vezes** — uma para sair de um usuário de serviço quase sem poder nenhum, e outra para chegar em root. É por isso que o checklist de enumeração se repete a cada shell nova.

---

### 2.2 Como o desafio "planta" um vetor de SUID/sudo/capability

O criador do CTF normalmente faz um dos dois:

**a) Customiza mal um binário legítimo.** Ex: um script de backup que roda como root via SUID, mas chama comandos internos sem path absoluto → possibilita PATH hijacking. Simula um erro real de configuração de sistema.

**b) Deixa um binário conhecido (do GTFOBins) com SUID/sudo "por engano".** Ex: `find` ou `python3` marcado com SUID. Mais didático — testa se você sabe consultar o GTFOBins e reconhecer o padrão.

Em CTFs de nível iniciante/intermediário (tom didático, como parece ser o caso do Pink Hat), espere mais o caso (b) — binários conhecidos, exploração direta via consulta ao GTFOBins.

---

### 2.3 O nome do binário/arquivo costuma ser a pista

Designers de CTF batizam as coisas de forma que sinaliza a intenção:

| O que você encontra | O que provavelmente é |
|---|---|
| SUID em binário com nome customizado (`backup`, `check_status`, `report_gen`) | Script/binário próprio — vale rodar `strings`, procurar PATH hijacking ou lógica falha |
| SUID em binário padrão do sistema (`find`, `vim`, `less`, `python3`, `nmap`) | GTFOBins puro — consultar direto |
| Cron chamando `.sh` num diretório gravável | Wildcard injection ou edição direta do script |

---

### 2.4 A restrição de tempo muda a estratégia de enumeração

Numa prova de 3h (como o Pink Hat), não há tempo de rodar scripts de automação e ler tudo manualmente também. O fluxo prático costuma ser:

```
1. sudo -l, find SUID, getcap  → ~2 minutos, sempre primeiro (rápido e barato)
2. Achou algo? → GTFOBins imediatamente, não tenta "descobrir sozinho" do zero
3. Nada óbvio? → rodar script de enumeração automatizada (ex: linpeas) para não perder tempo manualmente
4. Ler a saída procurando só o que está destacado como suspeito
```

A filosofia repetida nas cartilhas do evento — "pense em cadeia", "não procure apenas vulnerabilidades" — reflete exatamente isso: o vetor de privesc muitas vezes já apareceu como **pista** durante a fase de reconhecimento inicial (ex: um cron job estranho visto via LFI antes mesmo de ter shell) e só faz sentido quando cruzado com o acesso local.

---

### 2.5 Convenção de flags (dupla flag)

CTFs no estilo HackTheBox/TryHackMe costumam ter **duas flags por máquina**:

```
/home/<usuario>/user.txt    → flag de acesso inicial (comprometeu a aplicação)
/root/root.txt               → flag de privesc completo (chegou em root)
```

**Implicação prática:** vale sempre pegar a primeira flag assim que tiver qualquer shell, antes de gastar o resto do tempo tentando chegar em root — garante pontuação parcial mesmo que o privesc não feche.

---

### 2.6 Por que privesc costuma travar mais por disciplina do que por técnica

Em CTF, diferente de um pentest real, **o vetor foi colocado ali de propósito** — não é sorte achar, é questão de rodar o checklist certo. Quem trava em privesc geralmente não é por falta de conhecimento técnico avançado, mas por:

- Não ter enumerado uma das ~8 frentes (sudo, SUID, capabilities, cron, arquivos graváveis, variáveis de ambiente, credenciais espalhadas, kernel)
- Tentar um exploit complexo (kernel exploit, buffer overflow customizado) enquanto a resposta simples (`sudo -l` que nem rodou) já estava disponível
- Não repetir a enumeração depois de virar um segundo usuário intermediário

**Resumo prático:** em CTF, escalação de privilégio é menos sobre "quebrar" algo sofisticado e mais sobre seguir um checklist disciplinado até bater com uma configuração mal feita colocada ali de propósito. A técnica (SUID, GTFOBins, capabilities) é o vocabulário; a disciplina de enumeração completa, sem pular etapa, é o que decide se você chega em root dentro do tempo de prova.
