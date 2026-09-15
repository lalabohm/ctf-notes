# Guia de Comandos — CTF Pink Hat
### Referência estruturada por cenário (baseado nas cartilhas oficiais)

Formato: **fluxo Boot2Root** → Reconhecimento → Enumeração → Exploração → Acesso → Enumeração local → Escalação de privilégios → Root/Flag.

---

## 1. Reconhecimento (descobrir o que existe)

### `nmap` — mapear portas e serviços
| Cenário | Comando | Explicação |
|---|---|---|
| Primeiro contato com o alvo | `nmap -sC -sV <TARGET_IP>` | Scan rápido nas portas mais comuns, com scripts padrão (`-sC`) e detecção de versão de serviço (`-sV`) |
| Garantir que nenhuma porta ficou de fora | `nmap -p- --min-rate 1000 -T4 <TARGET_IP>` | Varre as 65.535 portas TCP. `-T4` acelera o scan, `--min-rate` evita que fique lento demais |
| Depois de identificar as portas certas | `nmap -sC -sV -p <PORTAS> <TARGET_IP>` | Foca só nas portas encontradas para extrair detalhes (banners, versões) |
| Guardar o resultado para consulta | `nmap -sC -sV -oN scan.txt <TARGET_IP>` | `-oN` salva a saída em arquivo texto; depois `cat scan.txt` ou `less scan.txt` |

**Quando usar:** sempre no início de qualquer máquina nova. É o passo 1 do "kit de emergência".

---

## 2. Web — investigar aplicações HTTP/HTTPS

### `curl` — requisições HTTP via terminal
| Cenário | Comando | Explicação |
|---|---|---|
| Ver só os headers de resposta | `curl -I http://<TARGET_IP>` | Não baixa o corpo da página, só os headers — rápido para identificar servidor/tecnologia |
| Ver requisição e resposta completas | `curl -v http://<TARGET_IP>` | Modo verboso: mostra request e response inteiros, útil para debugging |
| Seguir redirecionamentos (301/302) | `curl -L http://<TARGET_IP>` | Sem `-L`, o cURL para no redirect e não mostra o destino final |
| Checar só o status code | `curl -o /dev/null -s -w "%{http_code}\n" http://<DOMAIN>` | Descarta o corpo (`-o /dev/null`), silencia progresso (`-s`) e imprime só o código (200, 403, 404...) |
| Aplicação depende de hostname/vhost | `curl -H "Host: <DOMAIN>" http://<TARGET_IP>` | Simula o header Host sem precisar editar `/etc/hosts` — útil pra testar vhosts rápido |
| Enviar múltiplos headers custom | `curl -H "X-Test: valor" -H "Accept: application/json" http://<TARGET_IP>` | Útil para testar comportamento de APIs a headers específicos |
| Testar login/formulário (POST) | `curl -X POST -d "username=x&password=y" http://<TARGET_IP>/login` | Envia dados como formulário HTML tradicional |
| Testar API JSON | `curl -X POST -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1"}' http://<TARGET_IP>/api` | Formato comum para testar SSRF e endpoints de API |
| Baixar/salvar resposta | `curl http://<TARGET_IP>/arquivo.txt -o arquivo.txt` ou `curl -O http://<TARGET_IP>/arquivo.txt` | `-O` usa o nome original do arquivo remoto |

**Quando usar:** toda vez que a porta 80/443/8080 aparecer no nmap. Também serve para testar SSRF, APIs internas e comportamento de redirecionamento.

### Checklist manual de reconhecimento web (via navegador também)
Verificar: código-fonte HTML, comentários, JavaScript, `robots.txt`, endpoints, parâmetros de URL, cookies, headers, arquivos esquecidos, funcionalidades que recebem URLs (possível SSRF).

---

## 3. Download de arquivos

| Cenário | Comando | Explicação |
|---|---|---|
| Baixar um arquivo específico | `wget http://<TARGET_IP>/<FILE>` | Alternativa ao cURL, focada em download |
| Salvar com outro nome | `wget http://<TARGET_IP>/<FILE> -O arquivo-local` | `-O` maiúsculo define o nome de saída |

**Quando usar:** quando encontrar um arquivo exposto (config, backup) via enumeração web ou diretório.

---

## 4. Acesso remoto

### `ssh` — acesso via shell remota
| Cenário | Comando | Explicação |
|---|---|---|
| Login com usuário/senha | `ssh <USER>@<TARGET_IP>` | Pede senha interativamente; usar quando já tem credencial válida |
| Porta SSH não-padrão | `ssh <USER>@<TARGET_IP> -p <PORT>` | Necessário se o nmap mostrou SSH em porta diferente de 22 |
| Login com chave privada | `ssh -i id_rsa <USER>@<TARGET_IP>` | Usado quando você encontrou uma chave SSH (ex: em `/home`, backup, git) |
| Chave com permissão errada | `chmod 600 id_rsa` seguido do comando acima | SSH recusa chaves com permissão aberta demais (erro "UNPROTECTED PRIVATE KEY") |

**Quando usar:** depois de obter uma credencial (senha ou chave) via exploração web/serviço.

---

## 5. Navegação e identificação — primeira coisa a fazer após obter shell

| Cenário | Comando | Explicação |
|---|---|---|
| Quem eu sou | `whoami` | Nome do usuário atual |
| Identidade completa | `id` | Mostra UID, GID e grupos — revela se está em grupos privilegiados (ex: `docker`, `sudo`, `adm`) |
| Grupos apenas | `groups` | Só a lista de grupos |
| Onde estou | `pwd` | Diretório atual |
| O que tem aqui | `ls` / `ls -l` / `ls -la` | `-l` mostra permissões e dono; `-la` inclui arquivos ocultos (começam com `.`) |
| Navegar | `cd <DIRETORIO>` / `cd ..` | Entrar/voltar de diretório |
| Sistema operacional | `uname -a` e `cat /etc/os-release` | Versão do kernel e da distro — importante para buscar exploits de kernel conhecidos |
| Nome da máquina | `hostname` | Às vezes revela contexto (nome do desafio, domínio) |

**Quando usar:** sempre logo após obter qualquer tipo de acesso (shell reversa, SSH, RCE).

---

## 6. Busca — encontrar informação escondida

### `grep` — buscar texto dentro de arquivos
| Cenário | Comando | Explicação |
|---|---|---|
| Buscar palavra em um arquivo | `grep "password" arquivo.txt` | Busca literal, sensível a maiúsculas/minúsculas |
| Ignorar maiúsculas/minúsculas | `grep -i "password" arquivo.txt` | Encontra `password`, `Password`, `PASSWORD` |
| Mostrar número da linha | `grep -n "password" arquivo.txt` | Útil para depois abrir o arquivo direto na linha certa |
| Buscar recursivamente em diretório | `grep -Ri "password" /var/www 2>/dev/null` | `-R` percorre subdiretórios; combine com termos como `secret`, `token`, `user` |
| Filtrar saída de outro comando | `ps aux \| grep root` | `grep` não serve só para arquivos — funciona em pipe com qualquer saída |

### `find` — localizar arquivos/diretórios no sistema
| Cenário | Comando | Explicação |
|---|---|---|
| Achar arquivo pelo nome exato | `find / -name "user.txt" 2>/dev/null` | Clássico para achar a flag em máquinas Boot2Root |
| Busca case-insensitive | `find / -iname "config*" 2>/dev/null` | Útil quando não se sabe a capitalização exata |
| Buscar por extensão | `find / -name "*.conf" 2>/dev/null` | Encontra todos os arquivos de configuração |
| Arquivos de um usuário específico | `find / -user <USER> 2>/dev/null` | Revela o que pertence a outro usuário do sistema |
| Arquivos graváveis (possível abuso) | `find / -writable -type f 2>/dev/null` | Pode gerar muita saída — prefira escopar por diretório: `find /opt -writable -type f 2>/dev/null` |

**Nota importante:** `2>/dev/null` redireciona mensagens de erro (ex: "Permission denied") para lixo, deixando só resultado útil no terminal.

**Quando usar:** depois de ter uma shell, para localizar a flag, credenciais deixadas em arquivos, ou configs sensíveis.

---

## 7. Enumeração local — processos e rede

| Cenário | Comando | Explicação |
|---|---|---|
| Ver processos rodando | `ps aux` | Revela serviços, scripts, o que está rodando como root |
| Filtrar processos | `ps aux \| grep root` ou `\| grep python` | Focar em processos de interesse |
| Portas escutando localmente | `ss -tulnp` | Mostra serviços internos que talvez não apareçam no nmap externo (ex: `127.0.0.1:9000` só acessível de dentro da máquina) |
| Interfaces de rede | `ip addr` (ou `ip a`) | IPs configurados na máquina comprometida |
| Rotas de rede | `ip route` | Pode revelar outras redes/segmentos alcançáveis a partir dali (pivoting) |
| Testar conexão TCP a um serviço interno | `nc -nv <TARGET_IP> <PORT>` | Netcat para verificar se uma porta local está de fato acessível |
| Variáveis de ambiente | `env` ou `printenv` | Pode conter credenciais deixadas por engano; filtrar com `env \| grep -i password` |

**Quando usar:** logo após `whoami`/`id`, como parte do checklist "após obter shell" — mesmo sem saber ainda se há vulnerabilidade, é informação que pode virar pista depois.

---

## 8. Escalação de privilégios

| Cenário | Comando | Explicação |
|---|---|---|
| Primeiro teste sempre | `sudo -l` | Lista o que o usuário atual pode rodar como root via sudo. Se aparecer `NOPASSWD: /usr/bin/algo`, busque esse binário no **GTFOBins** |
| Buscar binários SUID | `find / -perm -4000 -type f 2>/dev/null` | Binários com bit SUID rodam com o dono do arquivo (frequentemente root), mesmo executados por outro usuário. Procure por binários incomuns ou fora do padrão |
| Buscar Linux Capabilities | `getcap -r / 2>/dev/null` | Capabilities dão privilégios específicos (ex: `cap_setuid+ep`) sem precisar de SUID completo — também consultável no GTFOBins |
| Confirmar escalação | `id` ou `whoami` | Se o resultado virar `root`, a escalação funcionou |

**Perguntas a fazer para cada achado de `sudo -l`, SUID ou capability:**
- Qual programa pode ser executado?
- Roda como root?
- Exige senha?
- Permite executar comandos arbitrários ou ler/escrever arquivos?
- Existe técnica documentada no GTFOBins?

**Quando usar:** depois de conseguir shell como usuário comum — é a etapa entre "acesso inicial" e "root".

---

## 9. Transferência de arquivos entre sua máquina e o alvo

| Cenário | Comando | Explicação |
|---|---|---|
| Servir arquivos da sua máquina | `python3 -m http.server 8000` | Sobe um servidor HTTP simples no diretório atual, porta 8000 |
| Baixar no alvo (via wget) | `wget http://<LOCAL_IP>:8000/<FILE>` | Puxa o arquivo do seu servidor local para dentro da máquina alvo |
| Baixar no alvo (via curl) | `curl -O http://<LOCAL_IP>:8000/<FILE>` | Alternativa ao wget |
| Enviar arquivo via SSH | `scp <FILE> <USER>@<TARGET_IP>:/tmp/` | Útil quando já tem acesso SSH e quer subir um script/ferramenta |

**Quando usar:** quando precisa levar uma ferramenta (script de exploit, linpeas, etc.) para dentro da máquina comprometida, ou trazer um arquivo de lá para análise local.

---

## 10. Rede/DNS — quando a aplicação depende de domínio

| Cenário | Comando | Explicação |
|---|---|---|
| Mapear IP → domínio manualmente | `echo "<IP> <DOMAIN>" \| sudo tee -a /etc/hosts` | Adiciona entrada ao `/etc/hosts` para que seu navegador/terminal resolva o domínio corretamente, mesmo sem DNS real |
| Testar depois de mapear | `curl http://ada.archive.axiom` | Acessa normalmente pelo nome, como se fosse um domínio real |

**Quando usar:** quando um header, certificado ou resposta HTTP menciona um hostname que não resolve — comum em labs que simulam ambientes corporativos.

---

## 11. Permissões de arquivo (Linux)

| Cenário | Comando | Explicação |
|---|---|---|
| Ver permissões | `ls -l` | Mostra dono, grupo e permissões (`rwx`) de cada arquivo |
| Tornar executável | `chmod +x script.sh` | Adiciona permissão de execução |
| Definir permissão exata | `chmod 755 script.sh` | 7=rwx (dono), 5=r-x (grupo), 5=r-x (outros) |

**Quando usar:** ao subir um script para a máquina alvo e ele não rodar por falta de permissão de execução.

---

## 12. Mencionados na cartilha 1 (não detalhados na cartilha 2) — vale revisar à parte

- **gobuster** — enumeração de diretórios/subdomínios web por força bruta com wordlist (ex: `gobuster dir -u http://<TARGET_IP> -w <WORDLIST>`)
- **smbclient** — enumeração e acesso a compartilhamentos SMB/Windows (ex: `smbclient -L //<TARGET_IP>/ -N`)
- **Base64 / hashes / cifra de César** — decodificação básica, útil em arquivos encontrados via `find`/`grep`

---

## Tabela-relâmpago (cola rápida)

| Objetivo | Comando |
|---|---|
| Scan inicial | `nmap -sC -sV <TARGET_IP>` |
| Todas as portas | `nmap -p- --min-rate 1000 -T4 <TARGET_IP>` |
| Headers HTTP | `curl -I http://<TARGET_IP>` |
| Seguir redirect | `curl -L http://<TARGET_IP>` |
| Download | `wget http://<TARGET_IP>/<FILE>` |
| SSH | `ssh <USER>@<TARGET_IP>` |
| Usuário atual | `id` |
| Buscar texto | `grep -Ri "texto" .` |
| Buscar arquivo | `find / -name "<FILE>" 2>/dev/null` |
| Ver sudo | `sudo -l` |
| Buscar SUID | `find / -perm -4000 -type f 2>/dev/null` |
| Capabilities | `getcap -r / 2>/dev/null` |
| Processos | `ps aux` |
| Portas locais | `ss -tulnp` |
| Servidor HTTP local | `python3 -m http.server 8000` |

---

## Fluxo mental para cada máquina (resumo estratégico)

```
Nmap → Enumeração de serviço (web/SMB/etc) → Arquivo/credencial interessante
   → Acesso (SSH/RCE) → Enumeração local (id, sudo -l, SUID, capabilities, ps, ss)
   → Escalação de privilégio → root → flag
```

Regra de ouro da cartilha: **não pule a enumeração** — a informação para avançar geralmente já está no sistema, o desafio é encontrá-la.
