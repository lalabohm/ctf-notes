# Guia de Identificação de Desafios — CTF
### Como descobrir rápido "o que é isso" antes de gastar tempo no caminho errado

Objetivo: em menos de 2-3 minutos de olhar pra um desafio/arquivo/porta, ter uma hipótese forte de categoria e primeiro comando a rodar — sem "tentar tudo às cegas".

---

## Índice
1. [Triagem por tipo de entrega (arquivo vs serviço vs URL)](#1-triagem-por-tipo-de-entrega)
2. [Identificar tipo de arquivo](#2-identificar-tipo-de-arquivo)
3. [Identificar categoria por porta/serviço (nmap)](#3-identificar-categoria-por-portaserviço)
4. [Sinais de que é Web](#4-sinais-de-que-é-web)
5. [Sinais de que é Criptografia](#5-sinais-de-que-é-criptografia)
6. [Sinais de que é Pwn / Binary Exploitation](#6-sinais-de-que-é-pwn--binary-exploitation)
7. [Sinais de que é Reverse Engineering](#7-sinais-de-que-é-reverse-engineering)
8. [Sinais de que é Forense](#8-sinais-de-que-é-forense)
9. [Sinais de que é Esteganografia](#9-sinais-de-que-é-esteganografia)
10. [Sinais de que é OSINT](#10-sinais-de-que-é-osint)
11. [Sinais de que é Boot2Root/Privesc (o mais provável no Pink Hat)](#11-sinais-de-que-é-boot2rootprivesc)
12. [Tabela-relâmpago de fingerprinting](#12-tabela-relâmpago-de-fingerprinting)
13. [Fluxograma de decisão](#13-fluxograma-de-decisão)

---

## 1. Triagem por tipo de entrega

A primeira pergunta nunca é "que vulnerabilidade é essa" — é **"que tipo de coisa eu recebi"**:

| O que você recebeu | Categoria provável |
|---|---|
| Um IP/hostname + porta pra conectar | Boot2Root, Web, Pwn (serviço de rede), Cripto (serviço) |
| Um arquivo binário (sem extensão, ou `.bin`, `.elf`) | Pwn ou Reverse |
| Uma URL apontando pra um site | Web |
| Uma imagem, áudio, vídeo, PDF | Forense ou Estego |
| Um arquivo `.pcap`/`.pcapng` | Forense de rede |
| Texto cifrado / números estranhos / Base64 longo | Criptografia |
| Um arquivo `.zip`/`.tar` protegido por senha | Forense (quebra de senha) ou pista pra outro desafio |
| Só um nome de usuário, foto, ou perfil social | OSINT |
| Um arquivo `.py`/`.c`/`.java` (código-fonte) | Cripto (analisar algoritmo) ou Pwn (analisar lógica vulnerável) |

---

## 2. Identificar tipo de arquivo

**Primeiro comando, sempre, pra qualquer arquivo desconhecido:**
```bash
file arquivo_desconhecido
```
Isso lê os **magic bytes** (assinatura no início do arquivo) e diz o tipo real — mesmo que a extensão tenha sido trocada de propósito (comum em forense/estego).

### Exemplos de saída e o que fazer
| Saída do `file` | Interpretação | Próximo passo |
|---|---|---|
| `ELF 64-bit LSB executable` | Binário Linux | Pwn ou Reverse → `checksec`, Ghidra |
| `PE32 executable` | Binário Windows | Reverse → Ghidra/IDA |
| `ASCII text` | Texto puro | Ler direto, provavelmente cripto ou pista |
| `Zip archive data` | Arquivo compactado | `unzip`, checar se tem senha |
| `PNG image data`, `JPEG image data` | Imagem | Estego → `exiftool`, `steghide`, `zsteg`, `binwalk` |
| `data` (genérico, sem reconhecer) | Formato desconhecido/customizado ou arquivo corrompido de propósito | `xxd arquivo \| head`, comparar magic bytes manualmente |
| `PDF document` | PDF | Forense → extrair metadados, texto oculto, `pdftotext`, `exiftool` |

### Ver os bytes brutos (quando `file` não identifica)
```bash
xxd arquivo | head -20
```
Compare o início com [assinaturas conhecidas](https://en.wikipedia.org/wiki/List_of_file_signatures) — arquivos de CTF às vezes têm o cabeçalho corrompido de propósito, e corrigir manualmente já é parte do desafio.

### Procurar arquivos escondidos dentro de outro arquivo
```bash
binwalk arquivo          # detecta arquivos embutidos (ex: zip dentro de uma imagem)
binwalk -e arquivo        # extrai automaticamente o que encontrar
strings arquivo | less    # texto legível embutido (flags, comentários, URLs)
```

---

## 3. Identificar categoria por porta/serviço

Depois do `nmap`, a **porta e o banner** já indicam a categoria provável:

```bash
nmap -sC -sV -p- <TARGET_IP>
```

| Porta/serviço | Categoria provável |
|---|---|
| 80, 443, 8080, 8000 (HTTP/HTTPS) | Web |
| 22 (SSH) já aberto de cara, sem outra porta | Ou você já tem credencial, ou é meio de acesso pós-explore de outro vetor |
| 21 (FTP) | Forense/recon — checar login anônimo, arquivos disponíveis |
| 445, 139 (SMB) | Enumeração Windows/Samba — `smbclient`, `enum4linux` |
| 25, 110, 143 (mail: SMTP/POP3/IMAP) | Menos comum em CTF didático, mas pode envolver enumeração de usuário |
| Porta alta customizada (ex: 1337, 31337, 4444) com banner estranho | Pwn — provavelmente um serviço binário feito pra exploração (`nc` direto na porta pra interagir) |
| 6379 (Redis), 3306 (MySQL), 5432 (PostgreSQL) | Serviço de banco exposto — testar acesso sem senha, ou é alvo de SSRF |
| Porta que só aparece via `ss -tulnp` DEPOIS de ganhar shell (127.0.0.1) | Serviço interno — parte de pivoting/pós-exploração |

### Interagir com porta desconhecida
```bash
nc -nv <TARGET_IP> <PORTA>
```
Se ao conectar aparecer um prompt tipo `Enter your name:` ou um menu de texto, é quase certeza **Pwn** (serviço binário customizado esperando input).

---

## 4. Sinais de que é Web

- Porta 80/443/8080 respondendo a `curl`
- Página HTML normal, formulário de login, painel de busca
- Resposta com headers tipo `Server: nginx`, `X-Powered-By: PHP`
- URL com parâmetros (`?id=`, `?search=`)

**Primeiro passo:** seguir o [guia de vulnerabilidades web](guia_vulnerabilidades_web_ctf.md) já feito.

---

## 5. Sinais de que é Criptografia

- Você recebe **texto**, não um serviço pra explorar
- Strings longas de caracteres aleatórios, números, ou Base64 (`=` no final é forte indício de Base64)
- Menção explícita a "cifra", "chave", "encriptado", "hash"
- Um par claro/cifrado dado como exemplo (`plaintext: ... / ciphertext: ...`) — sinaliza ataque de known-plaintext
- Arquivo `.py` fornecido implementando um algoritmo customizado (LCG, RSA feito à mão, XOR) — praticamente garante que a vulnerabilidade está na implementação, não no algoritmo teórico

### Identificar o tipo de cifra rapidamente
```bash
echo "TEXTO" | base64 -d              # tentar decodificar Base64
echo "TEXTO" | xxd -r -p              # se for hex
```
| Padrão do texto | Provável |
|---|---|
| Só letras maiúsculas, sem números/símbolos | Cifra clássica (César, Vigenère, substituição) |
| Termina em `=` ou `==` | Base64 |
| Só `0-9a-f` | Hexadecimal |
| 32, 40, ou 64 caracteres hex | Hash (MD5=32, SHA1=40, SHA256=64) — checar em crackstation/hashcat |
| Números grandes (centenas de dígitos) | RSA — provavelmente vai precisar fatorar `n` (RsaCtfTool, factordb) |
| Blocos de tamanho fixo repetidos | Cifra de bloco (AES) — procurar modo de operação (ECB é vulnerável a padrão repetido) |

---

## 6. Sinais de que é Pwn / Binary Exploitation

- Você recebe um **binário ELF** + acesso a um serviço de rede rodando esse binário
- `file` mostra `ELF 64-bit LSB executable`
- Porta customizada que, ao conectar com `nc`, espera input e não responde como HTTP

### Primeiro comando sempre
```bash
file binario
checksec --file=binario     # mostra proteções: NX, PIE, Canary, RELRO
```
O resultado do `checksec` já sinaliza a técnica:
| Proteção ausente | Técnica provável |
|---|---|
| Sem Canary | Buffer overflow clássico (stack smashing) |
| Sem NX (stack executável) | Shellcode injection direto na stack |
| Sem PIE | Endereços fixos — mais fácil de ROP/retornar pra função específica |
| Sem RELRO | GOT overwrite |

---

## 7. Sinais de que é Reverse Engineering

- Binário ELF/PE **sem** serviço de rede associado — você só roda localmente e precisa entender a lógica
- Pergunta tipo "encontre a senha certa" ou "o programa valida algo, descubra o quê"
- `strings` no binário mostra mensagens tipo `"Senha incorreta"`, `"Access granted"`

### Primeiro comando
```bash
file binario
strings binario | grep -i -E "flag|senha|password|correct"
```
Se `strings` já revelar a flag ou lógica óbvia, resolvido sem precisar abrir debugger. Senão, abrir no **Ghidra** e procurar a função `main` / comparação de string.

---

## 8. Sinais de que é Forense

- Você recebe um arquivo grande (imagem de disco `.dd`, `.img`, captura de rede `.pcap`, memória `.mem`/`.raw`)
- Pedido de "encontre o que aconteceu", "recupere o arquivo deletado", "identifique o IP do atacante"

### Primeiro comando por tipo
```bash
# Captura de rede
wireshark arquivo.pcap        # ou tshark -r arquivo.pcap

# Imagem de disco
file arquivo.dd
mount -o ro arquivo.dd /mnt   # (com cuidado, ambiente de VM/sandbox)

# Metadados de qualquer arquivo
exiftool arquivo
```
Em `.pcap`, procurar primeiro por protocolos "conversacionais" — HTTP (File → Export Objects), FTP (credenciais em texto claro), DNS (exfiltração de dados via subdomínio).

---

## 9. Sinais de que é Esteganografia

- Arquivo de imagem/áudio "normal demais" — tamanho grande pro que mostra, ou pedido explícito tipo "tem algo escondido aqui"
- `file` confirma que é imagem/áudio válida, mas o desafio insiste que tem mais

### Primeiro comando
```bash
exiftool imagem.jpg           # metadados (comentários, autor, GPS)
strings imagem.jpg | less     # texto embutido
binwalk imagem.jpg            # arquivo escondido dentro
zsteg imagem.png              # específico pra PNG/BMP — LSB steganography
steghide extract -sf imagem.jpg    # se suspeitar de steghide (às vezes pede senha)
```

---

## 10. Sinais de que é OSINT

- Não tem arquivo nem serviço — só um nome, @usuário, foto, ou trecho de texto
- Pergunta tipo "em que cidade essa foto foi tirada", "qual o e-mail dessa pessoa"

### Abordagem
```
Busca reversa de imagem (Google Images, TinEye)
Metadados EXIF da foto (exiftool) — às vezes tem GPS
Busca do @usuário em várias redes (Sherlock, ou manual)
Google dorking: site:linkedin.com "nome da pessoa"
```

---

## 11. Sinais de que é Boot2Root/Privesc

Esse é o formato mais provável pro Pink Hat, dado que a cartilha confirma "pentest-based". Reconhece-se por:
- Você recebe só um **IP**, sem pista de categoria
- `nmap` mostra múltiplas portas (não só uma porta isolada de "puzzle")
- Existe uma aplicação web **e** SSH ao mesmo tempo — sinal claro de "entre pela web, saia pelo SSH"
- O desafio menciona "duas flags" (`user.txt` e `root.txt`)

**Abordagem:** seguir os guias de [web](guia_vulnerabilidades_web_ctf.md) e [privesc](guia_privesc_linux_ctf.md) já prontos.

---

## 12. Tabela-relâmpago de fingerprinting

| Primeiro comando | O que ele revela |
|---|---|
| `file arquivo` | Tipo real do arquivo (ignora extensão falsa) |
| `nmap -sC -sV -p- <IP>` | Portas e serviços → categoria geral |
| `nc -nv <IP> <PORTA>` | Se é serviço interativo tipo Pwn |
| `strings arquivo \| less` | Texto legível escondido — pistas, flags, mensagens |
| `binwalk arquivo` | Arquivo escondido dentro de outro |
| `exiftool arquivo` | Metadados (autor, GPS, software usado) |
| `checksec --file=binario` | Se é Pwn e qual técnica de exploração |
| `curl -I http://<IP>` | Confirma Web e tecnologia usada |

---

## 13. Fluxograma de decisão

```
Recebi o quê?
│
├─ IP/hostname
│    │
│    ├─ nmap mostra várias portas (web + ssh, etc.)
│    │    → Boot2Root (web guide → privesc guide)
│    │
│    └─ nmap mostra 1 porta customizada, nc abre prompt de texto
│         → Pwn (serviço de rede)
│
├─ Arquivo
│    │
│    ├─ file → ELF/PE
│    │    ├─ Tem serviço de rede associado → Pwn
│    │    └─ Só roda local, pede senha/lógica → Reverse
│    │
│    ├─ file → imagem/áudio/PDF
│    │    ├─ Desafio menciona "escondido" → Estego
│    │    └─ Desafio menciona "investigar/recuperar" → Forense
│    │
│    ├─ file → texto/Base64/hex/números grandes
│    │    → Criptografia
│    │
│    └─ file → .pcap/.dd/.mem
│         → Forense
│
├─ URL
│    → Web
│
└─ Nome/@usuário/foto sem arquivo técnico
     → OSINT
```

**Regra prática:** os primeiros 2-3 minutos de qualquer desafio devem ser gastos rodando `file`, `nmap` ou `nc` — **nunca** partir direto para tentar explorar sem antes confirmar a categoria. Errar a categoria custa muito mais tempo do que os 2 minutos de triagem.
