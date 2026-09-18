# Links Essenciais para CTF

Organizado por categoria — plataformas de prática, ferramentas online, referências e comunidades.

---

## Plataformas de prática

| Site | Foco |
|---|---|
| [TryHackMe](https://tryhackme.com) | Trilhas guiadas (rooms), ótimo para iniciantes — módulos "Pre Security" e "Complete Beginner" gratuitos |
| [HackTheBox](https://www.hackthebox.com) | Máquinas Boot2Root, "Starting Point" para nível iniciante |
| [picoCTF](https://picoctf.org) | Desafios curtos no formato clássico de CTF (ganhar flag, submeter) |
| [Root-Me](https://www.root-me.org) | Desafios separados por categoria (web, cripto, forense, rede) |
| [OverTheWire](https://overthewire.org/wargames/) | Wargames em progressão (Bandit é o clássico pra praticar Linux/terminal) |
| [PentesterLab](https://pentesterlab.com) | Focado em Web, com exercícios práticos guiados |
| [CTFtime](https://ctftime.org) | Calendário de CTFs ao vivo no mundo todo + ranking de times |
| [CryptoHack](https://cryptohack.org) | Focado só em criptografia, muito bem estruturado |
| [pwnable.kr](https://pwnable.kr) / [pwnable.tw](https://pwnable.tw) | Focado em Pwn/binary exploitation |

---

## Web

| Site | Uso |
|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Melhor recurso gratuito pra aprender vulnerabilidades web a fundo (dá pra praticar SQLi, SSRF, IDOR etc. em labs reais) |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Repositório gigante de payloads por categoria de vulnerabilidade |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Referência das vulnerabilidades web mais críticas |
| [SecLists](https://github.com/danielmiessler/SecLists) | Wordlists pra tudo — diretórios, senhas, usernames, fuzzing |
| [jwt.io](https://jwt.io) | Decodificar/testar JWT |

---

## Linux / Privilege Escalation

| Site | Uso |
|---|---|
| [GTFOBins](https://gtfobins.github.io) | Catálogo de binários Unix exploráveis (SUID, sudo, capabilities) |
| [LOLBAS](https://lolbas-project.github.io) | Equivalente ao GTFOBins, mas pra Windows |
| [HackTricks](https://book.hacktricks.xyz) | Enciclopédia gigante de técnicas de pentest/privesc, muito usada como referência rápida |
| [linPEAS / winPEAS (PEASS-ng)](https://github.com/peass-ng/PEASS-ng) | Scripts de enumeração automatizada de privesc |
| [pspy](https://github.com/DominicBreuker/pspy) | Monitorar processos/cron sem privilégio de root |

---

## Pwn / Binary Exploitation

| Site | Uso |
|---|---|
| [pwn.college](https://pwn.college) | Curso gratuito e estruturado de binary exploitation |
| [pwntools docs](https://docs.pwntools.com) | Documentação da biblioteca Python essencial pra exploits |
| [ROP Emporium](https://ropemporium.com) | Desafios progressivos focados em ROP chains |
| [GEF](https://github.com/hugsy/gef) / [pwndbg](https://github.com/pwndbg/pwndbg) | Plugins de GDB voltados a exploração |

---

## Reverse Engineering

| Site | Uso |
|---|---|
| [Ghidra](https://ghidra-sre.org) | Descompilador/desassemblador gratuito (NSA) |
| [IDA Free](https://hex-rays.com/ida-free/) | Alternativa ao Ghidra |
| [crackmes.one](https://crackmes.one) | Repositório de binários pra praticar reversing |

---

## Criptografia

| Site | Uso |
|---|---|
| [CyberChef](https://gchq.github.io/CyberChef/) | "Canivete suíço" de decodificação — Base64, hex, XOR, cifras clássicas, tudo visual |
| [dCode](https://www.dcode.fr) | Identificador e solver de cifras clássicas (César, Vigenère, etc.) |
| [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) | Ataques automatizados contra RSA malformado |
| [FactorDB](http://factordb.com) | Fatoração de números grandes (útil pra quebrar RSA fraco) |
| [CrackStation](https://crackstation.net) | Lookup de hash em rainbow tables |
| [Boxentriq Cipher Identifier](https://www.boxentriq.com/code-breaking) | Identifica qual cifra provavelmente é, a partir do texto |

---

## Forense

| Site | Uso |
|---|---|
| [Wireshark](https://www.wireshark.org) | Análise de tráfego de rede (`.pcap`) |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Análise de memória RAM |
| [Autopsy](https://www.autopsy.com) | Análise forense de imagem de disco |
| [CyberChef](https://gchq.github.io/CyberChef/) | (também útil aqui, pra decodificar dados extraídos) |

---

## Esteganografia

| Site | Uso |
|---|---|
| [StegOnline](https://stegonline.georgeom.net) | Versão web do StegSolve, análise de camadas de bit em imagem |
| [Aperi'Solve](https://aperisolve.fr) | Roda vários checks de estego automaticamente (binwalk, zsteg, exiftool juntos) |

---

## OSINT

| Site | Uso |
|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Busca de username em centenas de plataformas |
| [OSINT Framework](https://osintframework.com) | Mapa de ferramentas OSINT por categoria |
| [TinEye](https://tineye.com) | Busca reversa de imagem |

---

## Referência geral / metodologia

| Site | Uso |
|---|---|
| [HackTricks](https://book.hacktricks.xyz) | (repetindo aqui porque cobre praticamente todas as categorias, não só privesc) |
| [CTF101](https://ctf101.org) | Introdução conceitual a cada categoria de CTF |
| [Awesome CTF (GitHub)](https://github.com/apsdehal/awesome-ctf) | Lista curada de ferramentas por categoria |
| [Reverse Shell Generator (revshells.com)](https://www.revshells.com) | Gera payload de reverse shell pronto pra qualquer linguagem disponível no alvo |
| [Explainshell](https://explainshell.com) | Cola qualquer comando de terminal e ele explica pedaço por pedaço |

---

## Writeups (para aprender depois de travar ou revisar abordagem)

| Site | Uso |
|---|---|
[CTFtime](https://ctftime.org) | Cada evento listado tem link pros writeups da comunidade |
| [GitHub: search "ctf writeup"](https://github.com/search?q=ctf+writeup&type=repositories) | Milhares de repositórios de writeups por evento |

---

## Comunidade

| Site | Uso |
|---|---|
| [CTFtime](https://ctftime.org) | Calendário + ranking de times (inclusive pra acompanhar a Pangeia) |
| Discords de CTF (buscar o do evento específico, geralmente linkado na página da competição) | Suporte ao vivo durante a prova |

---

**Uso recomendado antes do CTF Pink Hat:** priorizar **PortSwigger Academy** (web) e **GTFOBins/HackTricks** (privesc) — são os dois com maior retorno pro formato pentest-based/Boot2Root do evento, dado o gap identificado nas conversas anteriores.
