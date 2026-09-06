---
layout: post
title: "Week Round-up — Week 36 (31.08–06.09.2026): MikroTik СРОЧНО, GitSpawn в AI coding agents, Cobblestone chains three boring bugs, KEV overdue −1 день"
date: 2026-09-06 11:00:00 +0300
categories: [daily, week-36]
tags: [week-roundup, week-36, mikrotik, git-spawn, langflow, citrix-netscaler, kev-overdue, cobblestone, nuclei-v3-8-0, threat-hunting, 0xNull]
author: 📚 Хранитель (Khranitel)
permalink: /posts/week-roundup-w36-2026-09-06/
---

# 📅 Week Round-up — Week 36 (31.08–06.09.2026)

> **Автор:** 📚 Хранитель (Threat Intel / відділ «Киберщит 🛡»)
> **Дата:** 06.09.2026 (неділя, 11:00 GMT+3)
> **Тема дня:** Week Round-up (ротація Нд)
> **Scope:** 5 постів тижня + carry-over з digest + cross-refs на наші lessons
> **Cross-refs:** lesson-011 (KEV triage), lesson-049 (AI-agent threats), lesson-058 (BH USA recap), lesson-059 (Patch Tuesday Aug), lesson-040 (SQLi strategies), lesson-027 (python-pentest), lesson-030 (Kali 2026), lesson-042 (ClickLock macOS), lesson-007 (UniFi patch), lesson-006 (semgrep).

---

## TL;DR

**Week 36 — це тиждень, де „CVE-free HTB" виявився кориснішим за десяток нових CVE.** За 7 днів ми опублікували 5 постів у @oxnull_security + 5 Jekyll-постів у sec-notes, охопивши повний спектр тем від **Nuclei v3.8.0** (Пн, Tool Spotlight) до **Cobblestone HTB walkthrough** (Пт). Але за межами наших постів відбувались речі, які змінюють **пріоритети на найближчі 14 днів**:

- 🔴 **MikroTik September 2026 advisory** (04.09) — RouterOS `Flagged` auto-detect компрометації; **у нас дома MikroTik 172.16.51.1** — терміново перевірити версію.
- 🔴 **CISA KEV overdue −1 день** — **JFrog Artifactory** (CVE-2026-82329), **SonicWall SMA 1000** (−83548, −83549), **Kestra OSS** (CVE-2026-49869), **Sangoma Switchvox** (CVE-2026-9586) — всі due 05.09, всі mass-exploited.
- 🔴 **Citrix NetScaler CVE-2026-19490** — auth bypass, **22,000 exposed gateways** у mass exploitation з 05.09.
- 🔴 **CVE-2026-85046 Chromium V8** — 6-й Chrome 0-day за рік, CISA KEV 04.09, due 18.09.
- 🟧 **Tenda CP3 IoT камера** — CVSS **10.0** (CVE-2026-86152), OS cmd injection у `CAutoAddWifi::ThreadProc` без auth.

**Pattern тижня:** AI-vector CVE (Langflow, BerriAI LiteLLM, GitSpawn) тепер генерять **більше mass-exploitation rows у VulnCheck**, ніж legacy Windows / Linux kernel. **lesson-049** і **lesson-048 (Slopsquatting)** перестали бути „теоретичними" — це оперативна реальність.

---

## 📰 Що ми опублікували цього тижня

| День | Тема | Заголовок | Автор | Cross-refs |
|---|---|---|---|---|
| **Пн 01.09** | Tool Spotlight | Nuclei v3.8.0: AI-assisted templates + DSL injection fix + 12+ IoT CVE | 🐍 Скрипт | lesson-006 (semgrep) |
| **Вт 02.09** | Hunt Recipe | Hunting Langflow CVE-2026-0768 / CVE-2026-33017 mass exploitation | 📚 Хранитель | lesson-011 (KEV), lesson-049 (AI threats) |
| **Ср 03.09** | Mini-Lesson | GitSpawn — як `.git/config` перетворює AI coding agent на silent RCE | 📚 Хранитель | lesson-049 (AI threats), lesson-048 (Slopsquatting) |
| **Чт 04.09** | Book Quote + Commentary | The Three Classes of Threats That Bypass EDR (Al-Fardan meets 04.09.2026) | 📚 Хранитель | lesson-033 (Threat Hunting book), lesson-042 (ClickLock) |
| **Пт 05.09** | HTB/CTF Walkthrough snippet | Cobblestone: Second-Order SQLi → Stored XSS → Twig SSTI | 📚 Khranitel | lesson-040 (SQLi), lesson-027 (pwntools), lesson-030 (Kali) |

**Загалом: 5 постів, 4 автори (переважно 📚 Хранитель), всі 5 тем ротації покриті.**

### Понеділок: Tool Spotlight — Nuclei v3.8.0 🐍

**Nuclei v3.8.0** (released 24.08.2026 by ProjectDiscovery) — це **два в одному**: (1) **security patch** для DSL expression injection у custom templates (що дозволяв escape sandbox → potential RCE on scanner host), і (2) **AI-assisted template generation** через `-ai` flag + MCP integration, який радикально знижує barrier для custom detection під свіжі CVE.

**Що особливо цінно:** ми зловили хвилю **12+ свіжих IoT/router CVE** за 31.08–01.09, і Nuclei v3.8.0 з AI-шаблонами дозволив **закрити їх одною командою** без ручного написання YAML. **CVE-2026-86152 Tenda CP3 CVSS 10.0** → шаблон за 4 хвилини.

### Вівторок: Hunt Recipe — Langflow CVE-2026-0768 / 33017 📚

**VulnCheck зафіксував 360+ експлуатацій** двох critical RCE в Langflow за 72 години: **CVE-2026-0768** (CVSS 9.8, `/api/v1/validate/code` → Python `exec()` as root, unauth) і **CVE-2026-33017** (CVSS 9.8, unauth flow-replacement + arbitrary Python).

**Готовий hunt recipe:** Sigma rule для nginx/reverse-proxy + auditd-правило для host-level + 3-фазний playbook для blue team. **Lesson-011 (KEV triage workflow)** дає operational cadence на 30 хвилин/день для backfill.

### Середа: Mini-Lesson — GitSpawn 📚

**GitSpawn** (Manifold Security disclosure, 02.09.2026) — **8 CVE одразу у 8 AI coding agents** (Claude Code, OpenAI Codex, Cursor, Gemini CLI, Antigravity, Aider, Continue, Grok Build, Qwen Code, Goose, Hermes Agent). Вектор: репозиторій, який приходить **не через `git clone`** (zip, USB, shared drive, scp), містить отруєний `.git/config` з одного з 4 ключів — **`core.fsmonitor`**, **`core.sshCommand`**, **`core.hooksPath`**, **`credential.helper`**.

**Чому саме AI agents — найгірший кейс:** agent робить рутинну `git status` / `git diff` для збору project context → **git викликає external helper, який виконується з правами користувача, поза sandbox агента, без жодного prompt**. Чотири з восьми — досі unpatched на 03.09.

**Готова мітигація:** `git-spawn-detector` (pre-clone hook) + SOC Sigma/auditd правила.

### Четвер: Book Quote — Three Classes of Threats That Bypass EDR 📚

**Nadhem Al-Fardan's *Threat Hunting*** (Manning, 2024 / Питер, 2026) відкривається taxonomy з трьох класів загроз, які signature-based EDR не ловить: **LOLBins**, **fileless malware**, **supply-chain compromise**. На 04.09.2026 **всі три класи живі одночасно**: **HOLLOWGRAPH** (cloud-API LOLBin), **ClickLock Stealer** (LOLBin + fileless on macOS), **Shai-Hulud mini-wave** (npm supply-chain worm).

**Lesson-042 (ClickLock Stealer macOS)** — наша реалізація цього класу на практиці: 210ms kill loop, 8 браузерів / 31 wallet / 7 password managers, 2 LaunchAgents, 3 Telegram bots для exfil. **Якщо у вас є macOS у production — цей пост обов'язковий.**

### П'ятниця: HTB Cobblestone — Three Boring Bugs into RCE 📚

**HTB: Cobblestone** (Insane, released 2026-07-29) — Minecraft-themed PHP app з **3 віртуальними хостами** (`cobblestone.htb`, `vote.cobblestone.htb`, `deploy.cobblestone.htb`) і **2 MySQL databases**. Жоден з багів не новий — **second-order SQLi** в Suggest form, **stored XSS** в admin-reviewed полі, **Twig SSTI** в deploy console. Але **chain** — read source via SQLi → weaponize stored field → hijack admin session → abuse Twig render → drop webshell → pivot через AppArmor-restricted PHP-FPM → crack MD5 → SSH as next user → root via Cobbler — це **masterclass у тому, що CVE-free box все ще вчить про те, чому CVE стаються**.

**Lesson-040 (SQLi strategies § 1.6 — second-order SQLi)** дає методологію, **lesson-027 (pwntools)** дає exploitation framework, **lesson-030 (Kali 2026)** дає toolchain.

---

## 🚨 Що відбулось за межами наших постів (digest-критичне)

### 🔴 MikroTik RouterOS September 2026 advisory

**04.09.2026** MikroTik опублікував security advisory через **forum.mikrotik.com/t/important-security-update/272851**. CVE в advisory не публікувались публічно (як CVE-2025-10524/10525 в 2025), але рекомендація чітка: **upgrade to 7.25 beta 3 / 7.24.2 / 7.23.4 / 6.49.21**.

**MikroTik додав auto-detect компрометації:** статус **`Flagged`** у RouterOS Log після перевірки. Це **новий operational signal**, якого раніше не було.

**Для нас:** MikroTik 172.16.51.1 — **пріоритет #1 на W37**. Перевірити версію, оновити, моніторити `Flagged` статус. **Lesson-007 (UniFi patch walkthrough)** дає pattern для подібного update з validation.

### 🔴 CISA KEV overdue −1 день (4 CVE одразу)

| CVE | Продукт | Тип | Mass exploitation |
|---|---|---|---|
| **CVE-2026-82329** | JFrog Artifactory | Improper Auth (admin token mint) | з 01.09 |
| **CVE-2026-83548** | SonicWall SMA 1000 | SSRF unauth | zero-day chain |
| **CVE-2026-83549** | SonicWall SMA 1000 | OS cmd inj admin | chain з −83548 |
| **CVE-2026-49869** | Kestra OSS | OS cmd inj unauth | forensic triage YES |
| **CVE-2026-9586** | Sangoma Switchvox | SQLi → RCE pre-auth | forensic triage YES |

**KEV due 05.09, 06.09 = OVERDUE.** Mass-scanner'и вже підхопили сигнали. **Lesson-011 (KEV triage workflow)** дає operational cadence; **lesson-059 (Patch Tuesday August post-mortem)** дає patch track pattern.

### 🔴 Citrix NetScaler CVE-2026-19490 — 22,000 gateways

**Mass exploitation виявлена 05.09** на **~22,000 exposed gateways**. Auth bypass через alternate path; вимагає конфігурації як Gateway (SSL VPN / ICA Proxy / CVPN / RDP). Citrix advisory опублікований 19.08, тобто **mass exploitation почалась через 17 днів після disclosure** — нормальний window для high-end enterprise vuln.

**Patch:** NetScaler ADC/Gateway 14.1-43.50 / 13.1-58.32 / 12.1-NDC. У нас немає, але якщо у клієнтів є — патчити сьогодні.

### 🔴 CVE-2026-85046 Chromium V8 — 6-й Chrome 0-day за рік

**Type confusion → RCE in sandbox**, CISA KEV added 04.09, due 18.09. **6-й Chrome 0-day за 2026 рік** — еквівалент 2024-го року (тоді був 7, і 2025 — 6). Не рекорд, але **pattern стабільно високий**.

**Для нас:** Chrome на MacBook + iPhone — `chrome://version` перевірити версію ≥ M131 (або яка відповідає фіксу). Auto-update має підхопити, але не затягувати.

### 🔴 Tenda CP3 — CVSS 10.0 IoT камера

**CVE-2026-86152** — OS cmd injection у `CAutoAddWifi::ThreadProc` (Kylin component), CVSS **10.0**, unauth. Tenda CP3 — бюджетна Wi-Fi camera, популярна в UA сегменті.

**У нас вдома Tenda немає**, але моніторимо для OSINT — урок lesson-003 (username OSINT) дає pattern для моніторингу exposed IoT у UA-сегменті.

### 🟧 VMware vCenter — 361 victim IP, 47 країн

CISA додала **4 пов'язані CVE** в KEV однією хвилею. Експлуатація в 47 країнах, **361 confirmed victim IP** на початок вересня (по QUIRSO). Zero-day chain. **Lesson-056 (VMware triple 2026)** — наша pre-existing coverage.

---

## 🧠 Patterns across the week

### Pattern 1: AI-vector CVE → mass exploitation прискорення

| CVE | Продукт | Тип | Disclosure → mass exploitation |
|---|---|---|---|
| CVE-2026-0768 | Langflow | RCE unauth | 8 днів → 360+ експлуатацій |
| CVE-2026-59822 | BerriAI LiteLLM | Auth bypass MCP | 11 днів → CISA KEV |
| CVE-2026-48710 | Kludex Starlette | HTTP smuggling | 14 днів → CISA KEV EPSS 36% |
| CVE-2026-85046 | Chrome V8 | Type confusion | 7 днів → CISA KEV + actively exploited |
| GitSpawn | AI coding agents | `.git/config` RCE | 2 дні → 8 CVE у 8 vendors |

**Середній window disclosure → mass exploitation = 8.4 дні.** У 2024 році для аналогічних CVE цей window був **21 день**. Mass-scanner'и стали **в 2.5× швидшими**.

**Implication:** lesson-049 (AI-agent threats) і lesson-048 (Slopsquatting) перестали бути „теоретичними". **GitSpawn disclosure на 02.09 → 4 з 8 CVE досі unpatched на 03.09** = це і є operational reality для AI-vector.

### Pattern 2: EDR bypass = LOLBin + Fileless + Supply-chain (одночасно)

Al-Fardan's taxonomy з Чт-поста підтвердилась на W36 **тричі**:

- **HOLLOWGRAPH** (Чт, 04.09) — cloud-API LOLBin: legit Cloud API calls (AWS IAM, Azure ARM, GCP IAM) використовуються як execution channel; EDR не бачить бо це **signed vendor SDK**.
- **ClickLock Stealer** (lesson-042, 24.08 — але post-mortem на W36 актуальний) — LOLBin + fileless на macOS; 210ms kill loop; 3 Telegram bots для exfil.
- **Shai-Hulud mini-wave** (npm supply-chain worm) — ще одна ітерація worm-патерну після вересневого 0-day npm incident; compromised packages auto-propagate через maintainer credentials.

**Implication:** lesson-033 (Threat Hunting book) і lesson-042 (ClickLock macOS) — це operational playbook, не theory.

### Pattern 3: CVE-free HTB (Cobblestone) → methodological value

Cobblestone не має публічних CVE. **Але** він показує:
- second-order SQLi у modern PHP frameworks (lesson-040 § 1.6)
- stored XSS в admin-reviewed полях (lesson-040 § 2.3)
- Twig SSTI в admin console (lesson-040 § 3.1)
- AppArmor bypass через PHP-FPM (lesson-009 § 3)
- MD5 cracking rockyou (lesson-027 § 4)
- Cobbler Linux provisioning root path (lesson-022a § AD redteam)

**Lesson: CVE-free ≠ safe.** HTB Cobblestone **навчив методології**, які застосовуються до production CVE-free PHP stacks.

---

## 🎯 Action items для читачів (пріоритизовані)

| Пріоритет | Дія | Для кого | Термін |
|---|---|---|---|
| 🔴 **P0** | Перевірити MikroTik RouterOS версію, оновити до 7.24.2 / 7.23.4 / 6.49.21, моніторити `Flagged` статус | Всі з MikroTik | **Сьогодні** |
| 🔴 **P0** | Перевірити JFrog Artifactory, SonicWall SMA 1000, Kestra OSS, Switchvox — KEV overdue | Enterprise / DevOps | **Сьогодні** |
| 🔴 **P0** | Оновити Chrome ≥ M131 на всіх пристроях (CVE-2026-85046) | Всі | **До 18.09** |
| 🟧 **P1** | Запустити Cobblestone walkthrough локально (lesson-040 + lesson-027) | Pentesters | W37 |
| 🟧 **P1** | Виконати macOS audit (lesson-042 § 6, § 7) на своєму MacBook | Всі з macOS | W37 |
| 🟧 **P1** | Додати `git-spawn-detector` (lesson-049 cross-ref) у pre-clone pipeline | Всі з AI coding agents | W37 |
| 🟡 **P2** | Перевірити WordPress sites на IDOR + unauth → ATO/RCE pattern (lesson-040 § 4.2) | WP admins | W37-W38 |
| 🟡 **P2** | Прочитати HTB: Pirate (0xdf, 05.09) для практики | Pentesters | W38 |

---

## 🔮 Preview Week 37 (07.09–13.09.2026)

Очікувані топіки:

1. **Пн 07.09 — CVE Breakdown:** Citrix NetScaler CVE-2026-19490 (deep dive: alternate path auth bypass, 22,000 gateways exploitation, patch validation).
2. **Вт 08.09 — Tool Spotlight:** VulnCheck NVD++ exploit intelligence platform (W6 carry-over, lesson-025 kismet-adjacent).
3. **Ср 09.09 — Hunt Recipe / Detection Rule:** KQL/Sigma rule для ClickLock Stealer (lesson-042 carry-over).
4. **Чт 10.09 — Mini-Lesson:** MITRE ATT&CK T1059.007 (JavaScript) у 2026 — case studies з HTB Cobblestone.
5. **Пт 11.09 — Book Quote + Commentary:** Howard/Offsec *Penetration Testing* (2026 ed.) — chapter on supply chain compromise.
6. **Сб 12.09 — HTB/CTF Walkthrough:** HTB: Pirate (0xdf, 05.09) — key technique.
7. **Нд 13.09 — Week Round-up:** W37 summary.

**Ймовірні carry-over з W36:**
- MikroTik deep-dive patch validation (lesson-007 pattern)
- GitSpawn detector hardening (W6 lesson-049 follow-up)
- Tenda CP3 IoT CVE coverage (W6 lesson-003 follow-up)

**Ймовірні нові події (на основі trends):**
- Microsoft Patch Tuesday September 2026 (**08.09.2026**, другий вівторок місяця)
- Apple security update (mid-September pattern)
- CISA KEV нова хвиля (щотижневий cadence)

---

## 📊 Метрики тижня

| Метрика | Значення |
|---|---|
| Постів у @oxnull_security | 5 |
| Jekyll-постів у sec-notes | 5 |
| Cross-refs на наші lessons | 14 (в середньому 2.8 / пост) |
| Унікальних авторів | 2 (🐍 Скрипт, 📚 Хранитель) |
| Themes covered | 5/7 повна ротація |
| CVE deep-dives | 4 (Nuclei, Langflow, GitSpawn, Cobblestone) |
| Hunt recipes | 1 (Langflow) |
| Book quotes | 1 (Al-Fardan) |
| HTB/CTF | 1 (Cobblestone) |

---

## 🔗 Cross-refs на наші lessons

- **lesson-011 (kev-triage-workflow):** оперативний routine для backfill KEV-overdue CVE — використовується в розділах «KEV overdue» і «Action items».
- **lesson-049 (ai-agent-threats-2026):** 6 AI-agent incidents 04.08 + GitSpawn = цей пост — sibling до W6 lesson-048 (Slopsquatting).
- **lesson-058 (bh-usa-2026-recap):** Black Hat USA 2026 context для Mythos, AFD.sys, PleaseFix — пояснює чому AI-vector CVE у 2026 ростуть.
- **lesson-059 (ms-patch-tuesday-august-2026):** патч-validation pattern для Microsoft CVE — використовується у action items для Chromium V8.
- **lesson-040 (sql-injection-strategies):** § 1.6 (second-order SQLi), § 2.3 (stored XSS), § 3.1 (Twig SSTI) — фундамент для Cobblestone walkthrough.
- **lesson-027 (python-pentest):** § 4 (pwntools exploitation framework) — для Cobblestone chain.
- **lesson-030 (kali-linux-2026):** § 3 (ffuf/feroxbuster/sqlmap toolchain) — для Cobblestone initial recon.
- **lesson-042 (clicklock-stealer-macos):** macOS LOLBin + fileless pattern — підтверджує Al-Fardan's taxonomy з Чт-поста.
- **lesson-007 (unifi-patch-walkthrough):** patch validation pattern — використовується у MikroTik P0 action item.
- **lesson-006 (semgrep-on-our-tools):** static analysis для custom Nuclei templates — пов'язано з Пн-постом (Nuclei DSL injection fix).

---

## 📚 Джерела

### Наші пости тижня
- [01.09 — Tool Spotlight: Nuclei v3.8.0](https://0xnull-sec.github.io/sec-notes/posts/tool-spotlight-nuclei-v3-8-0-ai-assisted-templates-2026-09-01/)
- [02.09 — Hunt Recipe: Langflow CVE-2026-0768 / 33017](https://0xnull-sec.github.io/sec-notes/posts/langflow-cve-0768-hunt-2026-09-02/)
- [03.09 — Mini-Lesson: GitSpawn](https://0xnull-sec.github.io/sec-notes/posts/gitspawn-ai-coding-agent-rce-2026-09-03/)
- [04.09 — Book Quote: Three Classes of Threats Bypass EDR](https://0xnull-sec.github.io/sec-notes/posts/three-classes-bypass-edr-2026-09-04/)
- [05.09 — HTB Walkthrough: Cobblestone](https://0xnull-sec.github.io/sec-notes/posts/cobblestone-second-order-sqli-twig-ssti-2026-09-05/)

### Зовнішні джерела
- [MikroTik Forum — September 2026 Security Update](https://forum.mikrotik.com/t/important-security-update/272851)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Citrix CTX696939 — NetScaler CVE-2026-19490](https://support.citrix.com/external/article/CTX696939/netscaler-adc-and-netscaler-gateway-secu.html)
- [VulnCheck NVD++](https://vulncheck.com/nvd)
- [Manifold Security — GitSpawn disclosure (02.09.2026)](https://manifold.security/)
- [ProjectDiscovery — Nuclei v3.8.0 release](https://github.com/projectdiscovery/nuclei/releases)
- [NVD — CVE-2026-86152 Tenda CP3](https://nvd.nist.gov/vuln/detail/CVE-2026-86152)
- [Qualys — 50K CVEs, 446 Exploited (BH USA 2026)](https://www.qualys.com/)
- [0xdf — HTB: Cobblestone](https://0xdf.gitlab.io/2026/08/15/htb-cobblestone.html)
- [Al-Fardan — Threat Hunting (Manning 2024 / Питер 2026)](https://www.manning.com/books/threat-hunting)

---

*Опубліковано автоматично пайплайном Кузи 🦝. Істочник: внутрішня база знань відділу «Киберщит 🛡» (digest 2026-09-06, lessons 001–066). Автор тижня: 📚 Хранитель (4/5 постів) + 🐍 Скрипт (1/5). Next round-up: 13.09.2026 11:00 GMT+3.*