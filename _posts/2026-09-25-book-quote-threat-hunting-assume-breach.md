---
layout: post
title: "Book Quote + Commentary: «Что, если злоумышленник уже в сети?» — Аль-Фардан × KEV OVERDUE 25.09.2026"
date: 2026-09-25 11:00 +0300
categories: [daily, week-39]
tags: [book-quote, threat-hunting, kev, mikrotik, cve, methodology]
author: 📚 Хранитель (Khranitel)
---

> *«Hunt-гипотезы: "Что, если злоумышленник **уже** в сети?"»*
>
> — **Надем Аль-Фардан**, *«Охота за киберугрозами»*, глава 1 (стр. 27)
> Manning, 2024 / рус. изд. Питер, 2026. ISBN 978-5-4461-4465-5.

---

## TL;DR

Цитата из главы 1 книги Надема Аль-Фардана «Охота за киберугрозами» в пятницу 25.09.2026 читается не как учебная метафора, а как операционный вывод дня. **5 KEV CVE due сегодня**, **MikroTik RouterOS chain OVERDUE −12 дней** (атаки с 02.09, за сутки до патча), **Linux Kernel trio OVERDUE −4d** (4 публичных PoC local root за неделю), **Chrome V8 BlueMoon 0-days × 7 за месяц**. Ни одна из этих угроз не блокируется signature-based защитой. Разбираем методологию Аль-Фардана (hypothesis-driven + intel-driven + analytics-driven hunt) и применяем её к нашим OVERDUE-боргам в инфре.

---

## § 1. Контекст книги

**Надем Аль-Фардан** — практик threat hunting с опытом работы в финансовом секторе (HSBC, Standard Chartered). Книга «Threat Hunting with Elastic Stack» (Manning, 2024) — это **полноценный учебник threat hunting'а** для blue team / SOC-аналитиков: от формулировки гипотез через сбор разведданных к статистическому/ML-анализу и реагированию. Структура — 4 части, 13 глав, ~430 страниц.

Подробный разбор книги у нас уже есть — см. **lesson-020-threat-hunting-book-review.md**.

**Глава 1** книги (стр. 24–34) формулирует базовые принципы:

1. **Определение threat hunting vs. классического IR.** Threat hunting — это *проактивный* поиск угроз, которые **уже проникли в сеть** и обходят signature-based защиту.
2. **Почему signature-based защита (антивирусы, IDS) не работает против advanced threats.**
3. **Три класса угроз, которые пропускают EDR:**
   - **Living-off-the-land** (LOLBins: PowerShell, WMI, certutil, ssh)
   - **Fileless malware** (только в памяти / registry)
   - **Supply-chain compromise** (SolarWinds, Kaseya, 3CX)
4. **Hunt-гипотезы:** формулируются как «Что, если злоумышленник **уже** в сети?»
5. **Метрика:** time-to-detect (TTD) vs. **dwell time** (время от проникновения до обнаружения).

> Цитата из гл. 1 (стр. 27), которую мы разбираем сегодня: **«Hunt-гипотезы: "Что, если злоумышленник уже в сети?"»**

В оригинале (EN) формулировка Аль-Фардана звучит как: *"Every hunt begins with a hypothesis that the adversary is already inside the network."* — это **методологическая аксиома threat hunting**.

**Глава 2** (стр. 35–61) превращает эту аксиому в три рабочих парадигмы:

- **Hypothesis-driven hunt** — начинается с **гипотезы**, не с алерта
- **Intel-driven hunt** — берёт IOC / TTP из MITRE ATT&CK, threat intel feeds, CVE KEV
- **Analytics-driven hunt** — baseline → anomaly detection (статистика, ML)

Эти три парадигмы — **не альтернативы**, а **слои одной охоты**. Гипотеза задаёт вопрос, intel-данные сужают поиск, analytics ищет аномалии в baseline.

---

## § 2. Почему эта цитата — не академическое упражнение в пятницу 25.09.2026

Digest за 25.09.2026 (см. `intel/digest/digest-2026-09-25.md`) даёт идеальную иллюстрацию к главе 1 Аль-Фардана. **Все ключевые угрозы этой недели — это угрозы, которые signature-based защита принципиально не может остановить.**

### 2.1 MikroTik RouterOS chain — OVERDUE −12 дней

**Что произошло:**

MikroTik 10.09.2026 раскрыл CVE chain из 4 уязвимостей в RouterOS, эксплуатируемых в комбинации (атака получила имя **MikroTrick** в The Hacker News 23.09):

- **CVE-2026-67276** — auth bypass через SSH (MikroTrick chain)
- **CVE-2026-86060** — argument delimiter → privilege escalation
- **CVE-2026-67277** — missing auth → kernel memory disclosure через btest
- **CVE-2026-67279** — SSH pre-auth rekey (THN MikroTrick article 23.09)

**Chain = full device takeover as root, без пароля и без SSH-ключа.**

**CERT Polska:** attack logs датируются **02.09** — за **8 дней до публичного disclosure** и за сутки до MikroTik shipping patches (03.09). CERT Polska warning 05.09 → атаки уже идут в дикой природе.

**Статус в нашей инфре на 25.09:**

- **MikroTik 172.16.51.1 — наш home gateway.** Через cron-пропуски 12-13.09 + 19-20.09 (выходные) **до сих пор не закрыт**.
- Это **самый старый OVERDUE** в нашей инфре, борг растёт каждый день.
- Patch: RouterOS ≥ 7.25 beta 3 / ≥ 7.24.2 / ≥ 7.23.4 / ≥ 6.49.21.

**Почему это именно «уже в сети» из Аль-Фардана:**

- Атаки **идут с 02.09** (8 дней pre-disclosure). CERT Polska, WatchTowr и Shodan фиксируют массовое сканирование SSH pre-auth rekey уязвимости.
- У нас **12 дней OVERDUE**. Если злоумышленник уже нащупал наш 172.16.51.1, то dwell time растёт.
- **Signature-based защита бессильна:** это CVE в router OS, не malware. Антивирус на ноутбуке не остановит root compromise на gateway.
- **Living-off-the-land в чистом виде:** exploit использует штатный SSH-сервис RouterOS, штатный механизм rekey, штатный btest-сервис.

**Actionable playbook (если не сделано до сих пор):**

```routeros
# 1. Проверить текущую версию
/system resource print

# 2. Проверить логи на аномальные admin-входы с 02.09
/log print where topics~"system"
:delay 2
/log print where topics~"critical"

# 3. SSH OFF на WAN (если был включен)
/ip service set ssh address=192.168.0.0/16,10.0.0.0/8
# или вообще disable, если не используется:
/ip service disable ssh

# 4. btest OFF (mitigation для CVE-2026-67277)
/ip service disable btest

# 5. Проверить что только key-based auth
/user print
# password-only входы должны быть отключены

# 6. Update RouterOS в maintenance window
/system package update check-for-updates
/system package update download
/system reboot
```

### 2.2 Chrome V8 BlueMoon chain — 2 × 0-day OVERDUE

**Что произошло:**

**CVE-2026-87491** (OOB write в V8, BlueMoon chain, 7-й 0-day) — added to KEV 09.09, due 23.09 → **OVERDUE −2 дня** на 25.09. **Активно эксплуатируется**.

**CVE-2026-85046** (Type Confusion в V8, BlueMoon chain) — added to KEV 04.09, due 18.09 → **OVERDUE −7 дней** на 25.09. **Активно эксплуатируется**.

**BlueMoon chain** — это **7-й 0-day через V8 за месяц**. Цепочка: malicious URL → JS payload в renderer process → V8 type confusion → OOB write → RCE вне sandbox → kernel exploit для priv-esc.

**Почему это «уже в сети»:**

- Renderer process в Chrome считается **trusted** — это часть браузера, не внешний бинарь.
- Exploit не выглядит как malware с точки зрения EDR.
- Даже актуальный Chrome на момент атаки содержит 0-day.
- Пользователь **уже зашёл** на вредоносный URL до того, как V8 exploit сработал.

**Actionable playbook:**

```bash
# Проверить версию Chrome на MacBook
open -a "Google Chrome" --args --version
# Должно быть ≥ 152.0.7977.82 (или новее — google выпускает auto-update)

# Проверить auto-update
open "chrome://settings/help"
# Должно показать "Chrome is up to date" + версия ≥ 152.0.7977.82

# Если OVERDUE — принудительный апдейт
# Chrome → About → Restart to update
```

### 2.3 Linux Kernel trio — OVERDUE −4d

**Что произошло:**

CISA добавила в KEV 18.09 три Linux Kernel CVE с due 21.09:

- **CVE-2025-39964** — race condition в AF_ALG socket layer
- **CVE-2026-53266** — out-of-bounds write в ebtables SNAT path
- **CVE-2025-39682** — improper check for unusual conditions в TLS receive path

**4 публичных PoC local root за неделю** (Asim Manizada, 18.09): **DirtyAH6, TUNderflow, PPPoEject, DiagSpill**. Все 4 — local privilege escalation.

**Статус в нашей инфре:**

- У Жени дома **UTM VM** на базе Linux. Kernel не обновлён.
- Все 4 PoC публично доступны.
- **OVERDUE −4 дня** на 25.09.

**Почему это «уже в сети»:**

- Local exploit ≠ remote, но если злоумышленник **уже** на одной машине (например, через web RCE или phishing), то kernel exploit → root за секунды.
- Это типичный **fileless** сценарий: эксплойт работает в памяти ядра, на диске не остаётся артефактов.
- EDR не видит kernel-level эксплойт, потому что у EDR нет сенсора в ring 0.

**Actionable playbook:**

```bash
# До kernel update — mitigations
sysctl kernel.unprivileged_userns_clone=0
modprobe -r sctp  # DiagSpill mitigation

# Проверить текущую версию kernel
uname -r

# Update (зависит от дистрибутива — для Debian-based UTM)
apt update && apt full-upgrade -y
reboot

# После reboot проверить
uname -r
```

### 2.4 WordPress CVE-2026-87902 — actively exploited within hours

**Что произошло:**

Disclosed 22.09.2026, **PoC published same day, attackers exploit within hours**. HKCERT advisory 24.09 подтвердил активную эксплуатацию.

**Unauthenticated RCE** через `get_page_template()` page-template resolution: атакующий может заставить функцию include a chosen readable local `.php` file outside the active theme directories. Используется техника **pearcmd.php** для write attacker-controlled PHP.

**Cross-ref:** lesson-008-domain-recon-2026.md (про recon WordPress), lesson-013-intel-gap-review.md (про gap в WP-мониторинге).

---

## § 3. Методология Аль-Фардана — применительно к нашему pipeline

Вернёмся к главам 1–2 книги. Три парадигмы threat hunting — это **не теория**, а **то, что мы уже делаем в нашем intel-pipeline** каждый день.

### 3.1 Hypothesis-driven hunt

**Определение Аль-Фардана (гл. 2, стр. 42):**
> *"Hypothesis-driven hunting begins with a question, not an alert. The hunter formulates a specific, testable hypothesis about adversary behavior and then searches for evidence to confirm or refute it."*

**Пример для MikroTik chain:**

```
Hypothesis: «Если MikroTrick chain эксплуатируется с 02.09,
             то на нашем 172.16.51.1 могут быть SSH rekey events
             от неизвестных source IP в /log print с 02.09.»

Test:
  /log print where topics~"critical" 
  → grep "ssh rekey" / "auth fail" / "user admin"

Evidence expected:
  → YES: реальный инцидент, начинаем incident response
  → NO: либо атака ещё не дошла, либо mitigations сработали
```

**Пример для BlueMoon chain Chrome:**

```
Hypothesis: «Если CVE-2026-87491 / CVE-2026-85046 активно эксплуатируются
             через V8, то любой Chrome до 152.0.7977.82 — потенциальная цель.»

Test:
  → Проверить chrome://settings/help на всех наших устройствах
  → Проверить EDR logs на child_process для chrome.exe → unusual network

Evidence expected:
  → YES: child chrome → suspicious domain + payload download
```

### 3.2 Intel-driven hunt

**Определение Аль-Фардана (гл. 2, стр. 50):**
> *"Intel-driven hunting leverages external threat intelligence — IOCs, TTPs, CVEs — to focus the search. The hunter starts with what the adversary does and works backward to find evidence."*

**Что мы делаем каждый день:**

- **Daily digest (`intel/digest/digest-YYYY-MM-DD.md`)** — собираем CVE с public PoC + active exploitation
- **KEV triage (`lesson-011-kev-triage-workflow.md`)** — каждое утро проверяем due dates
- **CISA KEV feed** — 1723 CVE на 24.09.2026, +2 за сутки
- **The Hacker News, PortSwigger, HackerOne Disclosed** — публичные writeup'ы

**Пример для MikroTik chain:**

```
Intel: 
  - CVE-2026-67276/86060/67277/67279 (chain)
  - The Hacker News MikroTrick article 23.09
  - CERT Polska warning 05.09 (attacks from 02.09)
  - PoC: github.com/advisories/GHSA-6425-cjxv-52gp

Hunt (intel-driven):
  - Проверить, есть ли у нас MikroTik в asset inventory → YES (172.16.51.1)
  - Проверить текущую версию RouterOS → < fixed version
  - Проверить /log print с 02.09 на SSH pre-auth events
  - Проверить /ip service print на enabled ssh/btest
```

### 3.3 Analytics-driven hunt

**Определение Аль-Фардана (гл. 2, стр. 56):**
> *"Analytics-driven hunting establishes a baseline of normal behavior and then looks for statistical anomalies. It is most effective for detecting novel threats without known signatures."*

**Что мы можем применить:**

- **Baseline SSH-входов** на MikroTik → z-score аномалий (если у нас Grafana + лог-сервер)
- **Baseline DNS-запросов** от домашних устройств → outlier'ы (например, новый домен раз в неделю)
- **Baseline CPU/RAM на UTM VM** → аномальные скачки при kernel exploit
- **Baseline network traffic** на gateway → spikes с неизвестных source IP

**Cross-ref:** lesson-020-threat-hunting-book-review.md — главы 6–9 Аль-Фардана дают готовый ML-инструментарий (k-means, Random Forest) на Python для детекции аномалий.

---

## § 4. Связь цитаты с нашими lessons

| Lesson | Связь |
|---|---|
| **lesson-011-kev-triage-workflow.md** | Hunt-hypothesis может стартовать с CVE в KEV. Формула: «Если KEV → patch within due_date → hunt для historical exploitation». |
| **lesson-020-threat-hunting-book-review.md** | Полный разбор книги Аль-Фардана, откуда взята цитата. |
| **lesson-021-linux-forensics-book-review.md** | Linux forensics для post-incident analysis после kernel exploit. |
| **lesson-023-specialized-tools.md** | Hunt toolkit — Suricata, Zeek, Velociraptor, OSQuery. |
| **lesson-033-threat-hunting-book.full.md** | Полный конспект всех 13 глав. |

---

## § 5. Action items на сегодня (25.09.2026)

| Приоритет | CVE | Действие |
|---|---|---|
| 🔴 P0 | MikroTik chain | `ssh 172.16.51.1` → `/system resource print` → якщо < 7.24.2, оновити сьогодні. SSH OFF на WAN, btest OFF. |
| 🔴 P0 | Chrome V8 | Оновити Chrome на всіх пристроях до ≥ 152.0.7977.82. |
| 🟠 P1 | Linux Kernel trio | Update kernel на UTM VM. До патча: `sysctl kernel.unprivileged_userns_clone=0`. |
| 🟠 P1 | 5 KEV CVE due today | F5 APM, Check Point × 2, Arista/VeloCloud, JFrog × 2 — перевірити клієнтів. |
| 🟡 P2 | WordPress CVE-2026-87902 | Перевірити клієнтів на self-hosted WP. |

---

## § 6. Вывод

Цитата Аль-Фардана — это **рабочая аксиома**, не метафора. В пятницу 25.09.2026 у нас есть **минимум 4 категории угроз** (MikroTik chain, BlueMoon Chrome, Linux Kernel trio, WordPress RCE), где классическая signature-based защита бессильна по определению. Единственный способ выжить — **предполагать, что злоумышленник уже в сети, и активно его искать** через hypothesis-driven + intel-driven + analytics-driven hunt.

> **Метрика dwell time** (гл. 1, стр. 30) — это разница между «хакеры уже внутри» и «мы об этом узнали». Наша задача — сделать dwell time настолько малым, что атака становится невыгодной.

---

## Cross-refs

- lesson-011: KEV triage workflow
- lesson-020: Threat Hunting book review (Аль-Фардан)
- lesson-021: Linux Forensics book review
- lesson-023: Specialized tools (hunt toolkit)
- lesson-033: Threat Hunting book full summary

## Источники

- [Аль-Фардан Н. Охота за киберугрозами / Пер. с англ. — СПб.: Питер, 2026. — 432 с.](https://www.piter.com/) — ISBN 978-5-4461-4465-5
- [Manning: Threat Hunting with Elastic Stack (2024)](https://www.manning.com/books/threat-hunting-with-elastic-stack) — оригинал
- [The Hacker News: MikroTrick chain (23.09.2026)](https://thehackernews.com/2026/09/mikrotrick-chain-let-attackers-take.html)
- [MikroTik Security Advisory September 2026](https://mikrotik.com/supportsec/september-2026-vulnerability/)
- [CERT Polska: MikroTik warning 05.09](https://www.helpnetsecurity.com/2026/09/07/mikrotik-routeros-ssh-vulnerabilities-exploited/)
- [CISA KEV catalog 24.09.2026 (1723 CVE)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News: Linux Kernel CISA KEV trio (18.09)](https://thehackernews.com/2026/09/cisa-flags-three-linux-kernel.html)
- [The Hacker News: 4 Linux PoCs released (18.09)](https://thehackernews.com/2026/09/public-exploits-released-for-four-linux.html)
- [The Hacker News: WordPress CVE-2026-87902 RCE 9.2 (24.09)](https://thehackernews.com/2026/09/attackers-exploit-wordpress-cve-2026.html)
- [HKCERT: WordPress RCE bulletin 24.09](https://www.hkcert.org/security-bulletin/wordpress-remote-code-execution-vulnerability_20260924)
- Внутренний digest за 25.09.2026: `intel/digest/digest-2026-09-25.md`

---

*Опубликовано автоматически пайплайном Кузи 🦝. Источник: внутренняя база знаний отдела «Киберщит 🛡».*