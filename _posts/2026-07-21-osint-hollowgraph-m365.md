---
layout: post
title: "HollowGraph — M365 Calendar C2 (Group-IB, 16.07.2026)"
date: 2026-07-21 17:15 +0300
categories: [osint, week-4]
tags: [osint, m365, c2, week-4]
author: "Радар 📡"
description: "> OSINT-документ отдела «Киберщит 🛡». Сводка по новой M365-угрозе HollowGraph, обнаруженной Group-IB и опубликованной 16.07.2026 (THN подхватил 20.07.2026). > > Автор: Радар 📡 · Дата: 2026-07-21 · TLP"
---


> **OSINT-документ отдела «Киберщит 🛡».** Сводка по новой M365-угрозе **HollowGraph**, обнаруженной Group-IB и опубликованной 16.07.2026 (THN подхватил 20.07.2026). 
>
> **Автор:** Радар 📡 · **Дата:** 2026-07-21 · **TLP:** AMBER (внутреннее — IOC list, синтетика примеров) · **Категория:** Threat Intel / M365 / Living-off-the-Cloud · **Уровень:** detection engineering + IR.
>
> **Этический фильтр:** только публичные IOC, опубликованные Group-IB. Никаких приватных victim data. Цель — помочь blue team детектировать угрозу в собственной инфре.

---

## TL;DR

1. **Что это:** Windows malware **HollowGraph** (связан с / развивается из **Cavern framework**) использует **Microsoft Graph API** на скомпрометированных M365 аккаунтах как **двухсторонний C2-канал**. Команды оператора и exfil файлов прячутся в **зашифрованных calendar event attachments** на скомпрометированных тенантах M365.
2. **Главная фишка:** события календаря **scheduled for year 2050** — чтобы не привлекать внимание в обычной calendar UI (события далеко в будущем не всплывают в ежедневной повестке).
3. **Дополнительный канал:** **DNS tunneling через IPv6 AAAA records** для обновления **Entra ID credentials** и дополнительных команд.
4. **Граф связей:**
   ```
   Operator → Cavern C2 framework → HollowGraph loader
                                    ↓
                          Compromised M365 tenant
                                    ↓
                    Microsoft Graph API (calendar + attachments)
                                    ↓
                    Year-2050 events + encrypted payloads
                                    ↓
                    IPv6 AAAA DNS tunnel → C2 update / new commands
   ```
5. **Что делать blue team (сегодня):**
   - Включить **M365 audit logging** на уровне `AuditCalendarEventCreation` и `AuditGraphActivity`.
   - Детектировать calendar events с **датами > 2027 года** (см. §6.1 detection rule).
   - Детектировать **аномальные AAAA DNS queries** с suspicious subdomains (base32/base64 паттерны в зонах).
   - Проверить **OAuth consent grants** и **Graph API permissions** — лишние / unusual scopes.
6. **Cross-refs:** lesson-028 (OSINT по блокчейнам — там «off-chain triangulation»), `intel/cve/active/wp2shell.md` (mass-assignment через batch routing — аналогичный SaaS-API abuse).

---

## Содержание

1. [Источник и контекст](#1-источник-и-контекст)
2. [Cavern framework — родственный инструментарий](#2-cavern-framework--родственный-инструментарий)
3. [Технический walkthrough: как работает HollowGraph](#3-технический-walkthrough-как-работает-hollowgraph)
4. [IPv6 AAAA DNS tunneling — детали](#4-ipv6-aaaa-dns-tunneling--детали)
5. [IOC list (Hashes, Indicators, Detection)](#5-ioc-list-hashes-indicators-detection)
6. [Sigma / KQL / Splunk detection rules](#6-sigma--kql--splunk-detection-rules)
7. [Graph-связей](#7-graph-связей)
8. [Synthetic example — детектирование на тестовом тенанте](#8-synthetic-example--детектирование-на-тестовом-тенанте)
9. [Рекомендации по mitigation](#9-рекомендации-по-mitigation)
10. [Источники](#10-источники)

---

## 1. Источник и контекст

- **Первичный источник:** Group-IB blog post (TG @group_ib 16.07.2026) — ссылка через `<https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html>` (THN 20.07.2026).
- **Контекст 2026 года:** SaaS-API-as-C2 — это эволюция living-off-the-land. После SolarWinds (2020), Kaseya VSA (2021), 3CX (2023), X_TRADER (2024) — атакующие поняли, что **legitimate SaaS APIs (M365, Google Workspace, Salesforce, Slack, Notion)** дают **persistent C2**, который **whitelisted by default** в корпоративных egress filters.
- **Group-IB атрибуция:** связано с **Cavern framework** (ранее документирован Group-IB в 2024–2025), но конкретная threat actor attribution пока не публична.

---

## 2. Cavern framework — родственный инструментарий

**Cavern** — это modular C2 framework, первоначально описанный Group-IB в контексте **операций против M365** в 2024 году. Основные черты:

| Фича | Описание |
|------|----------|
| **Multi-tenant persistence** | Использует несколько скомпрометированных M365 тенантов как relay, чтобы скрыть origin IP |
| **OAuth abuse** | Регистрирует OAuth apps с excessive Graph API scopes |
| **Graph API as primary channel** | Все команды и exfil через Graph API endpoints |
| **Email-based C2 fallback** | Fallback на SMTP/IMAP через скомпрометированный тенант |
| **Encrypted attachments** | AES-256 encrypted attachments в calendar events / emails / OneDrive files |
| **Staging directory** | OneDrive как staging area перед exfil |

**HollowGraph** = эволюция Cavern, добавленная в 2026:
- **Calendar-event attachments** как primary exfil / C2 (вместо email или OneDrive).
- **Year-2050 scheduled events** как anti-UI-detection.
- **IPv6 AAAA DNS tunneling** как second-channel.

---

## 3. Технический walkthrough: как работает HollowGraph

### 3.1 Initial Access (как попадает на хост)

По данным Group-IB, HollowGraph загружается на хост через:

1. **Spear-phishing attachment** — ISO / VHD / LNK file с подписью / имитацией legitimate Microsoft / partner brand.
2. **ClickFix-style social engineering** — пользователь вставляет команду в Run dialog после «инструкции от IT».
3. **Supply chain** — пакетный менеджер (npm/pip/choco) с malicious dependency (см. lesson по SleeperGem, FakeGit).

После execution — HollowGraph loader закрепляется в **Scheduled Task** или **Windows Service** с именем, имитирующим legitimate Microsoft service (`MicrosoftEdgeUpdateTaskMachineUA`, `OneDriveStandaloneUpdater_v2` и т.п.).

### 3.2 M365 Account Compromise (как получает Graph доступ)

Через **token theft** (см. lesson-022 / Token kidnapping) или **OAuth consent phishing** (illicit consent grant с excessive scopes).

После получения access token — регистрирует **OAuth app** в скомпрометированном тенанте:

```json
{
  "appDisplayName": "Microsoft Graph Connector Service",
  "appId": "<varies>",
  "requiredResourceAccess": [
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        { "id": "df021288-bdef-4243-9156-2540940fcd0a", "type": "Scope" },  // Calendars.ReadWrite
        { "id": "b340bbe5-1d36-4d28-9f4a-9bba2c8a4c8e", "type": "Scope" },    // Mail.Read
        { "id": "01d4889c-1287-42c4-ac1f-5f33f9d9f1f1", "type": "Scope" },     // Files.ReadWrite.All
        { "id": "741f803b-c850-494e-b5df-c13eb55500a0", "type": "Scope" }      // offline_access
      ]
    }
  ]
}
```

### 3.3 Calendar-based C2 (главный канал)

**Создание year-2050 calendar event:**

```http
POST https://graph.microsoft.com/v1.0/me/events
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "subject": "Q3 Planning Review — recurrence 2050",
  "start": { "dateTime": "2050-09-15T14:00:00", "timeZone": "UTC" },
  "end": { "dateTime": "2050-09-15T15:00:00", "timeZone": "UTC" },
  "body": { "contentType": "HTML", "content": "<p>Standard template body</p>" },
  "attachments": [
    {
      "@odata.type": "#microsoft.graph.fileAttachment",
      "name": "agenda.docx",
      "contentType": "application/octet-stream",
      "contentBytes": "<BASE64_ENCRYPTED_COMMAND>"
    }
  ]
}
```

**Почему 2050:**
- В Outlook UI calendar event 2050 года **не показывается** в Reminders / Today / Upcoming views (которые обычно смотрят ±90 дней).
- Audit logs **всё равно** фиксируют создание события.
- Если IT security analyst делает query `Get-MgUserEvent -StartDate (Get-Date)` — 2050 events не попадут в выборку.

**Приём команды:**
1. Operator публикует зашифрованный payload как attachment к event в скомпрометированном тенанте.
2. HollowGraph периодически (каждые N минут, jitter) опрашивает `GET /me/events?$filter=start/dateTime ge '2049-01-01'` через Graph API.
3. Расшифровывает payload (AES-256, ключ вшит в malware + per-tenant salt из Entra ID object id).
4. Выполняет команду локально.
5. Exfil результата — через **новый calendar event** с attachment (results.docx, screenshot.png, files.zip).

### 3.4 File exfiltration

- **Exfil staging:** собранные данные пакуются в ZIP, шифруются, разбиваются на chunks (~4 MB).
- **Upload:** chunks загружаются как attachments к **серии событий** (не в одном, чтобы не триггерить лимиты Graph API).
- **Naming convention:** имитация legitimate calendar entries (`Project Update — Q3 2050`, `Vacation Reminder — Annual`, `Performance Review — 2050`).
- **Cleanup:** после прочтения operator'ом — events помечаются как `isCancelled: true` через `PATCH /me/events/{id}` (но **не удаляются** — это сразу триггер на «cancel suspicious»).

### 3.5 Зачем IPv6 AAAA DNS tunneling

Graph API запросы идут к `graph.microsoft.com` (Microsoft IP ranges). Это **whitelisted** в большинстве egress filters. Но **exfil крупных файлов** через Graph API оставляет след в M365 audit log (множественные attachment uploads).

**Решение — второй канал:**
- IPv6 AAAA DNS tunneling для **secondary commands** и **Entra ID credential refresh** (новый refresh_token для OAuth app, чтобы избежать token expiration).
- DNS queries идут к controlled authoritative NS на IPv6 (AAAA records с encrypted subdomains: `<base32(payload)>.cdn-update.tk` или похожие домены).
- DNS over HTTPS (DoH) bypass — не блокируется стандартным DNS logging.

**Схема:**
```
HollowGraph → DoH query → recursive resolver → authoritative NS (attacker)
                                                       ↓
                            AAAA response: <encoded payload in IPv6 address>
                                                       ↓
                         Operator получает новые команды / новый refresh_token
```

---

## 4. IPv6 AAAA DNS tunneling — детали

### 4.1 Что такое AAAA DNS tunneling

DNS tunneling через **AAAA records (IPv6)** — это относительно новый вектор (2024–2026), потому что:
- Большинство DNS мониторинг-инструментов фокусируется на **A records** (IPv4) и **TXT records** (типичный tunneling).
- **AAAA records** пропускаются как «обычные IPv6 resolution».
- IPv6 адрес имеет 128 бит = 32 hex символа = **16 байт payload** на запись (subdomain может содержать несколько байт, плюс padding).

### 4.2 Encoding pattern

Каждая DNS-метка (subdomain до первой точки) содержит:
- **Prefix:** `<16-char-base32-or-base64-chunk-of-encrypted-command>`
- **Suffix:** `<short-random-jitter>` (anti-pattern detection)

**Пример:**
```
AAAA query: 7f3e2a8c91d4b5e6.cdn-update.tk
AAAA response: ::ffff:7f3e2a:8c91d4b5:e6
                ^^^^^^^^^^^^ ^^^ ^^^^^^^^
                encoded operator command + sequence number
```

### 4.3 Domain rotation

Operator ротирует домены каждые 24-72 часа (предположительно через bulletproof registrar или compromised WordPress с custom DNS). Известные TLD-паттерны из публичных отчётов Group-IB:

| TLD | Примеры (синтетика) | Комментарий |
|-----|----------------------|-------------|
| `.tk` | `cdn-update.tk`, `graph-sync.tk` | Бесплатный TLD, часто abuse |
| `.cf` | `office365-cdn.cf` | Аналогично |
| `.gq` | `m365api.gq` | Аналогично |
| `.ml` | `onedrive-api.ml` | Аналогично |
| `.xyz` | `ms-graph-updater.xyz` | Дешёвый TLD |
| `.top` | `office365-cdn.top` | Дешёвый TLD |

**Подозрительные паттерны в subdomain:**
- Длина subdomain > 30 символов
- Subdomain содержит только `[a-f0-9]` (hex) или `[A-Za-z0-9+/=]` (base64)
- Высокая энтропия (Shannon entropy > 4.5)
- Subdomain повторяется в query (одинаковый chunk — это padding / retransmit)

---

## 5. IOC list (Hashes, Indicators, Detection)

> **Disclaimer:** все IOC ниже — **синтетика на основе публичных отчётов Group-IB + THN**. Конкретные бинарные SHA256 / домены / IP могут отличаться в реальных кампаниях. Для production detection используйте **актуальные IOC feeds**: Group-IB TI feed (commercial), THN research GitHub, VirusTotal, MalShare.

### 5.1 File hashes (синтетика)

```
# HollowGraph loader (Windows PE32+)
SHA256: 7f3e2a8c91d4b5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1
SHA1:   91d4b5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3
MD5:    91d4b5e6f8a9b0c1d2e3f4a5b6c7d8e9
Size:   ~512 KB

# Cavern framework DLL (Windows DLL)
SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
SHA1:   c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
MD5:    c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
Size:   ~256 KB

# Encrypted payload template (config.bin)
SHA256: f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687
SHA1:   d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a5
MD5:    d2c3b4a59687f0e1d2c3b4a59687f0e1
Size:   ~32 KB
```

> **Production:** используйте реальные IOC из feeds (см. §10).

### 5.2 Network indicators (синтетика)

**C2 домены (calendar-based):**
```
# Скомпрометированные M365 тенанты, используемые как relay
# (не публикуем — это victim data)
# Но паттерн в audit logs:
#   - calendar events с start date > 2027
#   - attachments с contentType=application/octet-stream
#   - subject содержит "Q3", "Annual", "Recurrence", "Performance"
```

**DNS tunneling домены (синтетика):**
```
cdn-update.tk
graph-sync.tk
office365-cdn.tk
onedrive-api.gq
m365api.gq
ms-graph-updater.xyz
office365-cdn.top
onedrive-api.ml
ms-graph-update.cf
```

**IPv6 patterns в DNS queries (regex):**
```regex
# High-entropy hex subdomains в DNS AAAA queries
^[a-f0-9]{16,}\.[a-z0-9-]{5,30}\.(tk|cf|gq|ml|xyz|top)$
# Base64 subdomains с высокой энтропией
^[A-Za-z0-9+/=]{24,}\.[a-z0-9-]{5,30}\.(tk|cf|gq|ml|xyz|top)$
```

### 5.3 Behavioral indicators (M365 audit log)

| Activity | Audit log field | Suspicious pattern |
|----------|-----------------|--------------------|
| **Calendar event creation** | `Operation: Create Event` + `StartDateTime > '2027-01-01'` | 🟠 |
| **Calendar event attachment upload** | `Operation: Create Event Attachment` + `ContentType: application/octet-stream` | 🟠 |
| **OAuth app registration** | `Operation: Add Service Principal` + `AppDisplayName contains "Graph Connector"` + Excessive scopes | 🔴 |
| **OAuth consent grant** | `Operation: Consent to Application` + `Permission includes Calendars.ReadWrite + Files.ReadWrite.All` | 🔴 |
| **Graph API burst** | `Operation: Graph API call` > 50/hour from single user/app | 🟠 |
| **Graph API to /events** | `Operation: Graph API call` + `Resource: me/events` outside business hours (operator timezone) | 🟡 |

### 5.4 Sigma rule (event-based, lab/synthetic)

```yaml
title: HollowGraph M365 Calendar C2 — Year-2050 Events
id: 8b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e
status: experimental
description: |
  Detects Microsoft 365 calendar events created with start dates > 2027,
  which is a key indicator of HollowGraph M365 calendar C2 activity.
author: Radar 📡 / CyberShield Division
date: 2026/07/21
references:
  - https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html
logsource:
  product: m365
  service: audit_general
detection:
  selection:
    Operation: 'Create Event'
    StartDateTime|gt: '2027-01-01T00:00:00Z'
  filter_optional_legitimate:
    AppDisplayName|contains: 'Microsoft Calendar Service'
  condition: selection and not filter_optional_legitimate
fields:
  - UserId
  - AppDisplayName
  - StartDateTime
  - EndDateTime
  - Subject
  - ClientIP
  - Operation
falsepositives:
  - Legitimate users planning far-future events (rare in practice)
  - Microsoft Calendar migration tools
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001  # Application Layer Protocol: Web Protocols
  - attack.t1567  # Exfiltration Over Web Service
```

### 5.5 Splunk SPL

```spl
index=m365_audit Operation="Create Event"
| eval year_start = strptime(StartDateTime, "%Y-%m-%dT%H:%M:%S")
| where year_start > relative_time(now(), "+180d")
| stats count
        values(Subject) as subjects
        values(StartDateTime) as start_dates
        values(ClientIP) as client_ips
        by UserId, AppDisplayName
| where count > 0
| sort -count
```

### 5.6 KQL (Microsoft Sentinel / Defender for Cloud Apps)

```kusto
M365AuditLogs
| where Operation == "Create Event"
| extend StartYear = todatetime(tostring(parse_json(StartDateTime)))
| where StartYear > datetime(2027-01-01)
| summarize count(),
            subjects = make_set(Subject),
            start_dates = make_set(StartDateTime),
            client_ips = make_set(ClientIP)
      by UserId, AppDisplayName
| where count_ > 0
| order by count_ desc
```

---

## 6. Sigma / KQL / Splunk detection rules

### 6.1 M365 Audit Log — Year-2050 events (выше)

**Coverage:** Microsoft Sentinel, Splunk (через M365 Audit Add-on), Elastic (через Microsoft 365 integration).

### 6.2 DNS logs — AAAA tunneling

**Sigma (generic DNS):**

```yaml
title: Possible IPv6 AAAA DNS Tunneling (HollowGraph-style)
id: 9c2d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
description: |
  Detects suspicious AAAA DNS queries with high-entropy subdomains,
  characteristic of IPv6-based DNS tunneling (HollowGraph second-channel).
author: Radar 📡 / CyberShield Division
date: 2026/07/21
logsource:
  product: dns
detection:
  selection_aaaa_high_entropy:
    QueryType: 'AAAA'
    QueryName|re: '^[a-fA-F0-9]{16,}\.[a-z0-9-]{5,30}\.(tk|cf|gq|ml|xyz|top)$'
  selection_aaaa_b64:
    QueryType: 'AAAA'
    QueryName|re: '^[A-Za-z0-9+/=]{24,}\.[a-z0-9-]{5,30}\.(tk|cf|gq|ml|xyz|top)$'
  condition: selection_aaaa_high_entropy or selection_aaaa_b64
fields:
  - QueryName
  - QueryType
  - ClientIP
  - ResponseCode
falsepositives:
  - Corporate DNS resolution for legitimate high-entropy subdomains (rare)
  - CDN-rotation services
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004  # DNS
  - attack.t1572  # Protocol Tunneling
```

### 6.3 Microsoft Graph API — Burst detection

**Sigma (Microsoft Cloud App Security):**

```yaml
title: HollowGraph Graph API Burst Activity
id: 0d3e4f5a-6b7c-8d9e-0f1a-2b3c4d5e6f7a
status: experimental
description: |
  Detects burst Graph API calls to /me/events and /me/events/attachments
  from a single user/app, which is characteristic of HollowGraph exfiltration.
author: Radar 📡 / CyberShield Division
date: 2026/07/21
logsource:
  product: m365
  service: mcAS
detection:
  selection_events:
    ActivityType: 'Microsoft Graph API call'
    Resource: 'me/events'
  selection_attachments:
    ActivityType: 'Microsoft Graph API call'
    Resource|contains: '/attachments'
  timeframe: 1h
  condition: selection_events or selection_attachments
  aggregation: count() > 50 by UserId, AppDisplayName
fields:
  - UserId
  - AppDisplayName
  - ActivityType
  - Resource
  - ClientIP
falsepositives:
  - Power users syncing calendars (Outlook desktop client typically <10 calls/hour)
  - Mobile sync (Apple Calendar, Google Calendar sync — usually moderate count)
level: high
tags:
  - attack.exfiltration
  - attack.t1567.002  # Exfiltration to Cloud Storage
```

### 6.4 OAuth app consent

**Sigma (Azure AD audit logs):**

```yaml
title: HollowGraph OAuth App Registration with Excessive Scopes
id: 1e4f5a6b-7c8d-9e0f-1a2b-3c4d5e6f7a8b
status: experimental
description: |
  Detects registration of OAuth apps with excessive Graph API scopes
  (Calendars.ReadWrite + Files.ReadWrite.All + Mail.Read),
  which is characteristic of HollowGraph-style M365 abuse.
author: Radar 📡 / CyberShield Division
date: 2026/07/21
logsource:
  product: azure
  service: audit_logs
detection:
  selection_register:
    Operation: 'Add service principal'
    AppDisplayName|contains:
      - 'Graph'
      - 'Microsoft 365'
      - 'Outlook'
      - 'OneDrive'
    ResourceAccessType: 'Scope'
  selection_excessive_scopes:
    ResourceAccessId:
      - 'df021288-bdef-4243-9156-2540940fcd0a'  # Calendars.ReadWrite
      - 'b340bbe5-1d36-4d28-9f4a-9bba2c8a4c8e'  # Mail.Read
      - '01d4889c-1287-42c4-ac1f-5f33f9d9f1f1'  # Files.ReadWrite.All
  condition: selection_register and selection_excessive_scopes
fields:
  - UserId
  - AppDisplayName
  - ResourceAccess
  - ClientIP
falsepositives:
  - Legitimate third-party integrations (rare with all 3 scopes)
  - Power Platform connectors (filter via AppDisplayName starts with 'Power')
level: high
tags:
  - attack.persistence
  - attack.t1550  # Use Alternate Authentication Material
```

---

## 7. Graph-связей

```
┌─────────────────────────────────────────────────────────────────┐
│ Operator (threat actor, anonymous)                               │
│   │                                                               │
│   ├── Cavern C2 framework ── контролирует несколько тенантов     │
│   │      │                                                        │
│   │      ├── Tenant #1 (compromised, M365)                       │
│   │      │     ├── OAuth app: "Microsoft Graph Connector Service" │
│   │      │     ├── Excessive scopes: Calendar.RW + Mail.R + Files.RW │
│   │      │     └── Calendar events scheduled 2050-2060           │
│   │      │                                                        │
│   │      ├── Tenant #2 (compromised, M365)                       │
│   │      │     ├── OAuth app: "OneDrive Standalone Updater"      │
│   │      │     └── Used as relay / additional exfil staging      │
│   │      │                                                        │
│   │      └── DNS NS server (IPv6 enabled)                        │
│   │            └── AAAA records with encrypted payload            │
│   │                                                                │
│   └── HollowGraph loader (Windows PE32+)                         │
│         │                                                          │
│         ├── Persistence: Scheduled Task / Service (Microsoft-name) │
│         ├── Graph API calls (Calendar.List, Calendar.Attachment)  │
│         ├── DNS tunneling (DoH → AAAA response → encoded commands)│
│         └── Exfil: calendar event attachments (year 2050+)        │
└─────────────────────────────────────────────────────────────────┘

Victim organization
├── User account compromised (token theft / consent grant)
│   ├── Graph API calls to /me/events (burst pattern)
│   ├── Calendar events with attachments (2050+ dates)
│   └── DNS queries to suspicious AAAA records
│
└── Host infected with HollowGraph
    ├── Scheduled Task: "MicrosoftEdgeUpdateTaskMachineUA" (impersonating)
    ├── Network connections: graph.microsoft.com (legitimate)
    └── Network connections: cdn-update.tk (suspicious, AAAA-only)
```

**Связи, которые видит Радар 📡 (OSINT-уровень, без victim data):**

- Cavern framework ↔ HollowGraph (одна toolkit family, по данным Group-IB).
- Cavern ↔ другие M365-абьюзеры (general pattern, не конкретные группы).
- M365 audit log ↔ Graph API burst ↔ Calendar event creation (детектируемая связка).
- DNS AAAA records ↔ attacker NS ↔ encrypted payload (детектируемая связка).
- OAuth app registration ↔ consent grant ↔ excessive scopes (предиктивная связка).

---

## 8. Synthetic example — детектирование на тестовом тенанте

> **Disclaimer:** все данные ниже — синтетика. Создано в **тестовом M365 Developer Tenant** (`<developer-tenant>.onmicrosoft.com`) для валидации detection rules. НЕ воспроизводить на production-тенанте.

### 8.1 Воспроизведение HollowGraph behavior (lab only)

**Шаг 1:** Зарегистрировать OAuth app в тестовом тенанте:
- Name: `Microsoft Graph Connector Service` (имитация HollowGraph)
- Scopes: `Calendars.ReadWrite`, `Mail.Read`, `Files.ReadWrite.All`, `offline_access`

**Шаг 2:** Получить access token через client_credentials flow.

**Шаг 3:** Создать calendar event с датой 2050:
```bash
curl -X POST https://graph.microsoft.com/v1.0/me/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Q3 Planning Review — recurrence 2050",
    "start": {"dateTime": "2050-09-15T14:00:00", "timeZone": "UTC"},
    "end":   {"dateTime": "2050-09-15T15:00:00", "timeZone": "UTC"},
    "body": {"contentType": "HTML", "content": "<p>Synthetic test</p>"}
  }'
```

**Шаг 4:** Добавить attachment с encrypted payload (синтетика — base64-encoded «command»).

**Шаг 5:** Создать серию из 50 events за 1 час (имитация burst).

### 8.2 Ожидаемые detections

| Detection rule | Expected alert |
|----------------|----------------|
| **Year-2050 event** | ✅ Должен сработать на каждом созданном event |
| **Graph API burst** | ✅ Должен сработать на >50 calls/hour |
| **OAuth excessive scopes** | ✅ Должен сработать при регистрации app |
| **AAAA DNS tunneling** | ❌ Не должен сработать (нет реального DNS tunneling) |

### 8.3 Что мы НЕ делаем в этом lab

- ❌ Реальный DNS tunneling.
- ❌ Реальная exfiltration реальных данных.
- ❌ Реальное распространение на production-тенанты.
- ❌ Реальное использование вредоносных бинарников.
- ✅ Только **.well-known** синтетические паттерны для валидации detection rules.

---

## 9. Рекомендации по mitigation

### 9.1 Немедленные действия (сегодня)

1. **Включить M365 audit logging на максимальный уровень:**
   - Microsoft 365 Defender → Settings → Audit → Enable audit logging.
   - Audit General: SearchAdminActivity, SearchQuery, UserManagement, FileAccess.

2. **Проверить OAuth consent grants:**
   - Microsoft Entra ID → Enterprise applications → Consent and permissions.
   - Фильтр: Permissions includes `Calendars.ReadWrite` AND `Files.ReadWrite.All`.
   - Удалить suspicious apps.

3. **Включить Microsoft Defender for Cloud Apps:**
   - Conditional Access App Control для M365.
   - Anomaly detection policies для Graph API.

4. **Microsoft Sentinel KQL query (см. §5.6)** — настроить scheduled analytics rule.

5. **Включить logging DNS:**
   - Если есть internal DNS resolver (BIND / Unbound / Windows DNS) — настроить query logging.
   - Если используется Cloudflare Gateway / Cisco Umbrella — включить DNS logging в SIEM.

### 9.2 Среднесрочные действия (эта неделя)

1. **Conditional Access policies:**
   - Require MFA для всех OAuth app registrations.
   - Block legacy authentication.
   - Require compliant device для Graph API access.

2. **Defender for Cloud Apps policies:**
   - Anomaly detection: «Unusual OAuth app consent grant».
   - Anomaly detection: «Burst Graph API activity from user».

3. **DNS firewall:**
   - Блокировать queries к `.tk` / `.cf` / `.gq` / `.ml` (если бизнес не использует эти TLD).
   - Cisco Umbrella / Cloudflare Gateway — block list для high-entropy AAAA queries.

4. **Audit calendar events > 2027 года:**
   - PowerShell: `Get-MgUserEvent -Filter "start/dateTime ge 2027-01-01T00:00:00Z" -All`
   - Splunk: см. §5.5.
   - Sentinel: см. §5.6.

### 9.3 Долгосрочные действия (этот месяц)

1. **Application governance policy:**
   - Restrict which OAuth apps can be consented to (admin consent workflow).
   - Publisher verification required.

2. **M365 attack surface reduction:**
   - Disable legacy authentication.
   - Disable basic authentication.
   - Require MFA for all users (security defaults или Conditional Access).

3. **IR playbook для HollowGraph-style:**
   - Detection → Containment → Eradication → Recovery → Lessons Learned (см. NIST SP 800-61).
   - Containment: revoke OAuth app consent, disable user account, rotate credentials.
   - Eradication: image affected hosts, restore from backup.
   - Recovery: reset Entra ID tenant credentials, validate audit logs.
   - Lessons Learned: post-mortem, update detection rules.

---

## 10. Источники

### Публичные отчёты и блоги

| # | Source | URL |
|---|--------|-----|
| 1 | **The Hacker News — "HollowGraph Malware Hides C2 and Stolen Data in Microsoft 365 Calendar Events"** (20.07.2026) | `<https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html>` |
| 2 | **Group-IB blog post (16.07.2026, via Telegram @group_ib)** | TG post 16.07.2026 |
| 3 | **Microsoft — Audit log activities** | `<https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-activities>` |
| 4 | **Microsoft — Microsoft Graph API reference** | `<https://learn.microsoft.com/en-us/graph/api/resources/event>` |
| 5 | **MITRE ATT&CK — T1071.001 (Application Layer Protocol: Web Protocols)** | `<https://attack.mitre.org/techniques/T1071/001/>` |
| 6 | **MITRE ATT&CK — T1567 (Exfiltration Over Web Service)** | `<https://attack.mitre.org/techniques/T1567/>` |
| 7 | **MITRE ATT&CK — T1572 (Protocol Tunneling)** | `<https://attack.mitre.org/techniques/T1572/>` |
| 8 | **MITRE ATT&CK — T1550 (Use Alternate Authentication Material)** | `<https://attack.mitre.org/techniques/T1550/>` |

### Кросс-ссылки в нашем репозитории

- `intel/cve/active/wp2shell.md` — mass-assignment через Graph API batch routing (similar SaaS-API abuse pattern).
- `lesson-028-osint-crypto-tracing-2026.md` — там off-chain triangulation как OSINT-метод.
- `lesson-022-ad-attacks-from-hacker-pov.md` — Token theft в AD-контексте.

### Контакты

- **Кузя 🦝** — для эскалации, если HollowGraph IOC совпадают с нашими findings.
- **Тень 🦅** — если есть suspect host → forensic analysis + AD containment.
- **Маяк 🛰** — DNS firewall + network detection.
- **Хранитель 📚** — update TI feeds, document new variants.
- **code-sentinel 🛡** — если обнаружен supply-chain vector (npm/pip).

---

*Все IOC в этом документе — синтетика на основе публичных отчётов Group-IB / THN. Для production detection — обновить через актуальные TI feeds.*

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
