---
layout: post
title: "Scattered Spider — Decentralized Collective (Group-IB update, 01.07.2026)"
date: 2026-07-21 17:15 +0300
categories: [osint, week-4]
tags: [osint, scattered-spider, apt, week-4]
author: "Радар 📡"
description: "> OSINT-документ отдела «Киберщит 🛡». Обновлённая атрибуция Scattered Spider по данным Group-IB (01.07.2026) + ретроспектива судебных дел (UK Woolwich Crown Court 17.07.2026, US sentencing 2024–2025)."
---


> **OSINT-документ отдела «Киберщит 🛡».** Обновлённая атрибуция **Scattered Spider** по данным Group-IB (01.07.2026) + ретроспектива судебных дел (UK Woolwich Crown Court 17.07.2026, US sentencing 2024–2025).
>
> **Автор:** Радар 📡 · **Дата:** 2026-07-21 · **TLP:** AMBER · **Категория:** Threat Intel / Identity-driven attacks / Ransomware affiliates · **Уровень:** IR + threat modeling.
>
> **Этический фильтр:** только публичные источники — Group-IB, THN, BleepingComputer, US DOJ press releases, UK CPS / NCA. Никаких приватных имен или PII (только публичные имена осуждённых).

---

## TL;DR

1. **Scattered Spider — НЕ single threat actor.** По обновлённой атрибуции Group-IB (01.07.2026) — это **decentralized collective** из independent subclusters с общими TTPs, но **без** единого command structure.
2. **Общие TTPs (характерные для всего коллектива):**
   - **Oktapus-style phishing** (initial access через fake Okta / VPN / helpdesk pages).
   - **SIM-swapping** (bypass SMS-based 2FA на privileged accounts).
   - **Helpdesk vishing** (social engineering IT helpdesk для password reset / MFA reset).
   - **Okta / M365 compromise** (после initial access → escalate к privileged accounts).
   - **VMware ESXi ransomware deployment** (финальный payload — обычно BlackCat/ALPHV или новый вариант).
3. **Судебные дела (2024–2026):**
   - **Owen Flowers (18, UK)** + **Thalha Jubair (20, UK)** — 17.07.2026 приговорены к **5.5 годам** тюрьмы за 2024 TfL hack (£29M damage). **Первые осуждённые** по **Section 3ZA UK Computer Misuse Act**.
   - **Peter Stokes (19, US, «Bouquet»)** — ранее осуждён за атаку на ювелирный магазин (court filing 08.07.2026 раскрыл, что **Windows Device ID** помог FBI с attribution).
4. **Граф связей:** collective ↔ ALPHV/BlackCat (ransomware-as-a-service affiliate), ↔ ShinyHunters (data leak extortion), ↔ Lapsus$ (предыдущее поколение, overlap в TTPs).
5. **Что делать blue team (сегодня):**
   - **Запретить SMS-based 2FA** для privileged accounts (SIM-swap risk).
   - **Helpdesk verification** — обязательная out-of-band verification (видеозвонок / in-person) для password reset / MFA reset.
   - **MFA fatigue training** — пользователи должны игнорировать unexpected MFA prompts.
   - **EDR на VMware ESXi** (если есть гипервизоры — основной target).
6. **Cross-refs:** lesson-022 (AD attacks), lesson-029 (privacy — SIM-swap как attack vector).

---

## Содержание

1. [Источники](#1-источники)
2. [Историческая справка](#2-историческая-справка)
3. [Decentralized model (Group-IB update)](#3-decentralized-model-group-ib-update)
4. [TTPs (детально)](#4-ttps-детально)
5. [Initial access: Oktapus-style phishing](#5-initial-access-oktapus-style-phishing)
6. [SIM-swapping и helpdesk vishing](#6-sim-swapping-и-helpdesk-vishing)
7. [Privilege escalation в Okta / M365](#7-privilege-escalation-в-okta--m365)
8. [VMware ESXi ransomware deployment](#8-vmware-esxi-ransomware-deployment)
9. [Судебные дела (2024–2026)](#9-судебные-дела-20242026)
10. [Атрибуция и overlap с другими группами](#10-атрибуция-и-overlap-с-другими-группами)
11. [IOC list и detection rules](#11-ioc-list-и-detection-rules)
12. [Рекомендации по mitigation](#12-рекомендации-по-mitigation)
13. [Источники](#13-источники)

---

## 1. Источники

- **Group-IB blog post (TG @group_ib 01.07.2026)** — основная атрибуция decentralized collective.
- **The Hacker News + BleepingComputer (17-18.07.2026)** — приговор Owen Flowers и Thalha Jubair в Woolwich Crown Court.
- **US DOJ press releases (2024–2025)** — обвинения и sentencing US-based участников.
- **UK CPS (Crown Prosecution Service) + NCA (National Crime Agency)** — UK cases.
- **MITRE ATT&CK Group G1015 (Scattered Spider)** — `<https://attack.mitre.org/groups/G1015/>`.

---

## 2. Историческая справка

### 2.1 Хронология

| Дата | Событие | Источник |
|------|---------|----------|
| **2021–2022** | Формирование как **Lapsus$ subcluster** (overlap в TTPs) | THN, BleepingComputer |
| **2022 (Q3)** | First major campaign — **Oktapus** (Twilio, Cloudflare, Cisco) | Group-IB, Twilio security blog |
| **2023 (Q1)** | **MGM Resorts** ransomware ($100M damage) | MGM disclosure, BleepingComputer |
| **2023 (Q2)** | **Caesars Entertainment** ransomware ($15M ransom paid) | Caesars SEC filing |
| **2024 (Q3)** | **Transport for London (TfL)** hack (£29M damage) | TfL incident disclosure, NCA |
| **2024 (Q4)** | **US court filings** — Peter Stokes «Bouquet» (ювелирный магазин) | US DOJ |
| **2026 (Jan)** | Multiple US hospital attacks (reports in H1 2026) | THN |
| **2026 (01.07)** | Group-IB blog post — **decentralized collective** model | Group-IB TG |
| **2026 (17.07)** | UK sentencing Owen Flowers + Thalha Jubair — **5.5 лет** | THN, BleepingComputer |
| **2026 (08.07)** | US court filing — Windows Device ID attribution | KrebsOnSecurity |

### 2.2 Эволюция имён

- **Lapsus$ (2021–2022)** — UK / Brazil группировка, известна «press release» style через Telegram.
- **Scattered Spider (2022–2024)** — переименование Lapsus$ subcluster + новые recruits из англоязычного underground.
- **Octo Tempest (2023)** — Microsoft naming convention для Scattered Spider.
- **Scattered Spider (2024–2026)** — основное public name после MGM/Caesars/TfL.
- **«0ktapus» (2022)** — отдельная кампания, но с overlap TTPs (Group-IB связывает с теми же людьми).

---

## 3. Decentralized model (Group-IB update)

### 3.1 Что изменилось в атрибуции Group-IB

До 2026 года Scattered Spider описывался как **loosely-affiliated collective** — несколько команд с частичным overlap в personnel.

Group-IB 01.07.2026 формализует это как **decentralized collective**:

```
                    ┌──────────────────────────────────────┐
                    │      "Scattered Spider" (umbrella)    │
                    │      (не единая группа, а экосистема) │
                    └─────────────┬────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
   ┌─────────┐              ┌─────────┐              ┌─────────┐
   │Cluster A│              │Cluster B│              │Cluster C│
   │(UK)     │              │(US West)│              │(US East)│
   │vishing  │              │SIM-swap │              │ransomware│
   │focus    │              │focus    │              │operator │
   └────┬────┘              └────┬────┘              └────┬────┘
        │                         │                         │
        │   Общие TTPs:           │                         │
        │   - Oktapus phishing    │                         │
        │   - SIM-swapping        │                         │
        │   - Helpdesk vishing    │                         │
        │   - Okta/M365 abuse     │                         │
        │   - VMware ESXi ransom  │                         │
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │  Affiliates / IABs:      │
                    │  - ALPHV / BlackCat      │
                    │  - ShinyHunters          │
                    │  - Lapsus$ (legacy)      │
                    │  - Other RaaS operators  │
                    └──────────────────────────┘
```

### 3.2 Ключевые атрибуты decentralized model

- **Нет единого command structure** — каждый cluster автономен, leader of cluster принимает решения о targets.
- **Общий TTP-sharing** — clusters обмениваются успешными TTPs через private Telegram / Discord / Matrix каналы.
- **Commodity tooling** — все используют одни и те же инструменты (Mimikatz, rclone, AnyDesk, ngrok).
- **Affiliates / IABs** — clusters работают как Initial Access Brokers для RaaS операторов (ALPHV/BlackCat).
- **Geographic distribution** — UK, US West Coast, US East Coast (Group-IB подтверждает как минимум 3 main clusters).

### 3.3 Что это меняет для defenders

- **Имена имён — шум.** «Scattered Spider» как threat-actor name — это **umbrella term**, не конкретная группа.
- **Атрибуция конкретного человека → конкретного cluster** возможна через OSINT (Telegram channels, social media, code reuse).
- **Threat hunting по общим TTPs** — эффективнее, чем по конкретным IOC.
- **Судебные дела бьют по людям**, но collective продолжает работать через другие subclusters.

---

## 4. TTPs (детально)

### 4.1 MITRE ATT&CK mapping

| Tactic | Technique | Описание |
|--------|-----------|----------|
| **TA0043 — Reconnaissance** | T1589.001 (Credentials) | Покупка credentials на underground markets |
| | T1591.002 (Org Info) | Recon IT helpdesk staff names, MFA enrollment process |
| | T1593.001 (Domains) | Регистрация look-alike domains (`okta-helpdesk.com`, `vpn-portal-uk.com`) |
| **TA0001 — Initial Access** | T1566.001 (Spear-phishing Attachment) | LNK / ISO файлы в emails |
| | T1566.002 (Spear-phishing Link) | Oktapus-style fake Okta / VPN login pages |
| | T1078.004 (Cloud Accounts) | Использование ранее купленных credentials |
| | T1656 (Impersonation) | Helpdesk vishing — impersonation IT staff |
| **TA0003 — Persistence** | T1556.006 (MFA — Modify Cloud MFA) | Helpdesk reset MFA enrollment |
| | T1098.005 (Device Registration) | Регистрация attacker-controlled device для MFA bypass |
| **TA0004 — Privilege Escalation** | T1078.004 (Cloud Accounts) | Compromise privileged Okta admin accounts |
| **TA0008 — Lateral Movement** | T1021.007 (Remote Services — RDP/SSH) | RDP через VPN после initial access |
| | T1021.001 (Remote Services — RDP) | RDP на VMware ESXi через privileged accounts |
| **TA0010 — Exfiltration** | T1567.002 (Cloud Storage) | rclone → Mega.nz, Dropbox, Google Drive |
| **TA0040 — Impact** | T1486 (Data Encrypted for Impact) | Ransomware deployment на ESXi |

---

## 5. Initial access: Oktapus-style phishing

### 5.1 Механика

**Шаг 1:** Recon — cluster идентифицирует организацию-target (часто крупная компания с IT helpdesk, использующая Okta / Microsoft 365 / Cisco VPN).

**Шаг 2:** Регистрация look-alike домена:
- `okta-helpdesk.com` (вместо `okta.com`)
- `cisco-vpn-portal.com` (вместо `cisco.com`)
- `company-helpdesk.support` (с поддержкой `company.com` email)

**Шаг 3:** Создание fake login page (фишинг) — визуально идентичная legitimate странице.

**Шаг 4:** SMS-рассылка / Telegram-рассылка с ссылкой на fake login (mass phishing, не targeted — «shotgun approach»).

**Шаг 5:** Пользователь вводит credentials → cluster логирует → проверяет credentials в automated tool.

**Шаг 6:** Если credentials имеют privileged role → переходим к SIM-swap / helpdesk vishing.

### 5.2 IOC (исторические, 2022–2024)

| Indicator | Type | Описание |
|-----------|------|----------|
| Domains | `okta-helpdesk.com`, `okta-mfa-reset.com`, `helpdesk-vpn.com` | Look-alike domains (синтетика на основе отчётов) |
| Subdomains | `login.<company>-okta.com`, `mfa.<company>-helpdesk.com` | Subdomains на compromised хостингах |
| URLs | `https://login.<company>-okta.com/?session=<token>` | Phishing URLs с session tokens |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0` | Automated phishing toolkit UA |

> **Production:** используйте актуальные IOC feeds (Group-IB TI, PhishTank, URLhaus).

---

## 6. SIM-swapping и helpdesk vishing

### 6.1 SIM-swapping — детально

**Цель:** получить контроль над телефонным номером privileged user (CEO, CFO, IT admin) → перехватить SMS-based 2FA.

**Шаги:**

1. **Recon:** найти privileged user через LinkedIn, corporate directory, social media.
2. **OSINT на user:** собрать date of birth, address, SSN last 4 digits (через breaches, social engineering).
3. **Подкуп сотрудника оператора:** связаться с corrupt insider в T-Mobile / AT&T / Vodafone через underground markets.
4. **Перенос номера:** insider переносит номер на attacker-controlled SIM.
5. **Перехват SMS-based 2FA:** attacker получает все SMS → login в privileged accounts.

**Anti-detection:** cluster не использует SIM-swap для всех пользователей — только для privileged accounts, чтобы не триггерить оператора.

### 6.2 Helpdesk vishing

**Цель:** убедить IT helpdesk сбросить MFA / пароль для privileged user.

**Шаги:**

1. **OSINT на helpdesk staff:** LinkedIn, Facebook, корпоративные посты — найти имена IT staff.
2. **Caller ID spoofing:** подделать caller ID на legitimate IT staff name / number.
3. **Impersonation:** позвонить helpdesk, представиться IT staff или privileged user.
4. **Сценарий:** «Я в отпуске, забыл пароль / MFA device дома, нужно сбросить» — helpdesk делает reset.
5. **MFA enrollment:** cluster регистрирует attacker-controlled device (TOTP authenticator, hardware key) на privileged account.
6. **Lateral movement:** login в privileged account через VPN / Okta → compromise внутренних систем.

### 6.3 Mitigations

| Mitigation | Реализация |
|------------|------------|
| **Запретить SMS-based 2FA** | Обязательный переход на TOTP (Authy, Google Authenticator) или hardware keys (YubiKey) |
| **Helpdesk verification policy** | Out-of-band verification: видеозвонок с corporate ID, in-person visit, security questions |
| **Privileged account tier** | Отдельная категория для CEO/CFO/IT admin — повышенные проверки |
| **MFA fatigue training** | Пользователи должны репортить unexpected MFA prompts |
| **Caller ID не доверять** | Helpdesk должен использовать callback на verified number |
| **SIM-swap insurance** | Mobile carriers: account PIN, biometric verification для любых changes |

---

## 7. Privilege escalation в Okta / M365

### 7.1 Okta compromise

После initial access в обычный user account:

1. **Discovery:** `GET /api/v1/users?filter=type+eq+%22service%22` — найти service accounts.
2. **Service account discovery:** `GET /api/v1/apps?limit=200` — найти privileged apps.
3. **Admin escalation:** если user → admin role через support case manipulation.
4. **Token theft:** `GET /api/v1/sessions/me` → получить session token.
5. **Lateral movement:** использовать Okta SSO для доступа к Salesforce, Workday, AWS Console, GitHub Enterprise.

### 7.2 M365 compromise

1. **Global Admin enumeration:** `GET /v1.0/users?$filter=assignedPlans/any(p:p/servicePlanId+eq+%27417b1ea0-ae3d-4d39-b8d4-8b8e1053a96b%27)` (Exchange Online plan).
2. **Application Impersonation:** `Add-MailboxPermission` для Exchange.
3. **EWS access:** чтение / отправка email от имени user.
4. **OAuth app registration:** register malicious app (см. lesson по HollowGraph — аналогичный паттерн).
5. **Data exfiltration:** `Search-Mailbox -SearchQuery "*"` → export to PST.

### 7.3 Detection rules

**Sigma (Okta):**

```yaml
title: Scattered Spider — Okta Admin Role Assignment
id: 2f5a6b7c-8d9e-0f1a-2b3c-4d5e6f7a8b9c
status: experimental
description: |
  Detects suspicious Okta admin role assignments, which is a key indicator
  of Scattered Spider post-initial-access privilege escalation.
author: Radar 📡 / CyberShield Division
date: 2026/07/21
logsource:
  product: okta
  service: system_log
detection:
  selection:
    eventType: 'group.user_add'
    groupId|contains: 'admin'  # фильтр для privileged groups
  selection_admin_roles:
    eventType: 'user.account.privilege.grant'
    privilege:
      - 'Super Administrator'
      - 'Application Administrator'
      - 'Group Administrator'
  timeframe: 1h
  condition: selection or selection_admin_roles
  aggregation: count() > 3 by actor.id, target.id
fields:
  - actor.id
  - target.id
  - groupId
  - privilege
falsepositives:
  - Legitimate IT admin onboarding
  - Service account initial setup
level: high
tags:
  - attack.privilege_escalation
  - attack.t1078.004  # Cloud Accounts
```

**Sigma (M365):**

```yaml
title: Scattered Spider — M365 Global Admin Enumeration
id: 3a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d
status: experimental
description: |
  Detects M365 admin role enumeration and assignment via Graph API,
  characteristic of Scattered Spider post-compromise activity.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: azure
  service: audit_logs
detection:
  selection_role_assign:
    Operation: 'Add member to role completed (PIM activation)'
    RoleDisplayName|contains:
      - 'Global Administrator'
      - 'Privileged Role Administrator'
      - 'Exchange Administrator'
  selection_graph_api_burst:
    Operation: 'Microsoft Graph API call'
    Resource: 'directoryRoles'
    | count() > 10 by UserId, AppDisplayName
  condition: selection_role_assign or selection_graph_api_burst
fields:
  - UserId
  - AppDisplayName
  - RoleDisplayName
falsepositives:
  - Legitimate IT admin operations (verify via ticket system)
  - PowerShell automation scripts (verify via script owner)
level: high
tags:
  - attack.privilege_escalation
```

---

## 8. VMware ESXi ransomware deployment

### 8.1 Механика

После compromise privileged Okta / M365 → доступ к **VMware vCenter / ESXi**:

1. **Discovery:** `GET https://<vcenter>/api/vcenter/host` — list ESXi hosts.
2. **Credential access:** через vCenter SSO или direct ESXi SSH.
3. **Lateral movement:** RDP / SSH на ESXi hosts с privileged credentials.
4. **Snapshot deletion:** `vim-cmd vmsvc/snapshot.removeall <vmid>` — удалить backups.
5. **Ransomware deployment:** через RaaS affiliate (ALPHV/BlackCat, новый вариант).
6. **Encryption:** массовое шифрование VMs на всех ESXi hosts.

### 8.2 Detection rules

**Sigma (vCenter):**

```yaml
title: Scattered Spider — vCenter Snapshot Mass Deletion
id: 4b7c8d9e-0f1a-2b3c-4d5e-6f7a8b9c0d1e
status: experimental
description: |
  Detects mass deletion of VM snapshots in vCenter, characteristic of
  Scattered Spider ransomware deployment on VMware ESXi.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: vmware
  service: vcenter
detection:
  selection:
    EventType: 'com.vmware.vim.VmwareVcenterHA'
    Operation: 'snapshot.remove'
  timeframe: 5m
  condition: selection
  aggregation: count() > 20 by UserName, HostName
fields:
  - UserName
  - HostName
  - VMName
falsepositives:
  - Legitimate VM maintenance operations
  - Backup software (Veeam, Nakivo) snapshot lifecycle
level: critical
tags:
  - attack.impact
  - attack.t1486  # Data Encrypted for Impact
```

### 8.3 Mitigation

1. **Separate vCenter admin accounts** — НЕ использовать M365 / Okta accounts для vCenter admin.
2. **ESXi MFA** — enable MFA для vCenter (если поддерживается).
3. **Snapshot immutability** — Veeam Hardened Repository или immutable backup (AWS S3 Object Lock, Azure Blob WORM).
4. **Network segmentation** — vCenter / ESXi в изолированной VLAN без Internet access.
5. **EDR на ESXi** — VMware vDefender или Carbon Black Cloud for VMware.

---

## 9. Судебные дела (2024–2026)

### 9.1 UK — Owen Flowers + Thalha Jubair

**Детали:**
- **Charges:** Section 3ZA UK Computer Misuse Act 1990 (с поправками 2024, первое использование в судебной практике).
- **Victim:** Transport for London (TfL) — сентябрь 2024, £29M damage.
- **Investigation:** NCA + Metropolitan Police (cyber crime unit).
- **Sentencing:** 17.07.2026, Woolwich Crown Court — **5.5 лет лишения свободы** (каждому).
- **Значимость:** **первые осуждённые по Section 3ZA** в UK.

**Section 3ZA Computer Misuse Act** — добавлен в 2024, ужесточает наказание за:
- Unauthorised access к критической инфраструктуре (transport, health, government).
- До **10 лет лишения свободы** + unlimited fine.

### 9.2 US — Peter Stokes «Bouquet»

**Детали:**
- **Charge:** Conspiracy to commit computer fraud (18 USC § 1030).
- **Victim:** ювелирный магазин (название redacted в публичных filings).
- **Investigation:** FBI + US Secret Service.
- **Sentencing:** предыдущий, но court filing 08.07.2026 раскрыл детали attribution.
- **Ключевая улика:** **Windows Device ID** помог FBI связать attack hardware с Peter Stokes.

**Windows Device ID (MDM device ID)** — уникальный identifier, привязанный к:
- Hardware hash (CPU, motherboard, disk serial numbers).
- OS install ID.
- Microsoft Account (если привязан).

**OSINT-урок:** Microsoft Device ID = persistent hardware fingerprint. **Privacy implication:** даже после wipe / reinstall — device ID остаётся привязан к hardware. Используется правоохранителями для attribution.

### 9.3 US — другие cases

- **2024 (Q4):** Tyler Buchanan (Florida) — extradition из Spain, обвинение в Oktapus phishing → plead guilty.
- **2025 (Q1):** Noah Urban (Florida, «King Bob» / «Sausage») — plead guilty, sentenced 2026.
- **2025 (Q2):** Conor Brian Fitzpatrick (Florida, «Pompompurin») — admin of BreachForums, sentenced.

### 9.4 Pattern

Все судебные дела показывают:
1. **Cluster-A (UK)** — операторы, малое количество участников, но central role.
2. **Cluster-B (US East Coast)** — operators + affiliates.
3. **Cluster-C (US West Coast)** — операторы SIM-swap + helpdesk vishing.

---

## 10. Атрибуция и overlap с другими группами

### 10.1 Overlap с Lapsus$ (2021–2022)

| Фича | Lapsus$ | Scattered Spider |
|------|---------|------------------|
| Press release через Telegram | ✅ | ✅ (менее публично) |
| Initial access через SIM-swap | ✅ | ✅ |
| Okta / M365 compromise | ✅ | ✅ |
| Data leak extortion | ✅ | ✅ (через ShinyHunters) |
| Ransomware deployment | ❌ (только extort) | ✅ (через ALPHV) |
| Geographic origin | UK / Brazil | UK / US |
| Age of core members | 14-17 лет (2022) | 18-22 лет (2024) |

### 10.2 Overlap с ShinyHunters

**ShinyHunters (2020–)** — French-speaking data breach extortion group.
- Scattered Spider продаёт / сотрудничает с ShinyHunters для **data leak extortion** (когда ransomware не нужен).
- **2025 (Q3):** ShinyHunters BreachForums seizure → связь с Scattered Spider через общий Telegram channel.

### 10.3 Overlap с ALPHV / BlackCat

**ALPHV / BlackCat (2021–2024)** — Russian-speaking RaaS оператор.
- Scattered Spider работает как **affiliate** для ALPHV.
- **2024 (Q4):** ALPHV exit scam (не выплатил affiliates) → часть Scattered Spider перешла на другие RaaS.

### 10.4 OSINT-граф связей

```
                ┌──────────────────┐
                │  Scattered Spider│ ← collective (umbrella)
                └────────┬─────────┘
                         │
        ┌────────────────┼─────────────────┐
        │                │                 │
        ▼                ▼                 ▼
   ┌─────────┐      ┌─────────┐       ┌─────────┐
   │Lapsus$  │      │Octo     │       │0ktapus  │
   │(legacy) │      │Tempest  │       │(2022)   │
   └────┬────┘      │(MSFT)   │       └────┬────┘
        │           └────┬────┘            │
        └────────────────┼─────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  TTPs in common:     │
              │  - Oktapus phishing  │
              │  - SIM-swap          │
              │  - Helpdesk vishing  │
              │  - Okta/M365 abuse   │
              │  - ESXi ransomware   │
              └──────────────────────┘

   Affiliated / IABs:
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │ALPHV /  │    │Shiny-   │    │Other    │
   │BlackCat │    │Hunters  │    │RaaS     │
   └─────────┘    └─────────┘    └─────────┘
```

---

## 11. IOC list и detection rules

### 11.1 File hashes (синтетика)

> **Production:** обновляйте через TI feeds (Group-IB, Mandiant, Recorded Future). Ниже — синтетика на основе публичных отчётов.

```
# Mimikatz variants (используются Scattered Spider для credential dumping)
SHA256: 5f4dcc3b5aa765d61d8327deb882cf99  (placeholder)

# rclone (для exfiltration)
SHA256: abcd1234567890ef  (placeholder)

# Cobalt Strike beacon (если используется)
SHA256: ef1234567890ab  (placeholder)
```

### 11.2 Network indicators (синтетика)

| Type | Indicator | Описание |
|------|-----------|----------|
| Domain | `okta-helpdesk.com`, `mfa-okta.com`, `vpn-portal-cisco.com` | Look-alike domains (исторические, 2022–2024) |
| URL pattern | `https://login.<company>-okta.com/?session=<token>` | Phishing URL pattern |
| Telegram channels | `t.me/<various>` | Private cluster communication channels (закрытые) |

### 11.3 Sigma rules

См. §7.3 (Okta), §7.3 (M365), §8.2 (vCenter).

---

## 12. Рекомендации по mitigation

### 12.1 Немедленные действия (сегодня)

1. **Audit privileged accounts:**
   - M365: найти все Global Admin / Privileged Role Admin accounts → убедиться в MFA strength.
   - Okta: admin accounts → MFA required (TOTP / hardware key).
   - vCenter: admin accounts → MFA required.

2. **Запретить SMS-based 2FA** для privileged accounts.

3. **Helpdesk verification policy:**
   - Out-of-band verification обязательна (видеозвонок с corporate ID).
   - Не принимать caller ID as proof.

4. **MFA fatigue training:**
   - Пользователи должны репортить unexpected MFA prompts в IT security.
   - IT security должен расследовать каждый report.

### 12.2 Среднесрочные действия (эта неделя)

1. **Network segmentation:**
   - vCenter / ESXi в изолированной VLAN без Internet access.
   - Admin jump server для privileged operations.

2. **EDR на ESXi:**
   - VMware vDefender или Carbon Black Cloud.

3. **Snapshot immutability:**
   - Veeam Hardened Repository или AWS S3 Object Lock / Azure Blob WORM.

4. **Conditional Access policies:**
   - Require compliant device для privileged operations.
   - Block legacy authentication.

### 12.3 Долгосрочные действия (этот месяц)

1. **Privileged Access Management (PAM):**
   - CyberArk / BeyondTrust / Thycotic — централизованное управление privileged accounts.
   - Just-in-time privileged access.

2. **Tiered admin model:**
   - Tier 0: Domain Controllers, Entra ID, Okta admin
   - Tier 1: Servers, infrastructure
   - Tier 2: Workstations, user support
   - Изоляция между tiers.

3. **IR playbook для Scattered Spider-style:**
   - Detection (Okta admin role assignment, ESXi snapshot deletion, MFA fatigue).
   - Containment (revoke Okta session, disable M365 admin, isolate ESXi).
   - Eradication (image affected hosts, reset credentials, rotate tokens).
   - Recovery (validate audit logs, restore from immutable backup).
   - Lessons Learned (post-mortem, update detection rules).

---

## 13. Источники

### Публичные отчёты

| # | Source | URL |
|---|--------|-----|
| 1 | **Group-IB blog (TG @group_ib 01.07.2026)** | TG post |
| 2 | **The Hacker News — "Scattered Spider Hackers Get 5+ Years in Jail" (17.07.2026)** | `<https://thehackernews.com/2026/07/scattered-spider-hackers-jail.html>` |
| 3 | **BleepingComputer — UK sentencing 17.07.2026** | `<https://www.bleepingcomputer.com/news/security/scattered-spider-members-jailed-for-tfl-attack/>` |
| 4 | **KrebsOnSecurity — Windows Device ID attribution** | `<https://krebsonsecurity.com/2026/07/scattered-spider-device-id.html>` |
| 5 | **MITRE ATT&CK Group G1015** | `<https://attack.mitre.org/groups/G1015/>` |
| 6 | **UK CPS press release — Section 3ZA** | `<https://www.cps.gov.uk/>` |
| 7 | **US DOJ press releases** | `<https://www.justice.gov/>` |

### Кросс-ссылки в нашем репозитории

- `lesson-022-ad-attacks-from-hacker-pov.md` — AD attack playbook.
- `lesson-029-osint-privacy-2026.md` — SIM-swap как privacy attack vector.
- `intel/osint/hollowgraph-m365.md` — M365 Graph API abuse pattern (overlap).

### Контакты

- **Кузя 🦝** — для эскалации.
- **Тень 🦅** — forensic + lateral movement containment.
- **Маяк 🛰** — network detection, DNS firewall.
- **Хранитель 📚** — TI feeds, document new variants.
- **code-sentinel 🛡** — review of admin tools (Okta, vCenter API).

---

*Все IOC в этом документе — синтетика на основе публичных отчётов Group-IB / THN / DOJ. Для production detection — обновить через актуальные TI feeds.*

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
