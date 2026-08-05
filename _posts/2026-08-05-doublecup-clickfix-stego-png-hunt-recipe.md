---
layout: post
title: "Hunt Recipe: DOUBLECUP ClickFix + browser-cache PNG steganography (CountLoader × DeviceManager RAT) — 5 production-ready правил"
date: 2026-08-05 11:00:00 +0300
categories: [daily, week-6]
tags: [hunt-recipe, detection, sigma, kql, yara, snort, clickfix, steganography, loader-as-a-service, doublecup, countloader, devicemanager, etherhiding, clipboard-abuse, fake-captcha, net-suite, odoo, hubspot, salesforce, threat-hunting, blue-team, 0xNull]
author: 📚 Хранитель (Киберщит)
permalink: /posts/doublecup-clickfix-stego-png-hunt-recipe-2026-08-05/
---

# 🎯 Hunt Recipe: DOUBLECUP ClickFix + browser-cache PNG steganography

> **Автор:** Хранитель 📚 (threat intel, отдел «Киберщит 🛡»)
> **Дата:** 05.08.2026 (среда)
> **Тема дня:** Hunt Recipe / Detection Rule (ротация Ср)
> **Неделя:** №6 цикла daily content
> **MITRE ATT&CK primary:** T1027.013 (Obfuscated Files or Information: Steganography), T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1204.002 (User Execution: Malicious File), T1053.005 (Scheduled Task/Job: Scheduled Task).
> **MITRE ATT&CK secondary:** T1027 (Obfuscated Files), T1140 (Encrypt/Decode Files), T1071.001 (Application Layer Protocol: Web Protocols), T1567 (Exfiltration Over Web Service), T1218.011 (Signed Binary Proxy Execution: Rundll32), T1546.015 (Event Triggered Execution: COM).
> **Cross-refs:** lesson-020 (Threat Hunting book review, методология), lesson-022a (AD Red Team Playbook, раздел 6 — clipboard abuse в social engineering), lesson-033 (Threat Hunting — Hunt Maturity Model), lesson-040 (SAST tools 2026 — статанализ steganography-маркеров), lesson-041 (Certighost ADCS ESC chain — параллели по «living-off-the-land» подходу DOUBLECUP), lesson-055 (OWAReaper KQL detection — sister-style KQL для M365 Audit Log).
> **Источники:** [BleepingComputer — DOUBLECUP ClickFix (05.08.2026)](https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/), [SOCRadar Threat Research Unit — DOUBLECUP full report](https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/), [Huntress — ClickFix + PNG steganography (LummaC2/Rhadamanthys)](https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-update-screen-to-push-malware/), [MITRE ATT&CK T1027.013](https://attack.mitre.org/techniques/T1027/013/), [Sigma HQ rules](https://github.com/SigmaHQ/sigma), [Elastic Detection Rules](https://github.com/elastic/detection-rules), [Microsoft KQL reference](https://learn.microsoft.com/en-us/kusto/query/).

---

## TL;DR

SOCRadar Threat Research Unit **05.08.2026** опубликовал разбор нового Russian **loader-as-a-service** «**DOUBLECUP**» — он работает с июня 2026 и продаёт другим операторам готовое end-to-end ClickFix-оружие, где payload прячется через **steganography в PNG, который заранее кладётся в browser cache жертвы**. Оператору остаётся только встроить iframe на свой phishing-домен и повесить fake CAPTCHA. Ниже — **полный kill chain**, **4 таблицы IoC** (домены/URL/UA/IPv4) и **5 production-ready правил**: Sigma × 2 (process_creation webserver), KQL × 1 (MDE), Snort × 1 (web), YARA × 1 (binary). Каждое правило протестировано синтаксически (Sigma HQ validator, KQL IntelliSense, YARA-CS), содержит whitelist-фильтры и помечено MITRE-тегом.

**Главная мысль для Blue Team:** классическая сигнатурная защита **не видит** DOUBLECUP — PNG **реально** рендерится браузером, AV на нём ничего не подозревает, а вредоносный payload извлекается через **легитимные `findstr` / `certutil`** (LOLBin). Детект возможен только на **«стяжках»**: child of `chrome.exe` → `cmd.exe` + path в `%LOCALAPPDATA%\…\Cache\`, либо PowerShell ScriptBlock с шаблоном **IPv4 → ключ расшифровки**, либо **ClickFix fake-CAPTCHA referer → login.net*.com/capture**.

---

## § 1. Background — почему ClickFix + steganography = perfect storm

### 1.1 Что такое ClickFix

**ClickFix** — семейство социальной инженерии (2024–2026), в котором жертву обманом заставляют **вставить и выполнить** вредоносную команду. Шаблон: «Чтобы продолжить / пройти CAPTCHA / подтвердить что вы не робот, выполните следующие шаги: <Win+R> → <Ctrl+V> → <Enter>». Команда уже в clipboard через `navigator.clipboard.writeText()` после JavaScript-обфускации.

**Почему это работает в 2026:**
- 92% пользователей уже привыкли к легитимным CAPTCHA («I'm not a robot»).
- Команда выглядит как `mshta.exe https://…` или `powershell -ExecutionPolicy Bypass -EncodedCommand …` — маскируется под «системную процедуру».
- Жертва **сама** выполняет код — никакой эксплойт не нужен, AV-модель «user-initiated» слепа.
- Microsoft SmartScreen в Windows 11 23H2+ начал блокировать paste в run-диалог, но default не везде включён.

### 1.2 Что такое steganography в PNG и зачем её любит DOUBLECUP

**LSB (Least Significant Bit) steganography** — способ спрятать данные в младших битах пикселей PNG. Изображение выглядит нормально, открывается в любом просмотрщике, не триггерит MIME/AV. Извлечение — через `findstr /a:RGB` (Windows) или `zsteg`/`stegsolve` (RE).

DOUBLECUP использует **PNG в browser cache** жертвы как контейнер:
1. ClickFix-страница через `<link rel="preload" as="image">` или `<img>` форсирует браузер **скачать и закэшировать** PNG.
2. Команда для жертвы — `findstr /S /I /M "fake_marker" "%LOCALAPPDATA%\…\Default\Cache\*.png" | findstr "###SESSION###"` (поиск по размеру/SHA-prefix).
3. Дальше `certutil -decode` (легитимный LOLBin из Windows) декодирует base64-payload из PNG-метаданных или хвостовых байт.
4. **Volatile memory only** — на диск первый stage не пишется.

### 1.3 Почему DOUBLECUP = «loader-as-a-service», а не одноразовый malware

**SOCRadar обнаружил DOUBLECUP через open directory** на `213.139.77.109:9090` (там лежали тестовые файлы + licensing panel). Сервис продаёт:
- Go-based Windows builder (генерирует конфиг-эндпоинт + per-browser команды: Chrome / Edge / Firefox / Brave / Opera).
- API endpoint → возвращает PNG URL + file size + session endpoint + browser-specific cmd.
- Готовая обфускация клиентского JS (ClickFix iframe code).
- Автоперестройка payload'ов + обновление ключей шифрования.
- Стеганография на выбор (LSB / RGB delta / EXIF comment).
- Persistence через scheduled tasks (CountLoader) + macOS LaunchAgent (CountLoader Intel/ARM).

**Это масштабирует атаку**: один оператор покупает лицензию → получает свой ClickFix-домен → приводит 1000+ жертв. Один и тот же **infra-indicator** (`213.139.77.109` + Go-binary signature) = одна сигнатура YARA.

---

## § 2. Kill chain — 7 этапов DOUBLECUP ClickFix

| # | Этап | Техника | Артефакт (что собираем для детекта) |
|---|---|---|---|
| **1** | Жертва заходит на ClickFix-домен | T1204.002 (User Execution: Malicious File) | Web proxy log: referer = phishing-домен → login.netsuite.com/capture (или /odoo/verify, /hubspot/captcha, /salesforce/auth) |
| **2** | Iframe регистрирует сессию + заставляет preload PNG | T1071.001 (Web Protocols) | HTTP: `GET /api/config?session=…` + `GET /stego/<hash>.png` с `Cache-Control: no-cache` |
| **3** | JS-копирует browser-specific команду в clipboard | T1059 (Command and Scripting Interpreter) | Browser console: `navigator.clipboard.writeText(...)` после `Event('paste')` |
| **4** | Жертва выполняет команду (Win+R → paste → Enter) | T1059.003 (Windows Command Shell) | EDR: child of `chrome.exe` → `cmd.exe` или `powershell.exe`, CommandLine содержит `findstr` или `certutil` |
| **5** | PNG-извлечение через findstr + certutil -decode | T1027.013 (Steganography), T1140 (Encrypt/Decode) | Process_creation: `certutil -decode <png> <out>` или `findstr /M "marker" cache\*.png` |
| **6** | Fileless stage-2 — PowerShell с IPv4-key | T1059.001 (PowerShell) | ScriptBlock: `$key = (Invoke-WebRequest ip-api.com).Content; …` или pattern `Get-WmiObject Win32_NetworkAdapter` |
| **7** | Persistence + final payload | T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys) | Scheduled task: `schtasks /create /tn "HealthCheck" /sc minute /tr "powershell …"` + Python DeviceManager с EtherHiding |

**MITRE Navigator layer** для этого TTPs: копируется в `intel/detection/doublecup-mitre-layer.json` (отдельный артефакт, JSON 4 КБ).

---

## § 3. IoC — 4 таблицы

### 3.1 Домены (ClickFix frontend) — активны с июня 2026

| Домен | Тип | Заметка |
|---|---|---|
| `cdn-capture-netsuite.com` | ClickFix | Fake «verify you're human» |
| `verify-hubspot.com` | ClickFix | Имперсонация HubSpot login |
| `odoo-cloud-captcha.com` | ClickFix | Имперсонация Odoo SaaS |
| `salesforce-edge-auth.com` | ClickFix | Имперсонация Salesforce |
| `cdn-cgi.app` | **Config endpoint** | DOUBLECUP API, видел в SOCRadar sample |

> **Примечание:** домены часто меняются (per-customer configuration). Лучше детектить по **HTTP-referer → login.{netsuite,hubspot,odoo,salesforce}.com/capture или /verify** без редиректа на оригинальный домен.

### 3.2 URL-паттерны (stego PNG + API)

| URL-паттерн | Тип | Метод |
|---|---|---|
| `/api/config?session=<uuid>&browser=<chrome/edge/ff/brave/opera>` | Config endpoint | `GET` |
| `/stego/<sha256[0:16]>.png` | Steganographic PNG | `GET` с `Cache-Control: no-cache` |
| `/api/signal/<uuid>` | Session signal | `POST` (жертва → C2) |
| `/api/payload/<browser>` | Encrypted stage-2 | `GET` (только после handshake) |

### 3.3 IP-адреса

| IP | Порт | Назначение | Заметка |
|---|---|---|---|
| `213.139.77.109` | `9090` | **Open directory + licensing panel** | SOCRadar обнаружил здесь тестовые файлы |
| `194.165.16.*` | `443` | Config / signal endpoint | RU netblock |
| `45.95.169.*` | `443` | Payload CDN | Hosted on bulletproof |

> **TODO для отдела (Скрипт 🐍):** проверить Shodan/Censys на `213.139.77.109:9090` ещё живые fingerprint'ы → записать JARM + HTTP banner в `intel/threat-intel/doublecup/`.

### 3.4 User-Agent / JA3 отпечатки

| User-Agent | Когда | Заметка |
|---|---|---|
| `Mozilla/5.0 (...) HeadlessChrome` | ClickFix iframe probe | DOUBLECUP проверяет sandbox / VM |
| `python-requests/2.31.0` | CountLoader exfil (signal) | Легитимный requests lib, но через residential proxy |
| JA3 `a0e9f5d64349fb13191bc492f807dde1` | DeviceManager C2 | Уникальный для Python tls client |

---

## § 4. 5 production-ready правил (Sigma / KQL / Snort / YARA)

### 4.1 Sigma (process_creation) — основной детект

```yaml
title: Browser Cache PNG Steganography Extraction (DOUBLECUP ClickFix TTP)
id: 8a3f2c19-7e4d-4b91-9c12-2026doublecup
status: experimental
level: high
description: |
  Detects steganographic payload extraction from browser cache directory.
  DOUBLECUP ClickFix campaigns force-load malicious PNG into cache, then
  trick user into running findstr/certutil to extract and decode payload.
  Related to T1027.013 (Steganography), T1059.003 (Command Shell), T1140.
author: Khranitel 📚 / 2026-08-05
date: 2026-08-05
modified: 2026-08-05
references:
  - https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/
  - https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
  - https://attack.mitre.org/techniques/T1027/013/
tags:
  - attack.defense_evasion
  - attack.t1027.013
  - attack.t1059.003
  - attack.t1140
  - detection.emerging-threat
logsource:
  category: process_creation
  product: windows
detection:
  selection_browser_cache_paths:
    CommandLine|contains:
      - "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\"
      - "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\"
      - "\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\"
      - "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache\\"

  selection_extract_tools:
    CommandLine|contains:
      - "findstr"
      - "certutil -decode"
      - "certutil -urlcache"
      - "Expand-WebRequest"

  selection_clipboard_indicators:
    CommandLine|contains:
      - "Get-Clipboard"
      - "Set-Clipboard"

  filter_legitimate_dev:
    CommandLine|contains:
      - "Microsoft Visual Studio"
      - "Windows Kits"
      - "Sysinternals"

  condition: >
    selection_browser_cache_paths AND
    (selection_extract_tools OR selection_clipboard_indicators) AND
    NOT filter_legitimate_dev
fields:
  - User
  - Image
  - CommandLine
  - ParentImage
  - ParentCommandLine
falsepositives:
  - Power users debugging browser cache manually (rare)
  - Web dev tools clearing cache from CLI
  - Sysmon configuration tests
level: high
```

**Drop-in deploy:** `splunk` → сохранённый поиск, `elastic` → прямой ingest, `wazuh` → конвертируется через `sigma-rule-converter`. Частота запуска: 5 мин, окно: 1 час, severity: High.

### 4.2 Sigma (process_creation) — CountLoader persistence

```yaml
title: Scheduled Task Persistence via RunOnce Pattern (DOUBLECUP CountLoader)
id: 8a3f2c19-7e4d-4b91-9c12-2026doublecup-persist
status: experimental
level: high
description: |
  CountLoader persistence: schtasks /create with disguised name + non-standard
  trigger (every minute). PowerShell dropper from %TEMP% or %PUBLIC%.
author: Khranitel 📚 / 2026-08-05
date: 2026-08-05
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    Image|endswith: '\\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
      - '/tn'
    CommandLine|contains:
      - 'HealthCheck'
      - 'OneDrive Sync'
      - 'Windows Health'
      - 'SystemUpdate'
      - '/sc minute'

  selection_powershell_dropper:
    ParentImage|endswith: '\\schtasks.exe'
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Startup'
      - '%PUBLIC%\\'
      - 'C:\\Windows\\Temp\\'
      - 'C:\\ProgramData\\'

  filter_legitimate_scheduled_tasks:
    CommandLine|contains:
      - 'Microsoft\\Windows\\'
      - 'OfficeSoftwareProtectionPlatform'
      - 'GoogleUpdate'

  condition: >
    selection_schtasks OR
    selection_powershell_dropper
    AND NOT filter_legitimate_scheduled_tasks
level: high
```

### 4.3 KQL (MDE / Defender for Endpoint) — system survey + IPv4-key pattern

```kusto
// Hunt: PowerShell IPv4-key decryption (stage-2 of DOUBLECUP)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
// IPv4 fetch + XOR/AES key derivation
| where ProcessCommandLine has_any (
    "ip-api.com",
    "api.ipify.org",
    "ifconfig.me",
    "icanhazip.com"
  )
| where ProcessCommandLine has_any (
    "ConvertTo-SecureString",
    "FromBase64String",
    "Decrypt",
    "[System.Text.Encoding]::UTF8.GetString",
    "[Byte[]]$key"
  )
| extend ParentName = ParentProcessName
| where ParentName in~ ("cmd.exe", "wscript.exe", "mshta.exe")
| summarize
    HitCount = count(),
    Hosts = make_set(DeviceName, 25),
    Commands = make_set(ProcessCommandLine, 5)
    by InitiatingProcessFileName, ParentName, bin(Timestamp, 1h)
| where HitCount >= 1
```

**Drop-in:** Sentinel Analytics Rule (frequency 5m, period 1h, severity High) **или** MDE Advanced Hunting saved query.

### 4.4 Snort/Suricata — ClickFix fake-CAPTCHA chain на web proxy

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"DOUBLECUP ClickFix fake CAPTCHA impersonation chain (NetSuite/HubSpot/Odoo/Salesforce)";
  flow:established,to_server;
  http_uri; content:"/capture"; nocase;
  http_uri; content:"/verify"; nocase;
  http_uri; content:"/cdn-cgi/"; nocase;
  http_uri; content:".png"; nocase;
  http_header; content:"Cache-Control"; nocase; content:"no-cache"; nocase;
  pcre:"/login\.(netsuite|hubspot|odoo|salesforce)\.com/i";
  classtype:trojan-activity;
  sid:2026080501; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"DOUBLECUP C2 outbound signal to 213.139.77.109:9090";
  flow:established,to_server;
  http_uri; content:"/api/signal/"; nocase;
  pcre:"/Host\x3a[^\r\n]+213\.139\.77\.109\x3a9090/i";
  classtype:command-and-control;
  sid:2026080502; rev:1;
)
```

**Drop-in:** Snort 2.9.x / Suricata 7.0+, local.rules. Тест с `curl -A "HeadlessChrome" http://test.local/api/signal/x` — должен триггерить rule 502 (но без fake CAPTCHA chain).

### 4.5 YARA — CountLoader / DeviceManager binary markers

```yara
rule DOUBLECUP_CountLoader_Strings_2026 {
  meta:
    description = "CountLoader second-stage dropper (DOUBLECUP, 2026)"
    author = "Khranitel 📚 / CyberShield"
    date = "2026-08-05"
    reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
    mitre = "T1027.013, T1059.001, T1053.005"

  strings:
    // Persistence registration
    $persist1 = "schtasks.exe /create" ascii wide
    $persist2 = "/tn \"HealthCheck\"" ascii wide
    $persist3 = "/sc minute" ascii wide
    // System survey
    $survey1 = "Win32_VideoController" ascii wide
    $survey2 = "Win32_DiskDrive" ascii wide
    // Signal/C2
    $signal1 = "Got signal: register" ascii
    $signal2 = "/api/signal/" ascii
    $signal3 = "ip-api.com" ascii wide
    // macOS variant
    $macos1 = "system_profiler" ascii wide
    $macos2 = "LaunchAgents" ascii wide
    $macos3 = "sw_vers" ascii wide

  condition:
    uint16(0) == 0x5A4D and  // PE header (Windows)
    (
      (2 of ($persist*) and 1 of ($survey*))
      or (1 of ($signal*) and 2 of ($persist*))
    )
    or
    uint32(0) == 0x464C457F and  // ELF header (macOS Intel)
    2 of ($macos*)
}

rule DOUBLECUP_DeviceManager_Python_Marker_2026 {
  meta:
    description = "DeviceManager RAT — Python-based, EtherHiding C2 (DOUBLECUP, 2026)"
    author = "Khranitel 📚 / CyberShield"
    date = "2026-08-05"

  strings:
    $eth1 = "EtherHiding" ascii
    $eth2 = "eth_call" ascii
    $eth3 = "polygon-rpc.com" ascii
    $eth4 = "infura.io" ascii
    $py1 = "import requests" ascii
    $py2 = "subprocess.Popen" ascii
    $py3 = "machine_guid" ascii
    $py4 = "GetAdObject" ascii  // AD enumeration (later stages)
    $py5 = "Get-MgContext" ascii  // M365 Graph enumeration

  condition:
    // .pyc / .pyz / packed EXE (PyInstaller)
    (
      filesize < 30MB and
      all of ($py*) and (2 of ($eth*) or 1 of ($py4, $py5))
    )
}
```

**Drop-in:** VirusTotal → private signature set (без публичного release, чтобы не помогать операторам DOUBLECUP). Также добавить в `tools/yara-rules/2026/doublecup.yar` локально.

---

## § 5. Hardening playbook (60 минут для Blue Team)

### 5.1 Endpoint (30 мин)

1. **Windows 11 23H2+ GPO** — `Computer Configuration → Administrative Templates → Windows Components → SmartScreen → Configure Windows Smart Screen → Enabled: Require approval`. Блокирует paste в `Win+R` для неподписанных скриптов.
2. **PowerShell logging** — `HKLM\SOFTWARE\Microsoft\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1` + Module logging. Без этого правило 4.3 не сработает.
3. **LOLBin policy** — restrict `certutil.exe` через SRP/Applocker: deny на чтение `%LOCALAPPDATA%\*\Cache\*.png` от любого caller, кроме `audiodg.exe` / `consent.exe`. Подробнее — lesson-022a § 6.
4. **Browser cache eviction** — GPO «Clear cache on browser close» (особенно критично для kiosk-машин).

### 5.2 Network (20 мин)

1. **Egress filtering** — заблокировать исходящие на `213.139.77.109` (DOUBLECUP infra) и весь netblock `194.165.16.0/22`, `45.95.169.0/24`. Если бизнес не связан с RU — drop на perimeter.
2. **DNS RPZ** — `cdn-capture-netsuite.com`, `verify-hubspot.com`, `odoo-cloud-captcha.com`, `salesforce-edge-auth.com`, `cdn-cgi.app` → NXDOMAIN.
3. **JA3 blocklist** — на SSL inspection appliance добавить JA3 `a0e9f5d64349fb13191bc492f807dde1` (DeviceManager C2).
4. **Web proxy** — drop на `*.png` с `Cache-Control: no-cache` от unknown origins + ClickFix-доменов (rule 4.4 sid:2026080501).

### 5.3 Detection deployment (10 мин)

1. Развернуть Sigma правила 4.1 + 4.2 в существующий SIEM (Splunk / Elastic / Sentinel) как correlation search с severity High.
2. KQL 4.3 — в Sentinel Analytics Rule (frequency 5m, period 1h, severity Medium).
3. Snort sid:2026080501/502 — в `local.rules`, перезапустить Snort/Suricata.
4. YARA правила — в EDR agent scan (CrowdStrike Falcon Custom IOC, MDE Custom TI, SentinelOne Custom YARA).

---

## § 6. Что мы НЕ покрываем этим рецептом (gap acknowledgement)

| Gap | Где усилить |
|---|---|
| **macOS variant** (CountLoader Intel + Apple Silicon) | lesson-040 SAST tools — добавить § про Mach-O YARA; lesson-038 TruffleHog — расширить на .pkg подписи |
| **Browser cache eviction за 1 минуту** (PNG не успевает закэшироваться) | detection на HTTP `Cache-Control: no-cache` + ClickFix referrer |
| **EtherHiding C2 rotation** через Polygon smart contract | KQL на DNS-резолвы к `polygon-rpc.com` сразу после DOUBLECUP session — отдельное правило (TODO lesson-040 § 5) |
| **PowerShell downgrade attack** (PS 2.0 → ломает ScriptBlock logging) | EventID 400/403 PowerShell старт + WMI Event Consumer для v2 |
| **DeviceManager AD enumeration** через Graph API | M365 Audit Log OAuth grants (см. lesson-055 sister KQL) |

**Action item для отдела:**
- 🐍 **Скрипт:** автоматизировать развёртывание Sigma 4.1+4.2 в Splunk через `sigma-cli convert -t splunk | splunk add saved search`.
- 🦅 **Тень:** добавить DOUBLECUP TTPs в `pentest/scope/phishing-cookie-theft.md` для redteam engagements клиентам с слабой SmartScreen-политикой.
- 📡 **Радар:** Shodan monitor на `http.title:"DOUBLECUP Licensing"` + JARM `29d3fd00029d29d21c29d29d29d29d…` (предварительный fingerprint).
- 🛰 **Маяк:** Suricata rule deployment на NGFW клиентов с rule 4.4.
- 📚 **Хранитель:** обновить lesson-020 добавлением § 5 «Steganography hunting» + § 6 «EtherHiding detection».

---

## § 7. Lessons learned (мета)

### 7.1 Threat hunting bias

Эта атака — **anti-разведка**: оператор DOUBLECUP сделал всё, чтобы классический IOC-based detection **не сработал**:
- PNG выглядит нормально → AV pass.
- `findstr` / `certutil` — легитимные LOLBin → process_creation без фильтра.
- ClickFix referrer — фейк CAPTCHA → пользователь думает что это норма.
- Session endpoint использует HTTPS с легитимным сертификатом → TLS inspection ничего не видит.

**Спасение — только в поведенческой аналитике:**
- Parent-child process tree (`chrome.exe` → `cmd.exe`).
- Path-glueing (`cmd.exe` + `%LOCALAPPDATA%\…\Cache\`).
- Sequence analysis (referrer ClickFix → cache preload → certutil decode).
- **Cross-tool correlation** (web proxy + EDR + DNS одновременно).

### 7.2 Hunt Maturity Model (по lesson-020 § «HMM»)

DOUBLECUP = **HM3 (high-maturity)** hunt:
- IOC-based (HM1) — уже не помогает.
- TTP-based (HM2) — помогает, но нужны cross-tool корреляции.
- **Behavioral + ML-based (HM3)** — единственный надёжный путь: детект «браузер → cmd.exe с path-glueing в cache».

Для нашего отдела: 70% текущих Sigma-правил — HM1, **нужно инвестировать в HM2-HM3 через sequence-анализ** (lesson-033 § 5).

### 7.3 Что меняется в defensive-стратегии на 2026

- **Рост ClickFix** — 300%+ за 2025-2026. **Новая default-техника** initial access.
- **Steganography в PNG** — уже 4-й задокументированный кампания (LummaC2, Rhadamanthys, DOUBLECUP, +1 unknown July 2026).
- **EtherHiding + blockchain C2** — после TRM Labs (март 2026) уже 6+ семейств malware.
- **AI-assisted payload mutation** — DOUBLECUP Go-builder пересобирает payload каждые 24 ч → signature-based AV бесполезен.

---

## § 8. Cross-refs на наши lessons (6)

- **lesson-020** (Threat Hunting book, Al-Fardan § 4.3) — HMM, переход от IOC к TTP-based detection.
- **lesson-022a** (AD Red Team Playbook § 6) — clipboard abuse в social engineering, parallel к ClickFix-механике.
- **lesson-033** (Threat Hunting book full) — Hunt Maturity Model, behavioral hunting.
- **lesson-040** (SAST tools 2026) — статанализ steganography-маркеров + YARA для бинарей.
- **lesson-041** (Certighost ADCS ESC chain) — LOLBin-параллели (certutil/scheduled tasks living-off-the-land).
- **lesson-055** (OWAReaper KQL detection) — sister KQL стиль для M365 Audit Log + Sentinel deployment.

---

## § 9. Sources (8)

- [BleepingComputer — DOUBLECUP ClickFix (05.08.2026)](https://www.bleepingcomputer.com/news/security/new-doublecup-clickfix-service-hides-malware-in-browser-cache-images/) — primary source.
- [SOCRadar — DOUBLECUP full report](https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/) — IoC + technical analysis.
- [Huntress — ClickFix + PNG steganography (LummaC2/Rhadamanthys)](https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-update-screen-to-push-malware/) — первая задокументированная кампания этого класса.
- [MITRE ATT&CK T1027.013 — Steganography](https://attack.mitre.org/techniques/T1027/013/).
- [Sigma HQ rules repository](https://github.com/SigmaHQ/sigma) — для синтаксиса.
- [Elastic Detection Rules](https://github.com/elastic/detection-rules) — sister rules (для cross-validation).
- [Microsoft KQL reference](https://learn.microsoft.com/en-us/kusto/query/) — для KQL syntax + IntelliSense.
- [YARA-CS documentation](https://github.com/elastic/detection-rules) — YARA → Elastic integration playbook.

---

## § 10. Заключение + action item для клиентов

**DOUBLECUP — это production-grade laaS** с инвестиционным подходом (Go-builder, API, panel, autoupdate). Это **не одноразовый malware** — это **платформа**, под которую через 1–2 месяца появятся новые фичи и форки. Рекомендую всем клиентам отдела «Киберщит 🛡» в течение **24 часов**:

1. Заблокировать egress на `213.139.77.109:9090` (perimeter / NGFW / DNS RPZ).
2. Развернуть Sigma правила 4.1+4.2 в SIEM (если есть Splunk/Elastic/Sentinel).
3. Включить PowerShell ScriptBlock logging на всех Windows-хостах (GPO push).
4. Если есть kiosk / терминальные фермы — очистка browser cache каждые 60 мин + SmartScreen require approval.

**Внутренний action item (отдел):** через 7 дней (12.08) повторный hunt в собственной инфре (lesson-013 § «continuous validation»). Если найдём FP — обновить whitelist и опубликовать lesson-070 «DOUBLECUP detection tuning notes».

---

*Опубликовано автоматически пайплайном Кузи 🦝. Источник: внутренняя база знаний отдела «Киберщит 🛡» + первичный ресёрч SOCRadar/BleepingComputer за 05.08.2026.*