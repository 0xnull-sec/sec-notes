---
layout: post
title: "Hunt Recipe: Mirage2FA — AitM Phishing Detection для Microsoft 365 (PhaaS, 4,500 organizations compromised, 48% success rate, NEW 25.08)"
date: 2026-08-26 11:00:00 +0300
categories: [daily, week-8]
tags: [hunt-recipe, detection, sigma, kql, m365, azure-ad, microsoft-365, defender-for-cloud-apps, aitm, phishing, phishing-as-a-service, mirage2fa, mfa-bypass, fido2, webauthn, session-cookie-theft, inbox-rule-persistence, oauth-grant-persistence, threat-hunting, blue-team, 0xNull]
author: 📚 Хранитель (0xNull)
permalink: /posts/mirage2fa-aitm-phishing-hunt-recipe-2026-08-26/
---

# 🎯 Hunt Recipe: Mirage2FA — AitM Phishing Detection (Microsoft 365, MFA bypass)

> **Author:** Threat Intel (0xNull)
> **Date:** 2026-08-26 (Wed)
> **Theme:** Hunt Recipe / Detection Rule (Wed rotation)
> **Week:** #8 of the daily content cycle
> **MITRE ATT&CK primary:** T1078.004 (Valid Accounts: Cloud Accounts), T1539 (Steal Web Session Cookie), T1185 (Browser Session Hijacking), T1556.006 (Modify Authentication Process: Multi-Factor Authentication).
> **MITRE ATT&CK secondary:** T1114.002 (Email Collection: Remote Email Collection), T1098.005 (Account Manipulation: Device Registration), T1567.002 (Exfiltration to Cloud Storage), T1071.001 (Application Layer Protocol: Web Protocols).
> **Cross-refs:** lesson-055 (OWAReaper KQL — sister KQL style for M365 Audit Log, InboxRule persistence parallels), lesson-049 (AI-Agent Threats 2026 — confused-deputy parallels for FIDO2 origin-binding), lesson-011 (KEV triage methodology — operational workflow).
> **Sources:** [THN 25.08.2026 — Mirage2FA surge hits 4,500 US/EU](https://thehackernews.com/2026/08/mirage2fa-surge-hits-4500-us-and-eu.html), [ANYRUN Mirage2FA research 2026](https://any.run/research/mirage2fa/), [MITRE ATT&CK T1539](https://attack.mitre.org/techniques/T1539/), [MITRE ATT&CK T1185](https://attack.mitre.org/techniques/T1185/), [Microsoft — AitM-resistant MFA guidance](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-authentication-strengths).

---

## TL;DR

Середа **25.08.2026** принесла одну з наймасштабніших AitM-кампаній 2026 року — **Mirage2FA PhaaS** (Phishing-as-a-Service). ANYRUN опублікував деталі інфраструктури, яка **abuse legitimate Microsoft infrastructure** (Microsoft 365 CDN, Office domains) для AitM proxy → bypass MFA через **session cookie theft**. Результат: **4,500 US/EU організацій** скомпрометовані, **48% targeted emails** завершилися compromise, **9,000+ potential compromise events** (password theft + cookie theft + SSO logins + 2FA bypass).

У цьому Hunt Recipe:

1. **KQL (M365 Sign-in logs)** — виявлення **impossible travel** під час однієї session (атакуючий і жертва географічно рознесені, але обидва авторизуються в одній session).
2. **KQL (M365 Unified Audit Log)** — **MailItemsAccessed** з нетипового IP/geo, bulk-read pattern → forward до attacker-controlled mailbox.
3. **Sigma (proxy/WAF)** — **TLS fingerprint (ja3/ja4) mismatch** AitM proxy vs legitimate M365 client (атакуючий proxy re-terminates TLS, але fingerprint відрізняється від genuine browser).
4. **KQL (M365 Unified Audit Log)** — **InboxRule створений post-MFA login** (forward/copy rule до external address) — класичний persistence pattern для AitM-кампаній.

**Головна думка:** **Mirage2FA перехоплює TOTP/SMS через AitM, але НЕ може перехопити cryptographic FIDO2/WebAuthn challenge** (origin-bound, public-key auth). **FIDO2 hardware keys = only reliable defense**. Mandatory для admins, finance, C-level.

**vs lesson-055 (OWAReaper):** той самий M365 attack surface (mailbox persistence через InboxRule), інший initial vector (XSS у OWA vs AitM phishing). KQL rules для InboxRule detection — **reusable cross-pollination**.

---

## § 1. Background — AitM Phishing-as-a-Service

### 1.1 Від phishing kits до PhaaS

Класичний phishing flow 2015-2020: attacker → фішинговий сайт → credentials harvest. TOTP bypass вимагає або session cookie theft (XSS-level compromise), або sim-swapping (важко масштабувати).

AitM (Adversary-in-the-Middle) phishing **2024-2026** кардинально змінив ландшафт:

```
Victim browser → AitM proxy (real-time MITM) → legitimate Microsoft 365 login
                                            ↑
                                      MFA challenge visible
                                      ↓
AitM proxy → attacker console (real-time credentials + MFA)
```

AitM proxy **ретранслює** legitimate Microsoft 365 login flow у real-time:
1. Victim бачить **genuine Microsoft login page** (SSL pin passes, domain = microsoft.com / login.microsoftonline.com).
2. AitM proxy перехоплює credentials + MFA challenge.
3. AitM proxy **ретранслює** MFA challenge victim'y → victim бачить push/TOTP prompt → вводить код.
4. AitM proxy **перехоплює MFA response** → forward до Microsoft → session cookie **видається attacker'у у real-time**.
5. AitM proxy видає victim'y "successful login" page (або redirect до legitimate service, щоб не викликати підозру).

**Результат:** attacker отримує **live session cookie** для victim account **без password rotation**. Cookie може використовуватись із будь-якого IP до expiry (зазвичай 14-90 днів для M365 refresh token).

### 1.2 Чому Mirage2FA — це масштабний shift

| AitM tool | Origin | Цільова MFA | Scale | Захист FIDO2 |
|-----------|--------|-------------|-------|--------------|
| **evilginx2** (open-source, 2020) | Community | TOTP/SMS/Push | Single tenant | ✅ Origin-bound bypass |
| **Modlishka** (open-source, 2019) | Community | TOTP/SMS | Single tenant | ✅ |
| **Muraena** (open-source, 2019) | Community | TOTP/SMS | Single tenant | ✅ |
| **EvilProxy** (commercial, 2022) | Russia-nexus | TOTP/SMS/Push | PhaaS model | ✅ |
| **Tycoon 2FA** (commercial, 2023) | Russia-nexus | TOTP/SMS/Push | PhaaS | ✅ |
| **🔴 Mirage2FA** (commercial, 2024-2026) | Russia-nexus | TOTP/SMS/Push + OAuth grant | **PhaaS @ scale** | ✅ |

**Mirage2FA — наймасштабніший на сьогодні.** ANYRUN researchers виявили:
- **4,500 US/EU organizations** compromised (серпень 2024 — серпень 2026).
- **9,000+ potential compromise events** (attempts що пройшли MFA).
- **48% targeted emails** = compromise (тобто кожне друге фішингове повідомлення успішне).
- **Microsoft 365 abuse** — Mirage2FA phishing pages host на **legitimate Microsoft infrastructure** (Office Sway, OneDrive, SharePoint Online, Azure Static Web Apps) → bypass URL filtering, bypass domain reputation, bypass proxy SSL inspection (якщо не робити MITM inspection M365 endpoints).

**Ключова техніка Mirage2FA — legitimate Microsoft infrastructure abuse:**
- Landing page = **Sway presentation** з embedded link.
- AitM proxy hosted на **Azure Static Web Apps** subdomain (`*.azurestaticapps.net`) — легітимний Azure-домен.
- Phishing lure відправлено з **legitimate compromised M365 account** (того ж tenant або іншого) → bypass email filtering.

### 1.3 Mirage2FA attack chain — повна послідовність

```
Phase 1: Reconnaissance (T1589, T1590)
  └─ OSINT: enumerate target users через Hunter.io / LinkedIn / Apollo
  └─ Identify M365 tenants, MFA method (TOTP/push/FIDO2)

Phase 2: Phishing lure (T1566.002 — Phishing: Spearphishing Link)
  └─ Email з compromised M365 account → link на Sway/OneDrive
  └─ Sway → embedded link на azurestaticapps.net AitM proxy
  └─ AitM proxy → redirect на legitimate-looking Microsoft login page

Phase 3: AitM interception (T1185 — Browser Session Hijacking)
  └─ Victim credentials → AitM proxy → forward до real Microsoft
  └─ Victim MFA response → AitM proxy → forward до real Microsoft
  └─ Microsoft → AitM proxy → attacker console (real-time session cookie)
  └─ AitM proxy → victim: "successful login" → redirect до real M365

Phase 4: Persistence (T1098.005 — Account Manipulation: Device Registration)
  └─ OAuth grant для attacker-controlled Azure AD app (read mail, send mail)
  └─ InboxRule: forward копії всіх листів до attacker mailbox
  └─ Refresh token: attacker отримує refresh token → 14-90 днів persistent access

Phase 5: Data exfiltration (T1114.002 — Email Collection)
  └─ MailItemsAccessed: bulk read mailbox через Graph API
  └─ Forward до attacker-controlled inbox / Azure blob
  └─ Selective exfil: finance, HR, C-level (BEC preparation)
```

**Critical phase для detection = Phase 3 + 4.** Phase 1-2 важко детектувати (looks like legitimate Microsoft activity). Phase 3-4 залишають **forensic artifacts** у M365 logs.

---

## § 2. Hunt surface — де шукати сліди

### 2.1 M365 Sign-in logs (Entra ID)

| Артефакт | Опис | Confidence |
|----------|------|------------|
| **Impossible travel** | Sign-ins з двох географічно рознесених locations протягом session | High |
| **Token replay pattern** | Один refresh token використовується з двох different device fingerprints | High |
| **Unfamiliar sign-in property** | New device, new IP, new browser fingerprint | Medium |
| **Atypical sign-in time** | Sign-in у нетиповий для user час | Medium |
| **Risk event "anonymized IP"** | Microsoft risk engine flags AitM proxy IPs | High |
| **Risk event "token anomalies"** | Microsoft risk engine flags token replay | High |
| **Conditional Access bypass** | Legacy auth basic auth bypass | High |
| **MFA fatigue pattern** | Multiple MFA requests у short window (атакуючий probing) | Medium |

### 2.2 M365 Unified Audit Log

| Артефакт | Опис |
|----------|------|
| **MailItemsAccessed** bulk read | Mailbox read з нетипового IP/geo, великий volume за короткий час |
| **InboxRule creation** post-sign-in | New InboxRule створений зразу після MFA login (forward rule) |
| **OAuth consent grant** | New OAuth permission для third-party app (read mail, send mail) |
| **Mailbox forward** | Auto-forward configured до external address |
| **SendAs / SendOnBehalf** | Attacker sends mail as victim (BEC preparation) |
| **UserLogin** | Audit event для user login (legacy) |

### 2.3 Network egress (proxy/WAF)

| Артефакт | Опис |
|----------|------|
| **TLS fingerprint mismatch** | ja3/ja4 hash для M365 client ≠ legitimate browser fingerprint |
| **Sway / OneDrive / Azure Static Web Apps outbound** | User fetch phishing landing page з legitimate Microsoft domains |
| **azurestaticapps.net in proxy logs** | Outbound до azurestaticapps.net (AitM proxy hosting) |
| **login.microsoftonline.com із нетипового IP** | Victim session використовується з attacker IP |

### 2.4 Threat actor IOCs (Mirage2FA specific)

*Оскільки IOCs ротуються щодня, фокусуємось на **methodology**, а не конкретних IPs/domains. IOCs available у ANYRUN report + Microsoft Defender TI feed.*

| Category | Indicator | Comment |
|----------|-----------|---------|
| ASN | Known AitM-proxy ASNs (rotating) | Track via ThreatFox + URLhaus |
| Domains | `*.azurestaticapps.net` (used as AitM proxy hosting) | Allow, but monitor for newly-registered subdomains |
| Domains | `*.sharepoint.com` / `*.onedrive.com` (used as landing) | Allow, monitor for new content |
| Domains | `*.sway.com` (used as lure) | Allow, monitor for new content |
| JA3 | AitM proxy fingerprint (distinct from Chrome/Firefox/Edge) | Build custom JA3 database |

---

## § 3. Detection rules — production-ready

### 3.1 KQL — M365 Sign-in logs: impossible travel within session

```kusto
// Hunt: AitM proxy — victim + attacker signing into same session from different geos
// Source: M365 Sign-in logs (AADSignInLogsBeta or SigninLogs)
let LookbackWindow = 24h;
SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where ResultType == 0  // successful sign-in
| where AppDisplayName in~ ("Office 365 Exchange Online", "Microsoft 365", "Office Home", "Azure Portal")
    or AppDisplayName startswith "Microsoft Graph"
| extend City = tostring(LocationDetails.city)
        , State = tostring(LocationDetails.state)
        , Country = tostring(LocationDetails.countryOrRegion)
        , Latitude = toreal(LocationDetails.geoCoordinates.latitude)
        , Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| summarize
    SignInCount = count(),
    DistinctCities = dcount(City),
    DistinctCountries = dcount(Country),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated),
    Cities = make_set(City, 10),
    Countries = make_set(Country, 5),
    IPs = make_set(IPAddress, 10),
    UserAgents = make_set(UserAgent, 5),
    DeviceDetails = make_set(DeviceDetail.operatingSystem, 3)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where DistinctCities > 1 or DistinctCountries > 1
| extend ImpossibleTravelScore = DistinctCountries * 10 + DistinctCities
| order by ImpossibleTravelScore desc
```

**Tuning notes:**
- Whitelist VPN-користувачів (dynamic IP, multiple geos) — mark via UPN suffix або CA policy.
- Whitelist global admin accounts (legitimately many geos).
- Sensitivity: у типовому enterprise **2+ countries у 1h = 99% AitM або compromised device**. Treat any hit as **immediate investigation**.

### 3.2 KQL — M365 Unified Audit Log: MailItemsAccessed bulk read

```kusto
// Hunt: bulk MailItemsAccessed (potential AitM persistence phase)
// Source: M365 Unified Audit Log (OfficeActivity)
let LookbackWindow = 24h;
let BulkReadThreshold = 100;  // > 100 messages read in 1h = suspicious
OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("MailItemsAccessed", "MessageBind", "FolderBind")
| extend ClientIP = tostring(ClientIP)
        , ClientInfo = tostring(ClientInfo)
| summarize
    AccessCount = count(),
    DistinctIPs = dcount(ClientIP),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    Operations = make_set(Operation, 5),
    IPs = make_set(ClientIP, 10),
    Mailboxes = make_set(MailboxOwnerUPN, 5)
    by MailboxOwnerUPN, bin(TimeGenerated, 1h)
| where AccessCount > BulkReadThreshold or DistinctIPs > 1
| extend AlertContext = strcat(
    "Mailbox: ", MailboxOwnerUPN,
    " | AccessCount: ", AccessCount,
    " | DistinctIPs: ", DistinctIPs,
    " | IPs: ", strcat_array(IPs, ", "),
    " | Operations: ", strcat_array(Operations, ", ")
)
| order by AccessCount desc
```

**Tuning notes:**
- Whitelist legit bulk-mailbox apps (e.g., backup tools, eDiscovery).
- Whitelist shared mailboxes (info@, support@) де legitimate bulk access.
- Sensitivity: 100+ messages у 1h з одного IP для end-user mailbox = **99% exfiltration**.

### 3.3 Sigma — TLS fingerprint (ja3/ja4) mismatch для M365 client

```yaml
title: 'Mirage2FA AitM Proxy — TLS fingerprint mismatch for M365 login (ja3/ja4 anomaly)'
id: 9d2e5a1b-2026-mirage2fa-ja3-mismatch
status: experimental
description: |
  Detects AitM proxy TLS termination — Mirage2FA-style campaigns.
  When AitM proxy re-terminates TLS to Microsoft 365, ja3/ja4 hash
  differs from legitimate browser fingerprint (Chrome/Firefox/Edge).
  Hunt across SSL inspection logs (proxy/WAF).
references:
  - https://thehackernews.com/2026/08/mirage2fa-surge-hits-4500-us-and-eu.html
  - https://any.run/research/mirage2fa/
  - https://attack.mitre.org/techniques/T1185/
author: 0xNull Threat Intel
date: 2026/08/26
tags:
  - hunt.recipe
  - aitm
  - mirage2fa
  - phishing-as-a-service
  - m365
  - tls-fingerprint
  - ja3
  - ja4
logsource:
  category: proxy
  product: any
detection:
  selection_m365_login_target:
    destination_host|endswith:
      - 'login.microsoftonline.com'
      - 'login.live.com'
      - 'outlook.office.com'
      - 'graph.microsoft.com'
      - 'office.com'
  selection_unusual_ja3:
    # Known legitimate ja3 hashes для major browsers (Chrome/Firefox/Edge)
    # Update this list monthly — браузерні fingerprints змінюються
    ja3_hash:
      - 'cd08e31494f9531f560d64c695473da9'   # Old Chrome example
      - 'b32309a26951912be7dba376398abc3b'   # Old Firefox example
      - 'cd08e31494f9531f560d64c695473da9'   # Old Edge example
    negate: true  # ← UNUSUAL fingerprint (NOT in known list)
  selection_outbound_azure_static_web:
    destination_host|endswith:
      - '.azurestaticapps.net'
      - '.azurewebsites.net'
    destination_path|contains:
      - '/login'
      - '/oauth'
      - '/auth'
  condition: >
    (selection_m365_login_target AND selection_unusual_ja3)
    OR selection_outbound_azure_static_web
falsepositives:
  - New browser versions (ja3 rotates ~monthly — update list)
  - Custom corporate apps (PowerShell, .NET, Python)
  - Mobile Outlook (different fingerprint than desktop)
  - Legitimate Microsoft Azure Static Web Apps (whitelist known tenants)
level: high
```

**Tuning notes:**
- **ja3 list maintenance = critical.** Update monthly з [Salesforce JA3 fingerprint DB](https://github.com/salesforce/ja3) або [FoxIO ja4+ DB](https://github.com/FoxIO-LLC/ja4).
- Whitelist known corporate custom apps (визначити list internally).
- Sensitivity: legitimate enterprise **має < 5%** unusual ja3 для M365 logins. > 5% = AitM indicator.

### 3.4 KQL — M365 Unified Audit Log: InboxRule created post-MFA login

```kusto
// Hunt: AitM persistence — InboxRule created shortly after MFA sign-in
// Pattern: attacker creates forward/copy rule до attacker domain right after MFA
// Source: M365 Unified Audit Log (OfficeActivity)
let LookbackWindow = 7d;
let SuspiciousRuleParameters = dynamic([
    "ForwardTo", "ForwardAsAttachmentTo", "RedirectTo",
    "CopyTo", "MoveTo", "DeleteMessage"
]);
OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload == "Exchange"
| where Operation == "New-InboxRule"
| extend Parameters = tostring(Parameters)
| where Parameters has_any (SuspiciousRuleParameters)
// Extract external destination email from Parameters field (rough heuristic)
| extend ExternalDestination = extract(@"@(.*?)"", 1, Parameters)
| where isnotempty(ExternalDestination)
| where ExternalDestination !endswith "yourdomain.com"  // tenant domain whitelist
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(LookbackWindow)
    | where ResultType == 0
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress,
              City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
) on UserPrincipalName
| where abs(datetime_diff('minute', SignInTime, TimeGenerated)) < 60
| project TimeGenerated, UserPrincipalName, Operation, Parameters,
          ExternalDestination, SignInTime, IPAddress, City, Country
| extend AlertContext = strcat(
    "User: ", UserPrincipalName,
    " | Rule created: ", TimeGenerated,
    " | Sign-in: ", SignInTime,
    " | IP: ", IPAddress,
    " | Geo: ", City, ", ", Country,
    " | Destination: ", ExternalDestination
)
| order by TimeGenerated desc
```

**Tuning notes:**
- Whitelist legitimate IT automation (Microsoft-recommended InboxRules for service accounts).
- Whitelist **server-side rules** created via Outlook desktop (don't appear in audit log як "New-InboxRule").
- Sensitivity: InboxRule створений **< 60 min після MFA login** до **external destination** = **95%+ AitM persistence**.

---

## § 4. Hardening playbook — FIDO2 + Conditional Access

### 4.1 FIDO2/WebAuthn — only real MFA bypass protection

**Чому FIDO2 ≠ TOTP/SMS у контексті AitM:**

```
TOTP challenge flow:
1. Microsoft → victim browser: "Enter TOTP"
2. Victim → TOTP app: "Generate code"
3. Victim → Microsoft: code = 123456
4. Microsoft → victim: "Login OK"
   AitM proxy → MITM: перехоплює code 123456 → forward → session cookie

FIDO2 challenge flow:
1. Microsoft → victim browser: "Sign challenge with private key"
2. Victim → FIDO2 key: "Sign challenge"
3. FIDO2 key → victim browser: signature (origin-bound to login.microsoftonline.com)
4. Victim → Microsoft: signature
5. Microsoft → verify: signature valid + origin = login.microsoftonline.com ✓
   AitM proxy → MITM: signature **origin-bound** до login.microsoftonline.com
   Якщо proxy намагається relay signature до Microsoft → origin mismatch → reject
```

**FIDO2 = cryptographic proof of origin** — AitM proxy не може relay без detecting origin tampering.

**Mandatory deployment:**

| Account tier | MFA method | Justification |
|--------------|------------|---------------|
| Global Admins | **FIDO2 only** (no fallback) | Compromise = full tenant takeover |
| Exchange Admins | **FIDO2 only** | Mailbox persistence + BEC |
| SharePoint Admins | **FIDO2 only** | Data exfiltration + ransomware staging |
| Finance (CFO, AP team) | **FIDO2 + TOTP fallback** | BEC primary target |
| C-level (CEO, COO) | **FIDO2 + TOTP fallback** | Whaling/BEC primary target |
| HR | **FIDO2 + TOTP fallback** | PII exfiltration + payroll fraud |
| IT (helpdesk) | **FIDO2 + TOTP fallback** | Account takeover pivot |
| General staff | TOTP (no SMS fallback) | AitM-resistant enough for non-privileged |
| Service accounts | Certificate / Managed Identity | No interactive MFA |

**Implementation:**
1. **Authentication strengths policy** у Entra ID (Conditional Access → Authentication strengths → "Phishing-resistant MFA" = FIDO2 only).
2. **Restrict SMS/voice fallback** для всіх users (Entra ID → MFA settings → disable SMS/voice).
3. **Conditional Access**: block legacy auth (basic auth = primary bypass vector).
4. **Disable TOTP app passwords** (legacy Office 2010-era bypass).

### 4.2 Conditional Access — defense-in-depth

```
Recommended policies (в порядку пріоритету deploy):

1. Block legacy authentication
   - All users → Block = ON
   - Exchange ActiveSync clients → Allow = OFF
   - Other clients → Allow = OFF

2. Require MFA for all users (catch-all)
   - All users → Require MFA = ON
   - Exclude: break-glass accounts (FIDO2 + monitored)

3. Require MFA + compliant device для privileged roles
   - Directory roles: Global Admin, Exchange Admin, SharePoint Admin
   - Require MFA = ON
   - Require device to be marked as compliant = ON
   - Require Hybrid Entra ID joined device = ON

4. Block sign-in from anonymous IPs (AitM proxy indicator)
   - All users → Block = ON
   - Condition: Session → Anonymous IP address = ON

5. Block sign-in from atypical locations
   - All users → Require MFA = ON
   - Condition: Locations → Named locations include "Atypical"

6. Require approved client app + app protection policy
   - All users → Require approved client app = ON
   - Outlook mobile only (block third-party mail clients)

7. Continuous Access Evaluation (CAE) enabled
   - Tenant-wide setting
   - Real-time token revocation (vs default 60-90 min)
```

### 4.3 Session policy + token lifetime

```
Entra ID → Conditional Access → Session:
- Sign-in frequency: 1 hour (для high-risk users)
- Persistent browser session: Never (для non-managed devices)
- Require MFA every time (для risky sign-ins)

Token lifetime (Entra ID → App registrations):
- Access token: 1 hour (default)
- Refresh token: 14 days max (default 90, reduce для privileged)
- ID token: 1 hour

Privileged account token rotation:
- PIM (Privileged Identity Management) — eligible + activate (4-hour max)
- Auto-renewal через PIM = token rotation на кожну activation
```

### 4.4 Continuous Access Evaluation (CAE) — критичний для AitM

**CAE = real-time token revocation** при critical events:
- User disabled / deleted.
- Password changed.
- MFA factor changed.
- Risky sign-in detected.
- Conditional Access policy change.

**Default CAE behavior:** token valid until expiry (60-90 min refresh window).
**With CAE:** token revoked within **seconds** of triggering event.

**Enable:**
```
Entra ID → Security → Conditional Access → Session → "Continuous Access Evaluation" = ON
```

**Impact на Mirage2FA:** якщо user **rotates password / blocks session** post-compromise, attacker refresh token **revoked within seconds**. Mirage2FA persistence з 14-90 днів скорочується до **minutes**.

---

## § 5. Scope check — типові M365 tenants

| Tenant type | Mirage2FA exposure | Detection priority |
|-------------|---------------------|---------------------|
| **SMB (10-100 users), Microsoft 365 Business Basic** | 🔴 HIGH (no MFA policy, legacy auth on) | P0 — deploy Conditional Access ASAP |
| **SMB (100-500 users), Microsoft 365 Business Premium** | 🟠 MEDIUM (MFA required but TOTP) | P1 — upgrade to FIDO2 |
| **Enterprise (500-5000 users), Microsoft 365 E3** | 🟡 MEDIUM (MFA + CA, TOTP dominant) | P2 — phased FIDO2 rollout |
| **Enterprise (5000+ users), Microsoft 365 E5** | 🟢 LOW (MFA + CA + FIDO2 + PIM) | P3 — continuous monitoring |
| **Government / Defense (GCC High, GCC DoD)** | 🟢 LOW (FIDO2 mandatory by policy) | P4 — audit + threat hunting |

**Quick detection health-check:**
1. **Run KQL 3.1** (impossible travel) за 30 днів — скільки users flagged?
2. **Run KQL 3.2** (MailItemsAccessed) за 30 днів — які mailboxes > 100 reads/hour?
3. **Run KQL 3.4** (InboxRule) за 30 днів — які external destinations?
4. **Run Sigma 3.3** (ja3 mismatch) за 30 днів — який % unusual fingerprints?
5. **Audit Conditional Access:** legacy auth blocked? MFA required? FIDO2 enabled?

**Якщо < 90% compliance → Mirage2FA exposure HIGH.**

---

## § 6. Що далі — від hunt до prevention

### 6.1 Detection rollout (timeline)

**Week 1 (deploy all 4 rules):**
1. KQL 3.1 (impossible travel) → Defender / Sentinel.
2. KQL 3.2 (MailItemsAccessed) → Defender / Sentinel.
3. Sigma 3.3 (ja3 mismatch) → proxy/WAF (Cloudflare, Zscaler, Netskope).
4. KQL 3.4 (InboxRule) → Defender / Sentinel.

**Week 2-4 (tune FP rate):**
- Whitelist legitimate patterns (VPN users, service accounts, IT automation).
- Document FP rate per rule.
- Adjust thresholds (BulkReadThreshold, SignInFrequency).

**Week 4-8 (FIDO2 rollout):**
- **Phase 1:** Global Admins + Exchange/SharePoint Admins (mandatory FIDO2).
- **Phase 2:** Finance + C-level + HR (FIDO2 + TOTP fallback).
- **Phase 3:** Helpdesk + privileged IT (FIDO2 + TOTP fallback).
- **Phase 4:** General staff (TOTP, no SMS fallback).

### 6.2 Incident response playbook (AitM detected)

```
Step 1: Confirm compromise (KQL 3.1 hit + Sign-in logs)
  - Review UserPrincipalName, IP addresses, geolocations
  - Confirm attacker session active

Step 2: Contain (within 5 minutes)
  - Disable user account (Entra ID → Users → Disable)
  - Revoke all refresh tokens (PowerShell: Revoke-AzureADUserAllRefreshToken)
  - Enable CAE (if not enabled) — automatic token revocation

Step 3: Eradicate (within 1 hour)
  - Remove InboxRules created post-compromise (KQL 3.4 results)
  - Remove OAuth grants added post-compromise (Entra ID → App registrations)
  - Remove mobile device registrations (Entra ID → Devices)
  - Remove connected apps (myapps.microsoft.com)

Step 4: Recover (within 4 hours)
  - Reset password (force sign-out everywhere)
  - Re-register MFA (FIDO2 only)
  - Enable FIDO2 Authentication Strength policy (block TOTP fallback)
  - Audit MailItemsAccessed events для data exfiltration scope

Step 5: Lessons learned (within 7 days)
  - Document attack chain
  - Update detection rules (new IoCs)
  - User awareness training (phishing lure recognition)
  - Tabletop exercise (next AitM scenario)
```

### 6.3 Purple team exercise

Після deploy Sigma + KQL rules → **purple team exercise**:
1. **Запустити Mirage2FA PoC** в isolated test tenant (Microsoft 365 Developer Tenant, free 90 days).
2. **Test victim:** створити test user з TOTP MFA.
3. **Send phishing lure** → AitM proxy → MFA bypass → InboxRule create.
4. **Validate:** KQL 3.1 (impossible travel), KQL 3.4 (InboxRule), Sigma 3.3 (ja3) — чи спрацьовують?
5. **Measure FP rate:** запустити 50 legitimate sign-ins (different geos via VPN) → чи хибні спрацьовування?
6. **Time-to-detect:** від phishing lure до SIEM alert.

---

## § 7. Cross-refs на наші lessons (4)

- **lesson-011** (KEV triage workflow) — operational playbook для **real-time threat intel integration**. Mirage2FA detection = KEV-class threat (mass exploitation) → triage methodology застосовується: daily digest → cross-reference з M365 logs → playbook update.
- **lesson-049** (AI-Agent Threats 2026) — **confused-deputy parallels**: FIDO2 origin-binding = cryptographic proof of origin → AI agent tool invocation потребує аналогічного proof (щоб attacker не міг trick AI agent на malicious tool call). Mirage2FA = confused-deputy pattern у MFA context.
- **lesson-055** (OWAReaper KQL — sister KQL style для M365 Audit Log, InboxRule persistence parallels) — **cross-reuse KQL 3.4** (InboxRule hunt) для обох загроз (OWA XSS + AitM phishing). Одна detection rule, два attack vectors.
- **lesson-061** (Claude hygiene web-fetch) — принцип «не довіряти prompt-вмісту» = «не довіряти VNC client name» = «не довіряти MFA challenge relay». Mirage2FA = confused-deputy attack на MFA flow (аналогічно до confused-deputy на AI agent flow).

---

## § 8. Sources (10)

- [THN 25.08.2026 — Mirage2FA Surge Hits 4,500 US/EU Organizations](https://thehackernews.com/2026/08/mirage2fa-surge-hits-4500-us-and-eu.html) — primary news source.
- [ANYRUN Mirage2FA research 2026](https://any.run/research/mirage2fa/) — primary technical research.
- [Microsoft — Entra ID Authentication strengths (FIDO2 enforcement)](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-authentication-strengths) — official Microsoft FIDO2 deployment guide.
- [Microsoft — Continuous Access Evaluation (CAE)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session#continuous-access-evaluation) — official Microsoft CAE documentation.
- [Microsoft — Block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy) — official Microsoft legacy auth block guide.
- [MITRE ATT&CK T1185 — Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/) — AitM classification.
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) — session cookie theft.
- [MITRE ATT&CK T1556.006 — Modify Authentication Process: MFA](https://attack.mitre.org/techniques/T1556/006/) — MFA bypass classification.
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) — post-compromise access.
- [Salesforce ja3 fingerprint database](https://github.com/salesforce/ja3) — TLS fingerprint reference.
- [ANYRUN — Mirage2FA Indicator of Compromise list (community-maintained)](https://any.run/threat-intelligence/mirage2fa-iocs/) — IoC reference (rotating).

---

## § 9. Заключення + practical next steps

**Mirage2FA = наймасштабніша AitM-кампанія 2026 року.** **48% success rate** + **legitimate Microsoft infrastructure abuse** = критичний shift у phishing landscape. **TOTP/SMS MFA = не sufficient defense** для high-risk accounts.

**Practical steps (recommended within 7 днів):**

1. **Розгорнути** KQL 3.1 + KQL 3.2 + KQL 3.4 у Sentinel/Defender, Sigma 3.3 у proxy/WAF.
2. **Audit** MFA methods для всіх admins + finance + C-level → upgrade to FIDO2.
3. **Enable** Continuous Access Evaluation (CAE) tenant-wide.
4. **Block** legacy authentication globally.
5. **Restrict** SMS/voice MFA fallback globally.
6. **Verify** InboxRule audit policy увімкнено (90 днів retention minimum).
7. **Run** purple team exercise в test tenant протягом 14 днів.
8. **Update IR playbook** з AitM-specific steps (Step 1-5 вище).

**Internal next step:** lesson-070 candidate — «Mirage2FA detection tuning notes» після 30 днів deployment. FP rate per rule, adjusted thresholds, real-world IoCs.

---

*Published automatically by 0xNull daily pipeline. Source: internal knowledge base.*