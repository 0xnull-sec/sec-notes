---
layout: post
title: "Book Quote + Commentary — The Three Classes of Threats That Bypass EDR (Al-Fardan meets 04.09.2026)"
date: 2026-09-04 11:00 +0300
categories: [daily, week-35]
tags: [threat-hunting, lolbin, supply-chain, edr-evasion, clicklock, hollowgraph, shai-hulud, npm, book-quote, al-fardan]
author: Khranitel
---

# Book Quote + Commentary — The Three Classes of Threats That Bypass EDR (Al-Fardan meets 04.09.2026)

> **TL;DR.** Nadhem Al-Fardan's *Threat Hunting* (Manning, 2024 / Russian edition: Питер, 2026) opens with a deceptively simple taxonomy of the threats that signature-based EDR cannot catch: **LOLBins**, **fileless malware**, and **supply-chain compromise**. Two years later, on 04.09.2026, all three classes are live in the wild at the same time — **HOLLOWGRAPH** (cloud-API LOLBin), **ClickLock Stealer** (LOLBin + fileless on macOS), and **Shai-Hulud mini-wave** (npm supply-chain worm). The taxonomy still predicts the incident feed. The book is still right.

---

## The Quote (Al-Fardan, *Threat Hunting*, Ch. 1 — *Introduction to Threat Hunting*)

> *"Signature-based detection — the engine under antivirus, IDS and the first generation of EDR — works against threats that *sign* themselves: known hashes, known byte sequences, known YARA rules. It fails against three classes of attacker that operate below the signature line:*
>
> *— **Living-off-the-land** binaries (LOLBins): PowerShell, WMI, certutil, mshta, regsvr32 — binaries that are signed by Microsoft, run on every Windows host, and have legitimate administrative uses.*
>
> *— **Fileless malware**: code that lives only in process memory, in registry `Run` keys, in WMI event subscriptions — leaving nothing for a disk-based antivirus to scan.*
>
> *— **Supply-chain compromise**: SolarWinds, Kaseya, 3CX — the attacker does not attack the victim directly; they attack a *trusted third party* upstream, ride the signed update channel, and land inside the perimeter already whitelisted."*

The book makes a structural argument around the quote: **detection rules written against signatures cannot defend against attackers that *are* the signature.** LOLBins are signed by Microsoft. Fileless malware has no file to hash. Supply-chain payloads ride the vendor's own update channel. The defender's choice is binary — either hunt on behaviour, or accept blind spots.

---

## Why this taxonomy still holds in 2026

The book was published in mid-2024 (Russian edition early 2026). On **04.09.2026** — twenty-eight months after the English first edition — the three classes Al-Fardan named are **not historical curiosities. They are the live incident feed.**

Three different families, three different vendors, three different kill-chains — and the public detection story for each is "signature-based EDR missed it." Let us walk through them one by one.

---

## Class 1 — LOLBins, cloud-era edition: HOLLOWGRAPH (M365 Graph API as C2)

**What happened.** Security researchers at Petri IT Knowledgebase published technical details (03.09.2026) on a new Windows implant tracked as **HOLLOWGRAPH**, part of the broader **Cavern framework** ecosystem that has been active throughout 2026. HOLLOWGRAPH's defining trick is its C2 channel.

**The cloud-API LOLBin.** Instead of using a traditional C2 server (which would light up network IDS rules), HOLLOWGRAPH uses **legitimate Microsoft Graph API calls**. Commands are encoded into **M365 Calendar event metadata** — subject lines, body fields, recurrence rules — and the implant polls Graph as a normal M365 client. Responses are stored as **Calendar event attachments**. To Defender for Endpoint / Defender for Cloud Apps / a SIEM watching network flows, this looks like **ordinary HTTPS traffic to `graph.microsoft.com`** from an already-authenticated M365 session.

**Why signature-based detection misses it.** There is no malicious IP, no C2 beacon pattern (the polling cadence is the same as Outlook's), no unusual DNS lookup, no malware hash. The artefact is "a user who creates and reads a lot of calendar entries" — a behaviour that *every M365 user* does. Al-Fardan's LOLBin argument, page 5, applies almost word-for-word to the cloud-API era: *the attacker is using signed, legitimate, ubiquitous infrastructure.*

**The defender's answer.** Al-Fardan Ch. 4 (Threat Intelligence Feeds) and Ch. 7 (Time-Series Analysis) suggest hunting for the **rate, not the content**. Calendar polling at 5-second intervals from a process that is not `Outlook.exe` is anomalous. Calendar reads originating from a non-Microsoft binary (e.g. `dllhost.exe` spawning Graph traffic) is anomalous. Calendar reads from a host that has no active Outlook profile is anomalous. None of these are signatures. All of them are behavioural baselines.

---

## Class 2 — LOLBins + fileless on macOS: ClickLock Stealer

**What happened.** SecurityWeek and Group-IB TG-channel coverage (03–04.09.2026) on the **ClickLock Stealer** family — a modular macOS infostealer that combines three EDR-evasion primitives in one binary.

**The kill chain.**

1. **ClickFix social engineering.** User is prompted (fake CAPTCHA, fake "verify you are human" page, fake PDF viewer prompt) to paste a command into Terminal. The command installs the stealer.
2. **Process killing loops.** Once running, ClickLock iterates over running processes and **kills anything that looks like an EDR / XDR / macOS-credential-related guard** — Gatekeeper helpers, XProtect scanners, third-party EDR agents. The kills happen **fast and in parallel**, before the EDR's own self-defence timer.
3. **Fileless credential extraction.** ClickLock then dumps the **macOS credential store** (the user's login-keychain) **and** browser cookies / autofill / crypto-wallet browser extensions, exfiltrating them over HTTPS to attacker-controlled infrastructure. No payload is written to disk after the initial drop — the rest is fileless.

**Why signature-based detection misses it.**

- The dropper is small and one-shot; by the time a YARA rule ships, the next wave has repacked it.
- The process kills are **legitimate syscalls** — `kill -9` against a process is not a malicious operation in isolation.
- The credential-store read uses Apple's own `security` CLI, a signed binary that is the **macOS-blessed way to read the credential store**.
- The exfiltration goes over HTTPS to a single, normal-looking domain.

This is the LOLBin argument applied to **Apple's own signed utilities**, plus the fileless argument applied to **credential-store reads** (which never touch the filesystem).

**The defender's answer.**

- **Behaviour-based EDR / EDR-XDR combos that watch for sudden bursts of `kill()` syscalls** are the only ones that catch step 2. CrowdStrike, SentinelOne and Microsoft Defender for Endpoint on macOS have rules in this direction, but they fire *after* the kills happen, not before.
- **Endpoint hardening on macOS**: disable Terminal access for non-admin users (via MDM), block `osascript` from running unprompted user input, enforce notarised-app-only Gatekeeper policy in **System Settings → Privacy & Security**.
- **User training**: the ClickFix step requires the user to *paste into Terminal*. Anything that trains the user to refuse that prompt closes the entire kill chain.

---

## Class 3 — Supply-chain: Shai-Hulud mini-wave (Elastic Security Labs, 04.09.2026)

**What happened.** On 03–04.09.2026, **Elastic Security Labs** confirmed a fresh Shai-Hulud propagation event — the third wave in two months. This wave compromised the **`keyv`** npm package maintainer account, used the maintainer's publish token to ship malicious versions of `keyv` and 280 downstream packages, and added **postinstall scripts** that exfiltrated environment variables, `.npmrc` tokens, and CI/CD secrets to **469 credential locations** (a mix of public GitHub repos and attacker-controlled endpoints).

**Why this is the textbook supply-chain compromise.** The package versions were **signed by the legitimate maintainer**, distributed over the **official npm registry**, and consumed by **`npm install` with no warning**. There is nothing to signature-match. The malicious code is in **plain JavaScript** but hidden in a `postinstall` hook that runs once per install — too late for `npm audit` on the consumer side.

**Why this matters beyond `keyv`.** Shai-Hulud is **worm-style** — once it lands in a CI/CD pipeline with publish rights to npm, it uses those rights to push more malicious packages under the maintainer's other namespaces. The blast radius is **whatever the maintainer controls**. For a maintainer with 50 packages and 5 million weekly downloads, that is **5 million weekly installs of a credential-exfiltrating update.**

This is the SolarWinds / Kaseya / 3CX pattern, ported to **npm**. Al-Fardan Ch. 4 explicitly cites those three incidents and warns: *the upstream-trust model fails when the upstream itself is compromised.*

**The defender's answer.**

- **`npm install --ignore-scripts`** for non-build environments (CI runners that don't need to compile native modules).
- **Pin and verify**: `npm ci` instead of `npm install` in CI; verify `package-lock.json` against a Sigstore-signed provenance bundle; lock `registry` to a vetted mirror.
- **Multi-maintainer review** for any package with > 100k weekly downloads (Shai-Hulud specifically targets single-maintainer packages).
- **Secret rotation cadence** for any CI/CD secret that has touched a `postinstall` hook — assume compromise and rotate.

---

## Cross-cutting theme: behavioural detection is the only answer

Al-Fardan's argument in Ch. 2 (*Basic Threat Hunting Principles*) is that **hunting is hypothesis-driven, not signature-driven.** The book's hunting cycle is:

```
Hypothesis (what TTP / class / vendor)
    → Data source (logs / EDR telemetry / network flows)
        → Baseline (what does *normal* look like?)
            → Anomaly (what deviates from baseline?)
                → Response (isolate, capture, eradicate)
                → Feedback (update baseline, write detection rule)
```

Applied to today's three incidents:

| Class | Hypothesis (TTP) | Data source | Anomaly |
|---|---|---|---|
| Cloud-API LOLBin | Graph API calls from non-Microsoft binary | M365 audit logs + EDR process telemetry | Calendar polling from `dllhost.exe` |
| macOS LOLBins + fileless | Burst of `kill()` syscalls + credential-store read | EDR process telemetry + macOS `log show` | 5+ processes killed within 1s by a non-admin process |
| Supply-chain | `postinstall` hook with outbound HTTP | npm install logs + outbound-flow logs | Any outbound HTTPS during `npm install` |

None of these are signatures. All of them are behavioural. **The 2024 taxonomy correctly identifies the class; only behavioural hunting closes it.**

---

## Practical checklist (do these today)

1. **Audit your M365 audit-log retention.** If you do not retain Graph API call logs for ≥ 90 days, you cannot hunt HOLLOWGRAPH-style implants retroactively. `Set-AdminAuditLogConfig -LogAgeLimit 90.00:00:00` or higher.
2. **Enable `npm ci` + `--ignore-scripts` in CI** for any pipeline that does not build native dependencies. Add an outbound-egress firewall that alerts on HTTPS during `npm install`.
3. **Enable macOS EDR's process-kill-burst detection.** CrowdStrike Falcon, SentinelOne Singularity, and Microsoft Defender for Endpoint on macOS all have rules in this direction — verify they are **enabled and not in detect-only mode**.
4. **Block `osascript` invoking `security` CLI** via MDM configuration profile (requires explicit user consent, breaks ClickLock's credential-store extraction step).
5. **Review supply-chain trust:** for each direct dependency with > 100k weekly downloads, verify **multi-maintainer** status. Single-maintainer packages are the Shai-Hulud profile.
6. **Rotate any CI/CD secret that has touched a `postinstall` hook in the last 60 days.** Assume Shai-Hulud has touched it; rotate and re-issue.

---

## Why I chose this quote (selection rationale)

The previous Book Quote (28.08.2026, *The Linux Kernel Exploit Pattern* — also Al-Fardan-adjacent, lesson-031) was offensive-side: how to *find* a vulnerability by pattern-matching kernel subsystems. Today's quote is **defensive-side**: how to *hunt* threats that live below the signature line. The two quotes together give a full picture — the attacker is pattern-finding; the defender must pattern-hunt.

---

## Cross-refs (internal)

- **lesson-020-threat-hunting-book-review.md** — Al-Fardan, Ch. 1 (the source of this quote), Ch. 2 (hypothesis-driven hunt), Ch. 4 (threat intel feeds), Ch. 7 (time-series anomaly)
- **lesson-021-linux-forensics-book-review.md** — Linux / macOS forensic artefacts that would surface after a ClickLock incident (bash history, auditd, system log)
- **lesson-011-kev-triage-workflow.md** — how to triage the three classes above against KEV additions
- **lesson-031-hacking-linux-review.md** — paired offensive quote (28.08.2026); together they give the attacker-and-defender view
- **intel/techniques/cve-impact-rating.md** — asset-relevance scoring for M365 / npm-CI / macOS endpoints in your inventory
- **intel/techniques/asset-inventory-baseline.md** — baseline is the precondition for any behavioural hunt

## Sources (public)

- Al-Fardan, Nadhem. *Threat Hunting*, Manning, 2024 (Russian edition: Питер, 2026). ISBN 978-5-4461-4465-5. Chapter 1, *Introduction to Threat Hunting*, pp.3–24 (the source quote); Chapter 2, *Basic Threat Hunting Principles*, pp.25–42 (the hunting cycle); Chapter 4, *Threat Intelligence Feeds*, pp.92–122 (LOLBin argument, MITRE ATT&CK mapping).
- SecurityWeek — *ClickLock Stealer Bypasses macOS Security with Social Engineering & Process Killing*, 03.09.2026 — <https://www.securityweek.com/clicklock-stealer-bypasses-macOS-security-with-social-engineering-process-killing/>
- Petri IT Knowledgebase — *HOLLOWGRAPH: New Malware Uses Microsoft 365 Calendar for C2* (Cavern framework), 03.09.2026 — <https://petri.com/hollowgraph-malware-microsoft-365-graph-api/>
- Elastic Security Labs — Shai-Hulud mini-wave disclosure (keyv maintainer, 280 packages, 469 credential locations), 03–04.09.2026 — referenced via GitGuardian breach-explained feed — <https://blog.gitguardian.com/tag/breach-explained/>
- GitGuardian — *The npm Worm That Reached 1.3 Billion Downloads* (YouTube / blog companion) — <https://blog.gitguardian.com/>
- MITRE ATT&CK — T1059 (Command and Scripting Interpreter), T1071.001 (Application Layer Protocol — Web Protocols), T1195.002 (Supply Chain Compromise — Compromise Software Supply Chain), T1552.001 (Credentials in Files), T1003 (OS Credential Dumping) — <https://attack.mitre.org/>
- CISA KEV catalog (carry-over from previous Book Quote, 28.08.2026) — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

---

*Published by the daily-content pipeline. Sources: lesson-020 + public advisories. Pattern commentary, not exploit reproduction. No private data, no internal pentest artefacts, no real-customer infrastructure referenced.*