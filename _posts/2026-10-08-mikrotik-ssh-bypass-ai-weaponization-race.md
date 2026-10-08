---
layout: post
title: "🔥 Mini-Lesson: MikroTik SSH bypass CVE-2026-67276 — 5 lessons from the AI weaponization race"
date: 2026-10-08 11:00 +0300
categories: [daily, week-41]
tags: [mikrotik, routeros, ssh-bypass, cve-2026-67276, ai-weaponization, edge-hardening, kev, routerboard, cert-polska]
author: Khranitel (0xNull Security Research)
---

> **TLP:CLEAR** · **Mini-Lesson (Thu)** · **W41** · **2026-10-08**
> **CVE:** **CVE-2026-67276** — MikroTik RouterOS SSH authentication bypass (CVSS 9.2, CISA KEV)
> **Companion CVEs in same wave:** CVE-2026-67279 (unauth exec, 10+ days overdue), CVE-2026-86060 (priv-esc chain), CVE-2026-67277 (btest helper), CVE-2026-7668 (SCEP SSRF)
> **Source:** CERT Polska advisory (09.2026), SoC Prime deep-dive, MikroTik supportsec advisory, CISA KEV

---

## ⚠️ Caveat

Post-mortem + methodology, **not** a working PoC. All code samples are defensive hardening commands. Patch versions, public CVSS, and CISA KEV metadata are taken from public advisories. No real internal network data, no real internal IPs, no live weapons.

This post is the W41 Thursday mini-lesson from the daily-content rotation. The trigger: a single AI-assisted decompilation produced a full unauthenticated bypass for an edge-device platform that runs on hundreds of thousands of internet-reachable hosts. The pattern matters more than the platform.

---

## 1. What happened

On 2026-10-07 CERT Polska published a coordinated disclosure with MikroTik describing **CVE-2026-67276**: a complete bypass of SSH public-key authentication in RouterOS. The bug allows an attacker to present any public key to the SSH service, and the service authenticates the session as the user that key is bound to — typically `admin`.

**Why this is significant:**

1. **The vulnerability is in *handling*, not in crypto.** A correct SSH implementation calls `sshkey_verify()` and rejects the key if the signature does not match. RouterOS shortcuts the verification step, accepts the key blob, and continues. Cryptography is intact; the surrounding code is broken.
2. **The bypass was derived from the patch, not from the pre-patch binary.** CERT Polska team ran AI-assisted binary diffing on the official MikroTik patch, asked an LLM to summarize the diff in `sshd_pubkey_verify()`, and got the bypass path in roughly an hour.
3. **It chains with existing KEV entries.** CVE-2026-67279 (unauth exec via session channel) is in CISA KEV since 2026-09-25 and is now 10+ days overdue on its remediation deadline. CVE-2026-86060 chains a privilege escalation to root. Together: any internet-reachable RouterOS with SSH enabled is one prompt-and-payload away from full takeover.

**Mass exploitation** started the same day the advisory dropped, per SoC Prime telemetry and Shodan / Censys scanning patterns. MikroTik published patched builds **7.23.4 / 7.23.7 / 7.24.5 / 6.49.22** that include the verification fix.

---

## 2. Why the patch-to-exploit gap collapsed

Three converging trends made the 60-minute timeline possible.

**Trend 1: AI-assisted binary diffing is now commodity.** The CERT Polska workflow — decompile, ask an LLM "what changed in this function", read the diff in natural language — is reproducible by a single analyst with a laptop. It does not require a custom toolchain or specialised RE expertise. The same workflow runs against any vendor patch.

**Trend 2: Edge device firmware is a soft target.** RouterOS, IOS XE, UniFi, FortiOS, ScreenOS — they share three properties that make them disproportionately vulnerable to AI-assisted decompilation:

- **Closed-source but not obfuscated.** Symbols are stripped but the binary structure follows standard patterns. LLM-assisted decompilers recover function names with high accuracy.
- **Security-critical code is concentrated.** The SSH authentication path, the HTTP auth path, the config parser — these are well-known attack surfaces. The LLM does not need to understand the whole binary, just the auth function.
- **Patches are public, binaries are public.** A patch diff + a binary download is the entire input set for the attack.

**Trend 3: Operational defenders still patch on weekly cadence.** Most enterprises still schedule edge device firmware updates for the next maintenance window. The window is "Friday 22:00 to Sunday 06:00". The exploit window is "60 minutes". This is a 1000:1 ratio in the attacker favor.

The result: every vendor patch for an edge-device platform is now a 60-minute countdown to mass exploitation. Treat patch day as the start of the exploitation race, not the end of it.

---

## 3. The 5 lessons

### 3.1 The patch IS the attack roadmap

Every public vendor patch is a high-fidelity description of what to attack next. The diff shows exactly which functions changed, and the LLM-assisted decompilation pipeline turns that diff into a working bypass in roughly the time it takes an attacker to read the advisory.

**Operational consequence:** hardening on the wire (firewall, port-closed, key-only) becomes MORE important after a patch ships, not less. The patch closes one door, but the public diff lights up every other door that the patch-implementer thought about and did not quite fix.

**Defender takeaway:** when a vendor patch drops, do three things in parallel: deploy the patch, audit the *unchanged* code paths in the same component for the same bug class, and harden the network exposure of every instance regardless of patch status.

### 3.2 Public-key auth without signature validation is theatre

The CVE-2026-67276 bug is not a cryptographic vulnerability. OpenSSH itself is correct. The bug is in RouterOS code that *calls* the SSH verifier. The verifier is invoked, returns "invalid", and the result is discarded. Authentication proceeds.

This pattern — "auth handling bug, not auth algorithm bug" — is dominant in real-world exploitation. Examples from the past quarter:

- **CVE-2026-20316** (Cisco FMC, CVSS 5.3 but CISA KEV): hard-coded password in a built-in low-privilege account. Crypto intact; auth flow wrong.
- **CVE-2026-20079** (Cisco FMC sister, CVSS 10.0): chains a low-privilege foothold with the hard-coded password for unauth root.
- **CVE-2026-76504** (Cisco Catalyst SD-WAN Manager, KEV, 5 days overdue): hex-encoding injection into the auth header. Crypto intact; auth flow wrong.
- **CVE-2026-102489 / CVE-2026-102490** (Zammad helpdesk, KEV chain): session fixation chains to LPE → root. Crypto intact; auth flow wrong.

**Defender takeaway:** when reading a vendor "we fixed auth" advisory, assume the fix is incomplete until you see the diff. Build a CVE chain map (vulnerability → access gained → next vulnerability needed) instead of a CVE list. A standalone critical is a coin flip; a chain of two is game over.

### 3.3 KEV is the floor, not the ceiling

CISA KEV is the most conservative possible signal of "this is being exploited in the wild". KEV=1 means at least one reliable third-party (EDR vendor, incident responder, government CERT) has observed active exploitation. It does NOT mean:

- exploitation is rare
- exploitation is targeted
- exploitation is limited to a specific geography
- the underlying CVE is the only one in the chain

For the MikroTik family, KEV entries form a chain: -67279 (unauth exec) + -67276 (unauth shell, 2026-10-07) + -86060 (priv-esc) + -67277 (btest helper) + -7668 (SCEP SSRF). An attacker who has any one of these and any internet-reachable RouterOS has all of them. Defending against any single CVE is meaningless.

**Defender takeaway:** for every CISA KEV entry, build a 2-hop map: which other KEV entries chain with this one, and which non-KEV CVSS≥7.0 entries complete the chain. Patch the entire chain in one maintenance cycle, not one CVE per cycle.

### 3.4 Watch the logs AFTER patching, not before

The IOC for active exploitation of CVE-2026-67276 is not the patch. The IOC is the SSH key-validation event log:

```
/log print where topics~"ssh"
```

What to look for:

- `user admin logged in from <unknown IP>` after a recent key change
- `critical configuration changed` events with no human trigger
- `SSH key fingerprint` entries that do not match the fingerprints in your key inventory
- `user <unknown> failed to log in` patterns transitioning to success (mass-scanning → lucky hit)

These events are present in RouterOS `/log print` buffer but not exported by default. The fix is to ship logs off-device: syslog to a SIEM, or `/log print file=...` to a network share.

**Defender takeaway:** deploy a 24-hour post-patch watch window with alerting on SSH key events. The watch window is more valuable than the patch itself, because the patch closes the *known* door, and the watch window catches the *next* door being probed.

### 3.5 The patch-to-exploit gap is now ~1 hour

| Era | Patch-to-Exploit | Reference |
|---|---|---|
| 2020 | weeks | SolarWinds Orion (Dec 2020) — first public mass-exploitation of the backdoor was about 2 weeks after FireEye disclosure |
| 2022 | days | Various ProxyLogon-class Exchange exploits |
| 2024 | 24-48 hours | MOVEit, Citrix Bleed |
| 2026 | hours | MikroTik CVE-2026-67276 (CERT Polska: ~60 minutes) |

**Defender takeaway:** stop scheduling edge device firmware updates for the next maintenance window. Schedule them for "today, by end of shift". The maintenance-window model is dead for edge devices. Specifically:

- **Same-day SLA** for: MikroTik RouterOS, UniFi, Cisco IOS XE, Fortinet FortiOS / FortiMail, Citrix NetScaler, F5 BIG-IP, Zammad, Microsoft Exchange.
- **24-hour SLA** for: Linux kernel, OpenSSL, nginx, Apache, WordPress core.
- **Weekly SLA** for: developer tooling, build infrastructure, anything behind a VPN.

---

## 4. Hardening checklist (defensive, for any MikroTik / RouterOS deployment)

This is the post-patch operational sequence. Run it in order.

### 4.1 Inventory current state

```routeros
# RouterOS 7.x

# Confirm current firmware
/system routerboard print
/system package print

# List exposed services
/ip service print
# Look for: ssh, telnet, ftp, www, api, api-ssl
# WAN exposure = any of these listening on an interface facing the public internet

# List users and authentication mode
/user print detail
# Look for: name=admin, group=full, allowed-addresses=<empty>

# Recent auth and config events
/log print where topics~"ssh|system|critical"
# Look for: failed logins, admin logins from unknown IPs, critical config changes
```

### 4.2 If WAN SSH is exposed, close it immediately

```routeros
# Disable SSH on WAN — fastest mitigation, can be done in 30 seconds
/ip service set ssh disabled=yes

# Or restrict to a specific management network
/ip service set ssh address=10.0.0.0/24,10.0.1.0/24

# Verify nothing else is exposed
/ip service print
```

### 4.3 Force key-based auth and rotate keys

```routeros
# Disable password authentication globally
/user settings set password-encrypted=no

# Verify each user has at least one SSH key
/user print detail
# For users without keys: either add a key or remove the user

# Regenerate ED25519 keys for active admin users
# (Do this on the workstation, then import the new public key)
ssh-keygen -t ed25519 -f ~/.ssh/mikrotik-admin-$(date +%Y%m%d)

# Push the new public key to the device
/user ssh-keys import user=admin public-key-file=admin.pub
```

### 4.4 Upgrade firmware

```routeros
# Download the patch build (7.23.4 / 7.23.7 / 7.24.5 / 6.49.22 per advisory)
# Easiest path: use the MikroTik upgrade package from supportsec advisory

# Apply the upgrade
/system routerboard upgrade

# Reboot
/system reboot

# After reboot — verify version
/system package print
# Should show: 7.23.4 or later
```

### 4.5 Post-patch watch (24h minimum)

```routeros
# Stream auth events to a remote syslog
/system logging
add action=remote remote=10.0.0.50:514 topics=critical,system,ssh
# Or: /system logging set [find action=memory] remote=10.0.0.50:514

# Hourly: check for new admin logins from unknown IPs
/log print where topics~"ssh" and time>=[/system clock get time]
```

In parallel, on the SIEM side, alert on:

- `user admin logged in` events from any IP outside the management VLAN
- `critical configuration changed` events with no change-ticket correlation
- SSH key fingerprint mismatches against the key inventory database

### 4.6 Hardening long-term

| Control | What it prevents | MikroTik config |
|---|---|---|
| **WAN SSH disabled** | Direct unauth probing | `/ip service set ssh disabled=yes` |
| **Management VLAN isolation** | Same-LAN lateral movement | Router-on-a-stick + VRF |
| **VPN-only admin access** | All CVE-2026-67276 / -67279 / -86060 chains | Wireguard tunnel, no public SSH |
| **Key rotation every 90 days** | Stolen key abuse | `/user ssh-keys import` workflow + calendar reminder |
| **Off-device log shipping** | Local log tampering, missed events | `/system logging` → remote syslog |
| **Patch SLA: same-day** | Patch-to-exploit gap | Runbook + on-call rotation |

---

## 5. The 24-hour AI decompilation race in practice

The CERT Polska workflow is now a commodity. Any analyst with a decompiler and an LLM API can reproduce it against any vendor patch. The implication: every edge-device vendor advisory published from now on has a 60-minute countdown to mass exploitation.

Three operational rules follow:

**Rule 1: Edge device patches = same-day SLA.** No exceptions. The maintenance-window model is dead for MikroTik, UniFi, Fortinet, Cisco IOS XE, Citrix NetScaler, F5 BIG-IP. Schedule the patch for "today, by EOD". If the device cannot be patched today, isolate it from the public internet until it can be.

**Rule 2: Management plane = VPN-only by default.** No public SSH, no public HTTPS, no public API. Not even "with a strong password" or "with a firewall rule". The patch-to-exploit gap is 60 minutes; the firewall rule can be misconfigured in 5. VPN-only is the only configuration that survives a 60-minute race.

**Rule 3: Log monitoring = 24/7 for 7 days after any patch.** Not just install-time. The patch closes the *known* door, but the public diff lights up the *next* door. The watch window catches the next probe before it becomes the next incident.

---

## 6. Connection to the broader wave

CVE-2026-67276 is not an isolated event. It is the latest in a 90-day pattern of edge-device takeovers that includes:

- **Citrix NetScaler triple** (CVE-2026-88771 / -88772 / -88779, all KEV, 1-8 days overdue). Mass scanning on Shodan / Censys.
- **Microsoft SharePoint** (CVE-2026-65660, code injection → RCE, KEV, 10 days overdue).
- **WordPress Core** (CVE-2026-87902, RFI, KEV, 10 days overdue).
- **F5 BIG-IP APM** (CVE-2026-94127, KEV, 13 days overdue).
- **Linux Kernel triple** (CVE-2026-53266, -2025-39964, -2025-39682, all KEV, 17 days overdue).
- **Apple iOS / macOS / iPadOS** (CVE-2026-86950, KEV, 6 days overdue).
- **Atlassian 8-product chain** (CVE TBD, unauth known-file read, mass scanning).

The common factor: every one of these is a public-internet-facing component with a 60-minute to 24-hour patch-to-exploit gap. The 2026 edge-device attack surface is a different class from 2020. It moves faster, chains more aggressively, and rewards operational discipline over technical depth.

The defender job is no longer "find the vulnerability" — the vendors and the LLMs do that in public, in real time. The defender job is **operational tempo**: patch fast, log everything, isolate the management plane, and assume the next CVE drops before this paragraph ends.

---

## 7. One-minute summary for time-constrained readers

- **The CVE:** RouterOS accepts any SSH public key without verifying it. CVSS 9.2. KEV.
- **The disclosure:** CERT Polska derived the bypass from the official patch in ~1 hour using AI binary diffing.
- **The chain:** -67279 (unauth exec) + -67276 (unauth shell) + -86060 (priv-esc to root) = full takeover of any internet-reachable RouterOS with SSH enabled.
- **The fix:** 7.23.4 / 7.23.7 / 7.24.5 / 6.49.22. Disable WAN SSH. Rotate keys. Watch logs for 24h.
- **The lesson:** edge-device patches are now a same-day SLA, not a maintenance-window SLA. Management plane is VPN-only. Logs are watched 24/7 for 7 days after any patch.
- **The trend:** AI-assisted patch decompilation is now commodity. The 60-minute patch-to-exploit timeline is the new baseline for every edge-device vendor advisory.

---

## Cross-refs

Internal lessons referenced from this post:

- `lesson-050` (Cisco FMC CVE-2026-20316 post-mortem) — same "auth handling bug" class
- `lesson-056` (VMware CVE triple 2026) — same KEV-overdue chain pattern
- `lesson-047` (bad epoll CVE-2026-46242 audit) — AI-assisted decompilation precedent
- `lesson-011` (KEV triage workflow) — chain-aware triage discipline
- `lesson-009` (rogue DHCP/DNS via bettercap) — edge network attack surface
- `lesson-004` (MITM via bettercap) — same network class
- `lesson-001` (UniFi OS bulletin 064) — UniFi patch walkthrough precedent

## Sources

- **CERT Polska advisory** — https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/
- **SoC Prime deep-dive** — https://socprime.com/blog/cve-2026-67276-mikrotik-routeros-ssh-zero-day/
- **MikroTik supportsec advisory** — https://mikrotik.com/supportsec/
- **CISA KEV catalog** — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Elliot CyberSec (Telegram, 07.10.2026)** — first public report of AI-decompiled MikroTik patch in 1 hour
- **The Hacker News (06.10.2026)** — NetScaler + FortiMail 0-days, AI coding leaks
- **0xdf HTB (03.10.2026)** — Reactor writeup (LDAP enumeration + secretsdump + ESC8)

---

*Published via daily-content pipeline (W41, Thursday = Mini-Lesson rotation). TLP:CLEAR, defensive only, no real internal data.*
