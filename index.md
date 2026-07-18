---
layout: home
title: 0xNull — sec-notes
---

# 0xNull — sec-notes

> Security research notes from the 0xNull team.  
> Pentesting · OSINT · Exploit dev · Threat hunting · CVE walkthroughs.  
> No fluff — only technical depth.

---

## Latest posts

{% for post in site.posts limit:10 %}
- **[{{ post.title }}]({{ post.url | relative_url }})** — {{ post.date | date: "%Y-%m-%d" }}
  {% if post.tags %} — tags: {{ post.tags | join: ', ' }}{% endif %}
{% endfor %}

---

## What we publish

- **CVE walkthroughs** — deep dives into specific vulnerabilities, with detection and mitigation steps
- **Penetration testing** — web, Active Directory, network, wireless, post-exploitation
- **OSINT** — username/email/domain reconnaissance, leak detection
- **Exploit development** — pwntools, heap exploitation, reverse engineering
- **Threat hunting** — MITRE ATT&CK, hunt hypotheses, anomaly detection

## Tools & Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=flat&logo=burpsuite&logoColor=white)
![pwntools](https://img.shields.io/badge/pwntools-red?style=flat)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat&logo=wireshark&logoColor=white)
![BloodHound](https://img.shields.io/badge/BloodHound-330000?style=flat)

## Find us

- 📢 Telegram: [@oxnull_security](https://t.me/oxnull_security) — daily drops
- 💻 CTF writeups: [ctf-writeups](https://github.com/0xnull-sec/ctf-writeups)
- 🛠 OSINT toolkit: [osint-toolkit](https://github.com/0xnull-sec/osint-toolkit)
- 🎯 Pentest cheatsheet: [pentest-cheatsheet](https://github.com/0xnull-sec/pentest-cheatsheet)

---

## About

All posts are written for educational and authorized security research purposes only. Do not use these techniques on systems you do not own or have explicit written permission to test.

**0xNull** — independent security researcher. Pentesting, bug bounty, CTF, blue team.  
Bio: "No fluff — only technical depth."
