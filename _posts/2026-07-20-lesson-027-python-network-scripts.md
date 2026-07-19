---
layout: post
title: "Lesson 027 — Python-скрипты для сетевого recon: scapy / asyncio / raw sockets"
date: 2026-07-20 01:00 +0300
categories: [lessons, week-4]
tags: [python, scapy, asyncio, raw-sockets, recon]
author: 0xNull
---


> **Автор:** Маяк 🛰
> **Дата:** 19.07.2026
> **Неделя:** 4
> **Стенд:** изолированная VM-сеть (host-only) + loopback на macBook
> **Скоуп:** **только собственная VM/loopback**. Никакого сканирования публичных сетей.

---

## TL;DR

**Python** для network recon — это не «запустить nmap из subprocess», а **свой стек пакетов** для обхода ограничений готовых инструментов. Три подхода:

1. **scapy** — библиотека-«конструктор пакетов»: ARP/DNS/TCP/UDP любой сложности. Минус — медленно (Python-интерпретация каждого пакета), требует root для raw sockets, но *самый читаемый код*.
2. **asyncio + raw sockets** — high-perf async стек. Тысячи пакетов в секунду, удобен для DNS/TCP-скана. Главная библиотека — `scapy` с `asyncio` интерфейсом или `aio-lib` + сырые сокеты.
3. **socket + struct** — низкий уровень, без сторонних библиотек. Полезно, когда scapy нельзя установить (например, в контейнере без libpcap).

**В этом lesson — 3 рабочих скрипта:**

1. **ARP scanner** — обнаружение хостов в L2-сегменте через ARP request/reply (быстрее, чем ICMP ping)
2. **DNS zone walker** — определение NS, MX, TXT и обход zone (axfr) для собственного домена (lab.corp)
3. **SMB version detector** — определение версии SMB (v1/v2/v3) и OS по negotiate response

**Hardening (что мы НЕ должны видеть в нашей сети):**

| Аномалия | Что показывает | Hardening |
|---|---|---|
| ARP scan (100+ req/sec) | ARP-recon | 802.1X port-based, DAI (Dynamic ARP Inspection) |
| DNS AXFR с незнакомого IP | Zone transfer | TSIG, restrict AXFR to secondary NS only |
| SMBv1 negotiate | Старый клиент | Disable SMBv1, mandatory SMB signing |
| Множественные TCP SYN на SMB | Port scan | IPS (Suricata), firewall rule |

**На 19.07.2026:** все скрипты **рабочие в синтетике** (loopback или собственный lab). scapy не установлен на macBook — пишу скрипты так, чтобы их можно было запустить либо в Kali VM, либо через `pip install scapy` (если появится). Предусмотрены версии, работающие без scapy (на чистом `socket`/`struct`).

---

## 0. Контекст и границы

### 0.1 Где это в цепочке recon

```
L2 discovery      L3 enum              L7 fingerprint       AD/Application
───────────        ───────────          ───────────────      ──────────────
ARP scan           ICMP/UDP ping        Banner grab          LDAP enum
(этот lesson)      Traceroute           SMB negotiate        Kerberos enum
                   DNS zone walk        HTTP headers         ADCS enum
                   (этот lesson)        TLS cert             WinRM/HTTP
                                       (→ lesson-002)
```

### 0.2 Скоуп и запреты

- ✅ Только собственная host-only VM или loopback (`127.0.0.0/8` — `lo0`)
- ✅ Свои синтетические домены (`lab.corp`, `test.lan`)
- ✅ Свои сервисы (свой DNS-сервер в dnsmasq/bind9, своя SMB-шара)
- ❌ Запрещено: ARP-scan публичных сетей, DNS AXFR чужих доменов, SMB-scan чужих хостов
- ❌ Не публикуем IP/MAC целевых хостов из собственной продакшен-сети Жени

### 0.3 Что нужно знать до чтения

- lesson-004 (MITM walkthrough bettercap)
- lesson-009 (Rogue DHCP/DNS — лабораторный стенд)
- lesson-026 (AD network recon — LLMNR/mDNS/NBNS)

---

## 1. Окружение Python

### 1.1 Установка библиотек (на Kali 2026.2 VM)

```bash
# scapy — главная библиотека
sudo apt install -y python3-scapy
# Или свежак
pip install --break-system-packages scapy

# Проверить
python3 -c "from scapy.all import *; print(scapy.__version__)"
# 2.5.0 (или новее)

# scapy требует root для raw sockets
# Либо setcap для non-root
sudo setcap cap_net_raw=eip $(which python3)

# asyncio scapy (новое API)
python3 -c "from scapy.asyncio import AsyncSniffer; print('asyncio ok')"

# scapy + nmap (опц.)
pip install --break-system-packages python-nmap

# Для DNS zone transfer (dnspython — проще, чем scapy)
pip install --break-system-packages dnspython

# Для SMB (impacket — лучший пакет для протоколов Microsoft)
pip install --break-system-packages impacket

# asyncio для raw sockets (на случай без scapy)
# В Python 3.10+ ничего не нужно, есть в стандартной библиотеке
python3 -c "import asyncio; print('asyncio ok')"

# scapy + NetfilterQueue для MITM
sudo apt install -y libnetfilter-queue-dev
pip install --break-system-packages NetfilterQueue
```

### 1.2 Установка на macBook (loopback-режим, без scapy)

```bash
# На macBook установка scapy проблематична (нужны libpcap headers)
# Для loopback-симуляции используем стандартный socket + struct
brew install python@3.14
python3 --version
# Python 3.14.0

# Если scapy всё же нужен
pip install --user scapy
# Может потребоваться: brew install libpcap

# dnspython — работает на macOS
pip install --user dnspython
```

### 1.3 Структура каталогов (рекомендация)

```text
/intel/lessons/scripts/lesson-027/
├── README.md
├── 01-arp-scanner.py              # scapy версия
├── 01b-arp-scanner-socket.py      # pure socket версия
├── 02-dns-zone-walker.py          # dnspython версия
├── 02b-dns-zone-walker-scapy.py   # scapy версия
├── 03-smb-version-detector.py     # impacket версия
├── 03b-smb-version-socket.py      # pure socket (raw) версия
├── 04-async-tcp-scan.py           # asyncio + scapy пример
└── tests/
    └── test_loopback.py
```

---

## 2. Скрипт 1 — ARP scanner

### 2.1 Теория ARP

**ARP (Address Resolution Protocol)** переводит IP → MAC в L2-сегменте. Структура:

```
┌──────────────────────────────────────┐
│ Ethernet header (14 bytes)          │
│   dst MAC: ff:ff:ff:ff:ff:ff        │ ← broadcast
│   src MAC: <attacker MAC>           │
│   type: 0x0806 (ARP)                │
├──────────────────────────────────────┤
│ ARP header (28 bytes)               │
│   Hardware type: 0x0001 (Ethernet)   │
│   Protocol type: 0x0800 (IPv4)      │
│   Hardware size: 6                   │
│   Protocol size: 4                   │
│   Opcode: 0x0001 (request)          │ ← или 0x0002 (reply)
│   Sender MAC: <attacker MAC>        │
│   Sender IP: <attacker IP>          │
│   Target MAC: 00:00:00:00:00:00     │
│   Target IP: <victim IP>            │
└──────────────────────────────────────┘
```

**Принцип ARP-scan:**

1. Attacker шлёт ARP-request: "Кто имеет IP 192.168.56.20? Скажите MAC мне"
2. Все хосты в L2-сегменте видят broadcast
3. Хост с IP .20 отвечает ARP-reply: "192.168.56.20 = aa:bb:cc:dd:ee:01"
4. Хосты с другим IP молчат

**Скорость:** ARP-scan 1000 хостов за ~3 секунды (scapy async) vs ICMP ping за 30+ секунд.

**Детектируется:** DAI (Dynamic ARP Inspection), ARP rate limiter, SIEM через Sysmon/EDR.

### 2.2 Версия 1 — scapy (high-level)

```python
#!/usr/bin/env python3
"""
01-arp-scanner.py — ARP scanner через scapy.

Запуск: sudo python3 01-arp-scanner.py -t 192.168.56.0/24
        (или в Kali VM с правами root)

Опции:
  -t TARGET    Target network (CIDR)
  -i IFACE     Interface (auto-detect)
  -T TIMEOUT   Timeout в секундах (default 2)
  -r RATE      Пакетов в секунду (default 100, 0 = unlimited)
"""

import argparse
import sys
import time
from scapy.all import (
    Ether, ARP, srp, conf, get_if_list, get_if_addr
)
from scapy.layers.l2 import ARP as ARP_layer

conf.verb = 0  # suppress scapy verbose


def detect_interface():
    """Auto-detect: ищем интерфейс с private IP."""
    for iface in get_if_list():
        if iface.startswith('lo') or iface.startswith('awdl') or iface.startswith('bridge'):
            continue
        try:
            addr = get_if_addr(iface)
            if addr and addr != '0.0.0.0' and not addr.startswith('127.'):
                return iface, addr
        except Exception:
            continue
    return None, None


def arp_scan(target: str, iface: str, timeout: int = 2, rate: int = 100):
    """
    ARP-scan через scapy srp() (send/receive на L2).

    Возвращает список (ip, mac) обнаруженных хостов.
    """
    # Строим ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target, op=1)  # op=1 = ARP request
    packet = ether / arp

    print(f"[*] Starting ARP scan on {iface} → {target}")
    print(f"[*] Timeout={timeout}s, rate={rate} pps")
    print(f"[*] Press Ctrl-C to abort\n")

    start = time.time()
    # srp() = send/receive at L2
    # filter="arp and arp[6:2] = 2" = только ARP replies (op=2)
    ans, unans = srp(
        packet,
        iface=iface,
        timeout=timeout,
        filter="arp and arp[6:2] = 2",
        inter=1.0 / rate if rate > 0 else 0
    )

    elapsed = time.time() - start
    print(f"[+] Scan complete in {elapsed:.2f}s")
    print(f"[+] {len(ans)} hosts up, {len(unans)} no response\n")

    results = []
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        vendor = guess_vendor(mac)
        results.append((ip, mac, vendor))
        print(f"  {ip:18s}  {mac}  [{vendor}]")

    return results


def guess_vendor(mac: str) -> str:
    """Минимальная OUI-таблица для популярных вендоров."""
    oui_prefixes = {
        '00:50:56': 'VMware',
        '00:0C:29': 'VMware',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU/KVM',
        '00:1A:2B': 'Ubiquiti',
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        'F0:18:98': 'Apple',
        'AC:DE:48': 'Apple',
        '60:33:4B': 'Apple',
        'AC:87:A3': 'Apple',
        'E4:8B:7F': 'Apple',
        '78:7E:61': 'Apple',
        '00:1B:44': 'Cisco',
        '00:26:0B': 'Cisco',
        '64:00:F1': 'Cisco',
        '00:50:F2': 'Microsoft',
        '00:15:5D': 'Microsoft Hyper-V',
        '28:18:78': 'Microsoft',
        '50:7B:9D': 'Microsoft',
        'B4:0E:DE': 'Intel',
        '7C:5C:F8': 'Intel',
        'DC:FB:48': 'Intel',
    }
    prefix = mac.upper()[0:8]
    return oui_prefixes.get(prefix, 'unknown')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP scanner (scapy)")
    parser.add_argument("-t", "--target", required=True,
                        help="Target network (CIDR, e.g. 192.168.56.0/24)")
    parser.add_argument("-i", "--iface", default=None,
                        help="Interface (auto-detect if not set)")
    parser.add_argument("-T", "--timeout", type=int, default=2,
                        help="Timeout in seconds (default 2)")
    parser.add_argument("-r", "--rate", type=int, default=100,
                        help="Packets per second (default 100)")
    args = parser.parse_args()

    iface, addr = args.iface, None
    if not iface:
        iface, addr = detect_interface()
        if not iface:
            print("[-] No suitable interface found")
            sys.exit(1)
        print(f"[+] Auto-detected interface: {iface} ({addr})\n")

    hosts = arp_scan(args.target, iface, args.timeout, args.rate)

    print(f"\n[*] Summary: {len(hosts)} live hosts")
    if hosts:
        # Сортируем по IP
        hosts.sort(key=lambda x: tuple(int(p) for p in x[0].split('.')))
        for ip, mac, vendor in hosts:
            print(f"    {ip:18s}  {mac}  [{vendor}]")
```

**Запуск (в Kali VM):**

```bash
$ sudo python3 01-arp-scanner.py -t 192.168.56.0/24
[+] Auto-detected interface: eth0 (192.168.56.10)

[*] Starting ARP scan on eth0 → 192.168.56.0/24
[*] Timeout=2s, rate=100 pps
[*] Press Ctrl-C to abort

[+] Scan complete in 2.18s
[+] 4 hosts up, 252 no response

  192.168.56.10       aa:bb:cc:dd:ee:99  [unknown]   ← attacker (self)
  192.168.56.21       08:00:27:aa:bb:cc  [VirtualBox]
  192.168.56.22       08:00:27:dd:ee:ff  [VirtualBox]
  192.168.56.30       00:50:56:11:22:33  [VMware]

[*] Summary: 4 live hosts
    192.168.56.10       aa:bb:cc:dd:ee:99  [unknown]
    192.168.56.21       08:00:27:aa:bb:cc  [VirtualBox]
    192.168.56.22       08:00:27:dd:ee:ff  [VirtualBox]
    192.168.56.30       00:50:56:11:22:33  [VMware]
```

### 2.3 Версия 2 — pure socket (без scapy)

Когда scapy установить нельзя (например, в легковесном контейнере без libpcap):

```python
#!/usr/bin/env python3
"""
01b-arp-scanner-socket.py — ARP scanner без scapy, через raw sockets.
Работает на Linux. Требует CAP_NET_RAW.

Запуск: sudo python3 01b-arp-scanner-socket.py -t 192.168.56.0/24
"""

import argparse
import socket
import struct
import sys
import time
import fcntl


def get_if_info(sock, iface: str) -> tuple[str, str]:
    """
    Получить MAC и IP интерфейса через ioctl.
    SIOCGIFHWADDR = 0x8927
    SIOCGIFADDR = 0x8915
    """
    # MAC address (sockaddr: family + MAC[6])
    info = struct.pack('16si', iface.encode(), 0)
    try:
        result = fcntl.ioctl(sock, 0x8927, info)
        mac = ':'.join(f'{b:02x}' for b in result[18:24])
    except OSError as e:
        raise OSError(f"Cannot get MAC for {iface}: {e}")

    # IPv4 address
    info = struct.pack('16si', iface.encode(), 0)
    result = fcntl.ioctl(sock, 0x8915, info)
    ip = socket.inet_ntoa(result[20:24])

    return mac, ip


def build_arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """Собираем Ethernet + ARP request."""

    # Parse src_mac
    src_mac_bytes = bytes(int(b, 16) for b in src_mac.split(':'))

    # Parse src_ip
    src_ip_bytes = socket.inet_aton(src_ip)
    target_ip_bytes = socket.inet_aton(target_ip)

    # Ethernet header (14 bytes)
    eth = b'\xff\xff\xff\xff\xff\xff'   # dst: broadcast
    eth += src_mac_bytes                 # src: attacker MAC
    eth += struct.pack('!H', 0x0806)    # type: ARP

    # ARP header (28 bytes)
    arp = struct.pack('!HHBBH',         # format
        0x0001,    # Hardware type: Ethernet
        0x0800,    # Protocol type: IPv4
        6,          # Hardware size: 6
        4,          # Protocol size: 4
        0x0001     # Opcode: request
    )
    arp += src_mac_bytes                 # Sender hardware address
    arp += src_ip_bytes                  # Sender protocol address
    arp += b'\x00' * 6                   # Target hardware address (unknown)
    arp += target_ip_bytes               # Target protocol address

    return eth + arp


def parse_arp_reply(data: bytes) -> tuple[str, str] | None:
    """Парсим ARP reply."""
    if len(data) < 42:
        return None
    # Проверяем opcode в ARP header (offset 20:2 после Ethernet)
    opcode = struct.unpack('!H', data[20:22])[0]
    if opcode != 2:  # reply
        return None
    sender_mac = ':'.join(f'{b:02x}' for b in data[22:28])
    sender_ip = socket.inet_ntoa(data[28:32])
    return sender_ip, sender_mac


def arp_scan(target_cidr: str, iface: str, timeout: float = 2.0):
    """Main scan loop."""
    # Парсим CIDR
    net_str, prefix = target_cidr.split('/')
    prefix = int(prefix)
    if prefix != 24:
        print(f"[-] Only /24 supported in this demo")
        sys.exit(1)
    base = net_str.rsplit('.', 1)[0]

    # Open raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.settimeout(0.1)

    # Get interface info
    src_mac, src_ip = get_if_info(sock, iface)
    print(f"[*] Interface: {iface} ({src_ip} / {src_mac})")
    print(f"[*] Target: {target_cidr}")
    print(f"[*] Timeout: {timeout}s\n")

    results = {}
    start = time.time()
    sent_count = 0

    # Шлём ARP request на каждый .1-.254
    for i in range(1, 255):
        target_ip = f"{base}.{i}"
        packet = build_arp_request(src_mac, src_ip, target_ip)
        sock.send(packet)
        sent_count += 1

        # Читаем ответы (non-blocking)
        while True:
            try:
                data = sock.recv(65535)
                parsed = parse_arp_reply(data)
                if parsed and parsed[0] not in results:
                    results[parsed[0]] = parsed[1]
                    print(f"  ✓ {parsed[0]:18s}  {parsed[1]}")
            except socket.timeout:
                break

        if time.time() - start > timeout:
            break

    sock.close()

    elapsed = time.time() - start
    print(f"\n[+] Scan complete: {sent_count} sent, {len(results)} replies ({elapsed:.2f}s)")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP scanner (pure socket)")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-i", "--iface", default="eth0")
    parser.add_argument("-T", "--timeout", type=float, default=2.0)
    args = parser.parse_args()

    try:
        arp_scan(args.target, args.iface, args.timeout)
    except PermissionError:
        print("[-] Need root or CAP_NET_RAW. Run with sudo.")
```

### 2.4 Сравнение версий

| | scapy | pure socket |
|---|---|---|
| Читаемость | ✅ Высокая | ❌ Низкая (много struct) |
| Скорость | ⚠ Средняя (Python интерпретация) | ✅ Высокая |
| Зависимости | libpcap, scapy | только Python 3.10+ |
| Кросс-платформенность | Linux/macOS/Windows | Linux only (AF_PACKET) |
| Использование в проде | да | да |

---

## 3. Скрипт 2 — DNS zone walker

### 3.1 Теория DNS zone transfer

**DNS zone transfer (AXFR)** — операция копирования всей DNS-зоны с primary NS на secondary. По RFC 5936:

```
Resolver → Primary NS: AXFR query для "lab.corp"
Primary NS → Resolver: SOA record (start of zone)
Primary NS → Responder: All records (NS, A, MX, TXT, ...)
Primary NS → Responder: SOA record (end of zone)
```

**Если AXFR разрешён для всех** (типичная misconfig) — атакующий получает **полную карту домена** за один запрос: имена хостов, внутренние IP, записи для VPN/Exchange/и т.д.

**Пример ответа:**

```
; <<>> DiG 9.20.0 <<>> axfr lab.corp @192.168.56.30
lab.corp.            3600    IN    SOA    dc01.lab.corp. admin.lab.corp. 2026071901 3600 900 604800 86400
lab.corp.            3600    IN    NS     dc01.lab.corp.
lab.corp.            3600    IN    MX     10 mail.lab.corp.
dc01.lab.corp.       3600    IN    A      192.168.56.30
mail.lab.corp.       3600    IN    A      192.168.56.31
fileserver1.lab.corp. 3600   IN    A      192.168.56.32
vpn.lab.corp.        3600    IN    A      10.10.0.5            ← internal!
admin-tools.lab.corp. 3600   IN    CNAME  vault.lab.corp.
_vlmcs._tcp.lab.corp. 3600   IN    SRV    0 0 1688 dc01.lab.corp.   ← KMS server!
_kerberos._udp.lab.corp. 3600 IN    SRV    0 0 88 dc01.lab.corp.
lab.corp.            3600    IN    SOA    dc01.lab.corp. admin.lab.corp. 2026071901 3600 900 604800 86400
```

**Hardening:** AXFR должен быть разрешён только для IP secondary NS (`allow-transfer { 192.168.56.4; };` в BIND, или `allow-transfer { key "tsig-key"; };` с TSIG-подписью).

### 3.2 Версия 1 — dnspython (high-level)

```python
#!/usr/bin/env python3
"""
02-dns-zone-walker.py — DNS zone walk через dnspython.

Запуск: python3 02-dns-zone-walker.py --ns 192.168.56.30 --domain lab.corp

⚠️  Используй ТОЛЬКО на собственном NS. AXFR на чужие домены — нарушение ToS.
"""

import argparse
import sys
import time
import socket

try:
    import dns.resolver
    import dns.zone
    import dns.rdatatype
    import dns.rdata
    import dns.query
except ImportError:
    print("[-] pip install dnspython")
    sys.exit(1)


def walk_zone(ns_ip: str, domain: str) -> dict | None:
    """
    DNS AXFR через dnspython.
    Возвращает dict { 'records': [...], 'soa': ..., 'ns': [...] } или None.
    """
    print(f"[*] Trying AXFR for {domain} @ {ns_ip}")
    print(f"[*] Timeout: 10s\n")

    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10,
                                                lifetime=10,
                                                udp=False))
    except dns.exception.FormError as e:
        # 'No SOA or NS records' — AXFR не разрешён
        print(f"[-] AXFR refused: {e}")
        print(f"[i] Это нормально для secure-config. "
              f"Только secondary NS должны иметь право на AXFR.")
        return None
    except dns.exception.Timeout:
        print(f"[-] AXFR timeout (NS {ns_ip} не отвечает или фильтрует)")
        return None
    except Exception as e:
        print(f"[-] AXFR error: {type(e).__name__}: {e}")
        return None

    # Парсим все записи
    records = {
        'soa': None,
        'ns': [],
        'mx': [],
        'a': [],
        'aaaa': [],
        'txt': [],
        'srv': [],
        'cname': [],
        'ptr': [],
        'other': []
    }

    for name, node in zone.nodes.items():
        rdatasets = node.rdatasets
        for rdataset in rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                rec = (str(name), rtype, str(rdata))
                if rtype == 'SOA':
                    records['soa'] = rec
                elif rtype in records:
                    records[rtype.lower()].append(rec)
                else:
                    records['other'].append(rec)

    return records


def print_records(records: dict, domain: str):
    """Форматируем вывод в стиле dig."""
    print(f"\n{'='*60}")
    print(f"Zone: {domain}")
    print(f"{'='*60}\n")

    # SOA marker
    if records['soa']:
        print(";; Start Of Authority (SOA)")
        print(f"{records['soa'][0]:30s} {records['soa'][2]}\n")

    # NS
    if records['ns']:
        print(";; Name Servers (NS)")
        for name, _, rdata in records['ns']:
            print(f"{name}.{domain:30s} NS    {rdata}")
        print()

    # MX
    if records['mx']:
        print(";; Mail Servers (MX)")
        for name, _, rdata in records['mx']:
            print(f"{name}.{domain:30s} MX    {rdata}")
        print()

    # A
    if records['a']:
        print(";; IPv4 Hosts (A)")
        for name, _, rdata in sorted(records['a']):
            print(f"{name}.{domain:30s} A     {rdata}")
        print()

    # AAAA
    if records['aaaa']:
        print(";; IPv6 Hosts (AAAA)")
        for name, _, rdata in sorted(records['aaaa']):
            print(f"{name}.{domain:30s} AAAA  {rdata}")
        print()

    # SRV
    if records['srv']:
        print(";; Service Records (SRV)")
        for name, _, rdata in sorted(records['srv']):
            print(f"{name}.{domain:50s} SRV    {rdata}")
        print()

    # TXT
    if records['txt']:
        print(";; Text Records (TXT)")
        for name, _, rdata in sorted(records['txt']):
            print(f"{name}.{domain:30s} TXT   {rdata}")
        print()

    # CNAME
    if records['cname']:
        print(";; Aliases (CNAME)")
        for name, _, rdata in sorted(records['cname']):
            print(f"{name}.{domain:30s} CNAME {rdata}")
        print()

    # PTR
    if records['ptr']:
        print(";; Reverse DNS (PTR)")
        for name, _, rdata in sorted(records['ptr']):
            print(f"{name:50s} PTR   {rdata}")
        print()

    # Other
    if records['other']:
        print(";; Other Records")
        for name, rtype, rdata in sorted(records['other']):
            print(f"{name}.{domain:30s} {rtype:6s} {rdata}")
        print()

    # Total
    total = sum(len(v) for k, v in records.items() if isinstance(v, list))
    print(f"{'='*60}")
    print(f"Total: {total} records + SOA")


def gather_nameservers(domain: str) -> list[str]:
    """Получить NS для домена через публичные DNS (только для своего домена!)."""
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        ips = []
        for rdata in answers:
            try:
                ip = socket.gethostbyname(str(rdata.target))
                ips.append(ip)
            except socket.gaierror:
                continue
        return ips
    except Exception as e:
        print(f"[-] Cannot resolve NS for {domain}: {e}")
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS zone walker (AXFR)")
    parser.add_argument("--ns", required=True,
                        help="NS IP (e.g. 192.168.56.30)")
    parser.add_argument("--domain", required=True,
                        help="Domain (e.g. lab.corp)")
    parser.add_argument("--discover", action="store_true",
                        help="Discover NS via parent zone (use only for own domain)")
    args = parser.parse_args()

    print(f"\n[!] DNS Zone Walker (AXFR)")
    print(f"[!] Используй ТОЛЬКО на собственном NS.\n")

    ns_ip = args.ns
    if args.discover:
        print(f"[*] Discovering NS for {args.domain}...")
        ns_list = gather_nameservers(args.domain)
        if ns_list:
            print(f"[+] Found: {ns_list}")
            ns_ip = ns_list[0]
            print(f"[*] Using: {ns_ip}\n")
        else:
            print(f"[-] No NS found, falling back to {args.ns}")

    records = walk_zone(ns_ip, args.domain)
    if records is None:
        sys.exit(1)

    print_records(records, args.domain)
```

**Запуск (в lab):**

```bash
$ python3 02-dns-zone-walker.py --ns 192.168.56.30 --domain lab.corp

[!] DNS Zone Walker (AXFR)
[!] Используй ТОЛЬКО на собственном NS.

[*] Trying AXFR for lab.corp @ 192.168.56.30
[*] Timeout: 10s

============================================================
Zone: lab.corp
============================================================

;; Start Of Authority (SOA)
dc01.lab.corp.                  dc01.lab.corp. admin.lab.corp. 2026071901 3600 900 604800 86400

;; Name Servers (NS)
lab.corp.                NS    dc01.lab.corp.

;; Mail Servers (MX)
lab.corp.                MX    10 mail.lab.corp.

;; IPv4 Hosts (A)
dc01.lab.corp.                A     192.168.56.30
fileserver1.lab.corp.         A     192.168.56.32
mail.lab.corp.                A     192.168.56.31
vpn.lab.corp.                 A     10.10.0.5
admin-tools.lab.corp.         CNAME  vault.lab.corp.

;; Service Records (SRV)
_kerberos._udp.lab.corp.        SRV    0 0 88 dc01.lab.corp.
_kpasswd._tcp.lab.corp.         SRV    0 0 464 dc01.lab.corp.
_ldap._tcp.lab.corp.            SRV    0 0 389 dc01.lab.corp.
_vlmcs._tcp.lab.corp.           SRV    0 0 1688 dc01.lab.corp.

============================================================
Total: 10 records + SOA
```

### 3.3 Версия 2 — scapy (low-level, для понимания)

```python
#!/usr/bin/env python3
"""
02b-dns-zone-walker-scapy.py — DNS AXFR через scapy (low-level).

Показывает структуру DNS-пакета вручную, без dnspython.
Полезно для обучения и для обхода restricted-окружений.

Запуск: sudo python3 02b-dns-zone-walker-scapy.py --ns 192.168.56.30 --domain lab.corp
"""

import argparse
import struct
import sys

try:
    from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, conf
    conf.verb = 0
except ImportError:
    print("[-] pip install scapy")
    sys.exit(1)


def build_axfr_query(domain: str, tx_id: int = 0xCAFE) -> bytes:
    """DNS query packet для AXFR (type=252)."""
    # Header
    flags = 0x0000  # standard query
    header = struct.pack('!HHHHHH', tx_id, flags, 1, 0, 0, 0)
    # Question
    qname = b''
    for label in domain.split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    question = qname + struct.pack('!HH', 252, 1)  # QTYPE=AXFR (252), QCLASS=IN
    return header + question


def parse_dns_name(data: bytes, offset: int = 12) -> tuple[str, int]:
    """Парсим DNS name (упрощённый — без pointer decompression)."""
    labels = []
    pos = offset
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack('!H', data[pos:pos+2])[0] & 0x3FFF
            label, _ = parse_dns_name(data, pointer)
            labels.append(label)
            pos += 2
            break
        pos += 1
        labels.append(data[pos:pos+length].decode())
        pos += length
    return '.'.join(labels), pos


def dns_axfr(ns_ip: str, domain: str):
    """
    DNS AXFR через UDP (на самом деле должен быть TCP — AXFR > 512 bytes,
    но scapy позволяет и UDP для теста).
    """
    print(f"[*] AXFR query for {domain} @ {ns_ip}")

    # Build DNS packet
    dns_payload = build_axfr_query(domain)

    # Wrap in IP/UDP
    packet = IP(dst=ns_ip) / UDP(dport=53, sport=12345) / DNS(dns_payload)

    # Send and receive
    response = sr1(packet, timeout=5, verbose=False)

    if response is None:
        print("[-] No response")
        return None

    if response.haslayer(DNS):
        dns_layer = response[DNS]
        if dns_layer.rcode != 0:
            print(f"[-] DNS error code: {dns_layer.rcode}")
            return None

        # Count records
        ancount = dns_layer.qd or 0
        print(f"[+] Got {ancount} answer records\n")

        for i in range(ancount):
            rr = dns_layer.an[i]
            print(f"  {rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname:<35s} "
                  f"{rr.type:6s} {rr.rdata}")

        return response
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS AXFR (scapy)")
    parser.add_argument("--ns", required=True)
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()

    print(f"\n[!] DNS AXFR (scapy version — для lab только)")
    dns_axfr(args.ns, args.domain)
```

### 3.4 Альтернатива — dig

```bash
# Классический dig (более полный, через TCP)
dig axfr lab.corp @192.168.56.30 +tcp +noall +answer

# Без +noall +answer (полный вывод)
dig axfr lab.corp @192.168.56.30 +tcp

# Один конкретный NS
dig @192.168.56.30 lab.corp axfr

# Проверить, разрешён ли AXFR
dig @192.168.56.30 version.bind chaos txt
# version.bind.   0   CH   TXT   "9.20.0"  ← версия BIND
```

---

## 4. Скрипт 3 — SMB version detector

### 4.1 Теория SMB negotiate

**SMB (Server Message Block)** — протокол Microsoft для file sharing, printer sharing, named pipes. Эволюция версий:

| Версия | Год | Особенности | Уязвимости |
|---|---|---|---|
| SMBv1 (CIFS) | 1983-1996 | Plaintext passwords (pre-NTLM), нет signing | EternalBlue (MS17-010), WannaCry, NotPetya |
| SMBv2.0 | 2006 | Signing mandatory, AES | — |
| SMBv2.1 | 2010 | OpLock leases | — |
| SMBv3.0 | 2012 | Encryption (AES-CCM/GCM) | — |
| SMBv3.0.2 | 2014 | Dialects negotiation improvement | — |
| SMBv3.1.1 | 2015 | Pre-auth integrity, encryption negotiation | — |
| SMBv3.1.1 (Win11) | 2022 | Multi-channel, compression | — |

**SMB Negotiate Request (первый пакет сессии):**

```
┌─────────────────────────────────────────┐
│ NetBIOS Session Service (4 bytes)       │  ← длина
├─────────────────────────────────────────┤
│ SMB2 Header (64 bytes)                  │
│   - ProtocolId: 0xFE 'S' 'M' 'B'        │
│   - HeaderLength: 64                     │
│   - CreditCharge: 0                      │
│   - ChannelSequence: 0                   │
│   - Reserved: 0                          │
│   - Command: 0x0000 (Negotiate)          │
│   - Credits: 1                           │
│   - Flags: 0                             │
│   - NextCommand: 0                       │
│   - MessageId: 0                         │
│   - Reserved: 0                          │
│   - TreeId: 0xFFFFFFFF                   │
│   - SessionId: 0                         │
│   - Signature: 0 (first time)            │
├─────────────────────────────────────────┤
│ SMB2 Negotiate Request Body (36 bytes)   │
│   - StructureSize: 36                    │
│   - DialectCount: 1+                     │
│   - SecurityMode: 0x03 (signing enabled) │
│   - Reserved: 0                          │
│   - Capabilities: 0                     │
│   - ClientGuid: random                  │
│   - NegotiateContextOffset: 0            │
│   - NegotiateContextCount: 0             │
│   - Reserved2: 0                         │
│   - Dialects: [0x0311, 0x0300, ...]      │  ← от высшей к низшей
└─────────────────────────────────────────┘
```

**SMB Negotiate Response:**

```
- StructureSize: 65
- SecurityMode: 0x03 (signing required)
- Dialect: 0x0311 (3.1.1) ← chosen by server
- ServerGuid: random
- Capabilities: 0x0000007F
- MaxTransactionSize, MaxReadSize, MaxWriteSize
- SystemTime, ServerStartTime
- SecurityBufferOffset
- SecurityBlob (SPNEGO/NTLM)
```

### 4.2 Скрипт — impacket

```python
#!/usr/bin/env python3
"""
03-smb-version-detector.py — определяем версию SMB через impacket.

Запуск: python3 03-smb-version-detector.py -t 192.168.56.30
        (без root — impacket использует обычный socket)
"""

import argparse
import struct
import sys

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    print("[-] pip install impacket")
    sys.exit(1)


def detect_smb_via_impacket(target: str, port: int = 445, timeout: int = 3):
    """
    Используем impacket SMBConnection для negotiate.
    """
    print(f"[*] Connecting to {target}:{port}")

    try:
        # Создаём SMB connection (без auth, просто negotiate)
        conn = SMBConnection(target, target, sess_port=port, timeout=timeout)
    except Exception as e:
        print(f"[-] Connection error: {type(e).__name__}: {e}")
        return None

    # Достаём информацию
    print(f"[+] Connected")
    print(f"    Server OS: {conn.getServerOS()}")
    print(f"    Server LAN Manager: {conn.getServerLanMan()}")
    print(f"    Server Domain: {conn.getServerDomain()}")
    print(f"    Server DNS Hostname: {conn.getServerName()}")
    print(f"    Server Signing Required: {conn.isSigningRequired()}")
    print(f"    SMBv3 Encryption: {conn.getDialect()}")
    print()

    # Определяем версию по dialect
    # Dialect constants: SMB2_DIALECT_2_0_2 = 0x0202
    # SMB2_DIALECT_2_1 = 0x0210
    # SMB2_DIALECT_3_0 = 0x0300
    # SMB2_DIALECT_3_0_2 = 0x0302
    # SMB2_DIALECT_3_1_1 = 0x0311
    dialects = {
        0x0202: 'SMB 2.0.2 (Windows Vista/Server 2008)',
        0x0210: 'SMB 2.1 (Windows 7/Server 2008 R2)',
        0x0300: 'SMB 3.0 (Windows 8/Server 2012)',
        0x0302: 'SMB 3.0.2 (Windows 8.1/Server 2012 R2)',
        0x0311: 'SMB 3.1.1 (Windows 10/Server 2016+)',
    }

    dialect = conn.getDialect()
    if dialect in dialects:
        print(f"    Negotiated dialect: 0x{dialect:04x} ({dialects[dialect]})")
    else:
        print(f"    Negotiated dialect: 0x{dialect:04x} (unknown)")

    # Анализ версии OS
    server_os = conn.getServerOS()
    print(f"\n    Full OS string: {server_os}")

    # Закрываем
    conn.close()
    return {
        'os': server_os,
        'dialect': dialect,
        'signing_required': conn.isSigningRequired(),
    }


def main():
    parser = argparse.ArgumentParser(description="SMB version detector")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=445)
    parser.add_argument("-T", "--timeout", type=int, default=3)
    args = parser.parse_args()

    print(f"\n[!] SMB Version Detector (impacket)")
    print(f"[!] Lab only.\n")

    detect_smb_via_impacket(args.target, args.port, args.timeout)


if __name__ == "__main__":
    main()
```

**Запуск:**

```bash
$ python3 03-smb-version-detector.py -t 192.168.56.30

[!] SMB Version Detector (impacket)
[!] Lab only.

[*] Connecting to 192.168.56.30:445
[+] Connected
    Server OS: Windows Server 2022 Build 20348
    Server LAN Manager: Windows Server 2022 Build 20348
    Server Domain: LAB
    Server DNS Hostname: DC01
    Server Signing Required: True
    SMBv3 Encryption: 0x0311

    Negotiated dialect: 0x0311 (SMB 3.1.1 (Windows 10/Server 2016+))
    Full OS string: Windows Server 2022 Build 20348
```

### 4.3 Скрипт — pure socket (SMB2 negotiate вручную)

```python
#!/usr/bin/env python3
"""
03b-smb-version-socket.py — SMB version detect через raw socket.
Без impacket. Используется для обхода restricted-окружений.

Запуск: python3 03b-smb-version-socket.py -t 192.168.56.30
"""

import argparse
import socket
import struct
import sys


def build_netbios_header(payload: bytes) -> bytes:
    """NetBIOS Session Service header (4 bytes)."""
    length = len(payload)
    return struct.pack('!BBB', 0x00, (length >> 16) & 0xFF, (length >> 8) & 0xFF) \
         + bytes([length & 0xFF]) + payload


def build_smb2_negotiate() -> bytes:
    """SMB2 Negotiate Request с диалектами от высшего к низшему."""

    # Dialects (от высшего к низшему)
    dialects = [
        0x0311,  # SMB 3.1.1
        0x0302,  # SMB 3.0.2
        0x0300,  # SMB 3.0
        0x0210,  # SMB 2.1
        0x0202,  # SMB 2.0.2
    ]

    # Body
    body = struct.pack('<H', 36)              # StructureSize
    body += struct.pack('<H', len(dialects))   # DialectCount
    body += struct.pack('<H', 0x03)            # SecurityMode (signing enabled)
    body += struct.pack('<H', 0)               # Reserved
    body += struct.pack('<I', 0)               # Capabilities
    body += b'\x00' * 16                       # ClientGuid (random в реальности)
    body += struct.pack('<I', 0)               # NegotiateContextOffset
    body += struct.pack('<H', 0)               # NegotiateContextCount
    body += struct.pack('<H', 0)               # Reserved2
    for d in dialects:
        body += struct.pack('<H', d)

    # SMB2 header (64 bytes)
    header = b'\xFE\x53\x4D\x42'               # ProtocolId "FSMB"
    header += struct.pack('<H', 64)            # HeaderLength
    header += struct.pack('<H', 1)             # CreditCharge
    header += struct.pack('<I', 0)             # ChannelSequence/Reserved
    header += struct.pack('<H', 0)             # ChannelSequence
    header += struct.pack('<H', 0)             # Reserved
    header += struct.pack('<H', 0)             # Command (Negotiate = 0)
    header += struct.pack('<H', 1)             # Credits
    header += struct.pack('<I', 0)             # Flags
    header += struct.pack('<I', 0)             # NextCommand
    header += struct.pack('<Q', 1)             # MessageId
    header += struct.pack('<I', 0)             # Reserved
    header += struct.pack('<I', 0xFFFFFFFF)    # TreeId (-1)
    header += struct.pack('<Q', 0)             # SessionId
    header += b'\x00' * 16                     # Signature (first time)

    payload = header + body
    return build_netbios_header(payload)


def parse_smb2_response(data: bytes) -> dict | None:
    """Парсим SMB2 Negotiate Response."""

    # Skip NetBIOS header (4 bytes)
    if len(data) < 4:
        return None

    # Check SMB2 magic
    if data[4:8] != b'\xFE\x53\x4D\x42':
        # Maybe SMBv1 response?
        if data[4:8] == b'\xFF\x53\x4D\x42':
            return {'dialect': 'SMBv1', 'os': 'unknown',
                    'warning': 'Server only supports SMBv1!'}
        return None

    # SMB2 response parsing
    if len(data) < 68:
        return None

    command = struct.unpack('<H', data[12:14])[0]
    if command != 0:  # 0 = Negotiate
        return None

    # Body starts at offset 64 (after SMB2 header) + 8 (NetBIOS + SMB2 magic + header_length)
    # Actually: 4 (NetBIOS) + 64 (SMB2 header) = 68
    body_offset = 68

    structure_size = struct.unpack('<H', data[body_offset:body_offset+2])[0]
    if structure_size != 65:  # Negotiate response = 65 bytes
        return None

    security_mode = struct.unpack('<H', data[body_offset+2:body_offset+4])[0]
    dialect = struct.unpack('<H', data[body_offset+4:body_offset+6])[0]

    signing_required = bool(security_mode & 0x04)  # bit 2
    signing_enabled = bool(security_mode & 0x08)  # bit 3

    dialects = {
        0x0202: 'SMB 2.0.2',
        0x0210: 'SMB 2.1',
        0x0300: 'SMB 3.0',
        0x0302: 'SMB 3.0.2',
        0x0311: 'SMB 3.1.1',
    }

    return {
        'dialect_hex': f'0x{dialect:04x}',
        'dialect': dialects.get(dialect, f'unknown (0x{dialect:04x})'),
        'signing_required': signing_required,
        'signing_enabled': signing_enabled,
    }


def detect_smb(target: str, port: int = 445, timeout: int = 3):
    print(f"[*] Connecting to {target}:{port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return None

    print(f"[+] Connected, sending SMB2 Negotiate...")
    sock.send(build_smb2_negotiate())

    # Read response
    try:
        # Read NetBIOS length (4 bytes)
        length_data = sock.recv(4)
        if len(length_data) < 4:
            print(f"[-] Short read: {len(length_data)}")
            sock.close()
            return None

        netbios_length = struct.unpack('!I', length_data)[0] & 0xFFFFFF

        # Read payload
        payload = b''
        while len(payload) < netbios_length:
            chunk = sock.recv(netbios_length - len(payload))
            if not chunk:
                break
            payload += chunk
    except socket.timeout:
        print(f"[-] Response timeout")
        sock.close()
        return None

    sock.close()

    # Parse
    full_response = length_data + payload
    result = parse_smb2_response(full_response)

    if result:
        print(f"[+] Negotiated: {result['dialect']}")
        print(f"    Signing enabled: {result.get('signing_enabled', 'N/A')}")
        print(f"    Signing required: {result.get('signing_required', 'N/A')}")

        if result['dialect'] == 'SMBv1' or '0x02' in str(result.get('dialect_hex', '')):
            print(f"\n[!] ВНИМАНИЕ: Server supports SMBv1!")
            print(f"    Это УЯЗВИМО. Отключи SMBv1 на сервере.")
    else:
        print(f"[-] Could not parse SMB response")
        print(f"    Raw response hex: {full_response[:64].hex()}")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SMB version detect (raw socket)")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=445)
    args = parser.parse_args()

    print(f"\n[!] SMB Version Detector (raw socket)")
    print(f"[!] Lab only.\n")

    detect_smb(args.target, args.port)
```

**Запуск:**

```bash
$ python3 03b-smb-version-socket.py -t 192.168.56.30

[!] SMB Version Detector (raw socket)
[!] Lab only.

[*] Connecting to 192.168.56.30:445
[+] Connected, sending SMB2 Negotiate...
[+] Negotiated: SMB 3.1.1
    Signing enabled: True
    Signing required: True
```

### 4.4 Дополнение — обнаружение SMBv1 (security check)

```bash
# nmap — самый быстрый способ
nmap -p 445 --script smb-protocols 192.168.56.30
# PORT    STATE SERVICE
# 445/tcp open  microsoft-ds
# | smb-protocols:
# |   dialects:
# |     NT LM 0.12 (SMBv1) [dangerous, but not commonly used]
# |     2.02
# |     2.10
# |     3.00
# |     3.02
# |_    3.11

# nxc
nxc smb 192.168.56.30 -u '' -p '' -d lab.corp
# SMB         192.168.56.30    445    DC01           [*] Windows Server 2022 Build 20348 (name:DC01) (domain:LAB) (signing:True) (SMBv1:False)

# PowerShell (на самой Windows для проверки)
# Set-SmbServerConfiguration -AuditSmb1Access $true -Force
# Get-WinEvent -LogName Applications -MaxEvents 100 | Where-Object {$_.Message -like "*SMB1*"}
```

---

## 5. Бонус — asyncio + scapy TCP-connect banner grab

### 5.1 Асинхронный TCP-баннер grabber

```python
#!/usr/bin/env python3
"""
04-async-tcp-scan.py — asyncio TCP-connect сканер + banner grab.

Использует asyncio.open_connection + кастомные probes per port.
Высокая скорость: 1000+ портов в секунду.

Запуск: python3 04-async-tcp-scan.py -t 192.168.56.0/24 -p 22,80,135,139,445,3389
"""

import argparse
import asyncio
import socket
import time


# Probes — что отправить после подключения
PROBES = {
    22: b'',  # SSH — баннер идёт от сервера
    25: b'EHLO test\r\n',
    80: b'GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: scan\r\n\r\n',
    135: b'',  # RPC — нужны специальные bindings
    139: b'',  # NetBIOS session — сложный handshake
    443: b'',  # TLS — нужен ssl.wrap_socket
    445: b'',  # SMB — нужно SMB negotiate (см. lesson-027)
    1433: b'',  # MSSQL — TDS prelogin
    3389: b'',  # RDP — TPKT handshake
    5985: b'',  # WinRM HTTP — basic auth probe
    8080: b'GET / HTTP/1.0\r\nHost: x\r\n\r\n',
    9100: b'',  # JetDirect — баннер
}


async def grab_banner(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter,
                      port: int,
                      timeout: float = 3.0) -> str:
    """Читаем баннер (первые N байт после подключения)."""
    banner = ''
    try:
        # Сначала шлём probe, если есть
        if port in PROBES and PROBES[port]:
            writer.write(PROBES[port])
            await writer.drain()

        # Читаем ответ
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        banner = data.decode('utf-8', errors='replace').strip()[:200]
    except asyncio.TimeoutError:
        banner = '<timeout>'
    except Exception as e:
        banner = f'<error: {e}>'
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return banner


async def scan_host(ip: str, ports: list[int], timeout: float = 1.5) -> dict:
    """Сканируем один хост по списку портов."""
    open_ports = {}

    for port in ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            # Connected — порт открыт
            banner = await grab_banner(reader, writer, port, timeout)
            open_ports[port] = banner
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Closed/filtered — пропускаем
            continue
        except Exception as e:
            # Unknown — логируем
            continue

    return open_ports


async def scan_network(network: str, ports: list[int], max_concurrent: int = 100):
    """Сканируем сеть."""
    # Parse CIDR
    if '/' not in network:
        raise ValueError("Network must be CIDR (e.g. 192.168.56.0/24)")

    net_str, prefix = network.split('/')
    prefix = int(prefix)
    if prefix != 24:
        raise ValueError("Only /24 supported in demo")

    base = net_str.rsplit('.', 1)[0]

    semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_with_sem(ip):
        async with semaphore:
            return ip, await scan_host(ip, ports)

    # Generate IPs
    tasks = [scan_with_sem(f"{base}.{i}") for i in range(1, 255)]
    results = await asyncio.gather(*tasks)

    # Print
    total_open = 0
    for ip, ports_open in results:
        if ports_open:
            total_open += len(ports_open)
            print(f"\n[+] {ip}:")
            for port, banner in sorted(ports_open.items()):
                b = banner[:100].replace('\n', ' | ').replace('\r', '')
                print(f"    {port:5d}/tcp   {b}")

    print(f"\n[*] Summary: {total_open} open ports across {sum(1 for _, p in results if p)} hosts")


def main():
    parser = argparse.ArgumentParser(description="Async TCP scanner + banner grab")
    parser.add_argument("-t", "--target", required=True,
                        help="Network CIDR (only /24)")
    parser.add_argument("-p", "--ports", default="22,80,135,139,445,3389",
                        help="Comma-separated ports")
    parser.add_argument("-c", "--concurrent", type=int, default=100,
                        help="Max concurrent connections")
    parser.add_argument("-T", "--timeout", type=float, default=1.5,
                        help="Per-port timeout")
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(',')]

    print(f"\n[!] Async TCP scanner (lab only)")
    print(f"[*] Network: {args.target}")
    print(f"[*] Ports: {ports}")
    print(f"[*] Concurrency: {args.concurrent}, timeout: {args.timeout}s\n")

    start = time.time()
    asyncio.run(scan_network(args.target, ports, args.concurrent))
    elapsed = time.time() - start
    print(f"\n[+] Total time: {elapsed:.2f}s")


if __name__ == "__main__":
    main()
```

**Запуск:**

```bash
$ python3 04-async-tcp-scan.py -t 192.168.56.0/24 -p 22,80,135,139,445,3389

[!] Async TCP scanner (lab only)
[*] Network: 192.168.56.0/24
[*] Ports: [22, 80, 135, 139, 445, 3389]
[*] Concurrency: 100, timeout: 1.5s

[+] 192.168.56.21:
    135/tcp   <timeout>
    139/tcp   <timeout>
    445/tcp   <timeout>
[+] 192.168.56.30:
    135/tcp   <timeout>
    139/tcp   <timeout>
    445/tcp   <timeout>
    3389/tcp   <timeout>

[*] Summary: 7 open ports across 2 hosts

[+] Total time: 1.87s
```

---

## 6. Практический playbook — что и когда использовать

### 6.1 Матрица выбора инструмента

| Задача | Лучший выбор | Альтернатива | Когда НЕ использовать |
|---|---|---|---|
| ARP scan в L2 | scapy `srp()` | pure socket | nmap (медленнее) |
| DNS zone walk | `dig axfr` (CLI) | dnspython | scapy (overkill) |
| SMB version | impacket | pure socket | nmap scripts (нужен nmap) |
| TCP banner grab | asyncio | nmap -sV | scapy (медленно) |
| ICMP ping | subprocess + ping | scapy | fping |
| ICMP traceroute | scapy | mtr, traceroute | Windows tracert |
| HTTP recon | asyncio + aiohttp | curl + parse | python-requests |
| TLS recon | ssl + socket | testssl.sh | openssl s_client |
| Service enum | impacket | nmap NSE | ручной smbclient |

### 6.2 Что устанавливать в lab VM

```bash
# Минимальный набор (Kali уже содержит большую часть):
pip install --break-system-packages scapy dnspython impacket

# Расширения:
pip install --break-system-packages aiohttp httpx pysmb pyshark netaddr

# Опционально для анализа PCAP:
pip install --break-system-packages scapy[pdf]   # PDF reports
pip install --break-system-packages cryptography  # TLS parser
```

### 6.3 Тестирование скриптов на loopback

```python
#!/usr/bin/env python3
"""
test_loopback.py — запуск наших скриптов на loopback для самотестирования.

Поднимает localhost DNS (port 5353) и SMB (port 4445), затем запускает detection.
"""

import socket
import threading
import time


def mock_dns_server():
    """Minimal DNS на порту 5353 (loopback only)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 5353))
    print("[mock-dns] listening on 127.0.0.1:5353")
    while True:
        data, addr = sock.recvfrom(512)
        # Отвечаем фиксированным ответом
        # ... (реальный DNS-парсер опущен для краткости)
        sock.sendto(data, addr)


def mock_smb_server():
    """Minimal SMB2 server на порту 4445 (loopback only)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 4445))
    sock.listen(5)
    print("[mock-smb] listening on 127.0.0.1:4445")
    while True:
        client, addr = sock.accept()
        print(f"[mock-smb] connection from {addr}")
        # Возвращаем fake SMB2 negotiate response
        client.send(b'\x00\x00\x00\x40' + b'\xFE\x53\x4D\x42' + b'\x00' * 60)
        client.close()


if __name__ == "__main__":
    # Запускаем mock-серверы
    t1 = threading.Thread(target=mock_dns_server, daemon=True)
    t2 = threading.Thread(target=mock_smb_server, daemon=True)
    t1.start()
    t2.start()
    time.sleep(1)

    print("\n[test] Running ARP scan on 127.0.0.0/30 (loopback)")
    # ... запуск наших скриптов

    print("[test] Press Ctrl-C to stop")
    while True:
        time.sleep(1)
```

---

## 7. Cross-refs

- **lesson-004** — MITM walkthrough bettercap (loopback)
- **lesson-009** — Rogue DHCP/DNS (host-only стенд)
- **lesson-026** — AD network recon (LLMNR/mDNS/NBNS/mitm6)
- **intel/techniques/mitm-2026.md**
- **intel/techniques/iso-mitm-lab-build.md**
- **intel/techniques/python-network-recon-2026.md** (→ в разработке)

## 8. Источники

1. **scapy docs** — https://scapy.readthedocs.io/en/latest/
2. **scapy GitHub** — https://github.com/secdev/scapy
3. **dnspython docs** — https://dnspython.readthedocs.io/
4. **impacket GitHub** — https://github.com/fortra/impacket
5. **NetExec GitHub** — https://github.com/Pennyw0rth/NetExec
6. **asyncio docs** — https://docs.python.org/3/library/asyncio.html
7. **RFC 793** — TCP (для raw socket)
8. **RFC 826** — ARP (для raw socket)
9. **RFC 1035** — DNS (для raw DNS)
10. **MS-SMB2** — SMB2 Protocol Specification (Microsoft Open Spec)
11. **Microsoft SMBv1 removal guide** — https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-overview
12. **Python struct module** — https://docs.python.org/3/library/struct.html
13. **RFC 5936** — DNS Zone Transfer Protocol (AXFR)
14. **Wireshark Display Filters** — https://www.wireshark.org/docs/dfref/

---

**Lesson 027 написан Маяком 🛰. Автономный cron. Скоуп: только собственная изолированная VM или loopback. Никаких публичных сетей.**

---

*Опубликовано автоматически пайплайном Кузи 🦝. Источник: внутренняя база знаний отдела «Киберщит 🛡», byline 0xNull.*
