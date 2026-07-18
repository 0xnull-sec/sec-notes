---
layout: post
title: "# Lesson 021"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 021 — Linux Forensics: обзор книги «Practical Linux Forensics» (Nikkel, 2022)

> **Источник:** Bruce Nikkel. *Practical Linux Forensics: A Guide for Digital Investigators*. No Starch Press, 2022. ISBN 978-1-7185-0190-1.
> **Файл в библиотеке:** `intel/library/incoming/02362_Nikkel Bruce - Practical Linux Forensics - 2022.pdf` (5 МБ)
> **Дата конспекта:** 18.07.2026. **Автор:** Кузя 🦝 (авто-реферирование `pdftotext` + ручной анализ структуры).
> **Cross-refs:** `lesson-017-heap-exploitation-intro.md` (Неделя 3, Скрипт), `lesson-020-threat-hunting-book-review.md` (Lesson 020, Хранитель), `intel/techniques/static-analysis.md`

---

## TL;DR

Книга **Брюса Никкеля** (Bruce Nikkel) — это **полноценный учебник Linux forensics** для DFIR-аналитиков: от базового обзора Linux до глубокой реконструкции событий на файловой системе, в логах, сети и периферии. Структура — 11 глав, охватывающих все основные артефакты (storage, logs, boot, packages, network, time, users, peripherals). Подходит как **полевой справочник** для incident response на Linux-системах.

Главная ценность для отдела «Киберщит 🛡»:
- **Forensic methodology** (главы 1–2) — стандартизированный подход «post-mortem dead disk forensics»
- **Filesystem artifacts** (главы 3–4) — ext4/XFS/Btrfs internals, inode/timeline analysis
- **Log forensic** (глава 5) — syslog/journald/auth.log/secure
- **Network artifacts** (глава 8) — `/etc/network/interfaces`, NetworkManager, `/proc/net/*`, ARP cache
- **User activity** (глава 10) — bash history, last/lastb, utmp/wtmp

**Для инфры Жени это критично:** если CVE-2026-46242 (Bad Epoll) будет эксплуатироваться на Linux-VM, эта книга — гайд как реконструировать атаку.

---

## Структура книги (11 глав)

### Глава 1. Digital Forensics Overview (стр. 1–24)
- **Forensic process**: collection → examination → analysis → reporting
- **Chain of custody** и legal admissibility (Daubert standard)
- **Dead disk forensics** vs. **live forensics** (книга фокусируется на post-mortem)
- **Write blockers** (Tableau, WiebeTech) — обязательны для forensic soundness
- **Hashing**: MD5 (legacy) + SHA-256 (modern) для integrity verification
- **Imaging tools**: `dd`, `dcfldd`, `ewf` (libewf), `Guymager`

### Глава 2. Linux Overview (стр. 25–62)
- Unix history (1970 — Bell Labs) → GNU (1983 — Stallman) → Linux kernel (1991 — Torvalds) → distributions
- **4 mainstream дистрибутива** (фокус книги): Debian/Ubuntu, Fedora/RedHat, SUSE, Arch
- **Architecture-independent**: x86_64 (Intel/AMD) + ARM (Raspberry Pi)
- **Server vs. desktop** forensics — разные артефакты
- **Filesystem hierarchy** (`/etc`, `/var`, `/tmp`, `/home`, `/proc`, `/sys`)
- **Mount points** + `fstab` анализ

### Глава 3. Evidence from Storage Devices and Filesystems (стр. 63–94)
- **Partition tables**: MBR (legacy) vs. GPT (modern)
- **Volume management**: LVM (в Fedora/RHEL), ZFS, Btrfs subvolumes
- **RAID**: mdadm (software), hardware (BBWC)
- **Файловые системы**:
  - **ext4** — default для большинства Linux. Inode-based, journaling, extent-based allocation.
  - **XFS** — high-performance, used in RHEL/CentOS.
  - **Btrfs** — copy-on-write, snapshots, subvolumes.
  - **ZFS** — Solaris-derived, snapshot/clone, but licensing restricts Linux GPL kernel integration.
- **Slack space analysis**: unallocated space в cluster'е
- **Superblock** + **inode tables** — где искать deletion timestamps

### Глава 4. Directory Layout and Forensic Analysis of Linux Files (стр. 95–114)
- **FHS (Filesystem Hierarchy Standard)** — что обязано быть где
- **Config files** в `/etc/`:
  - `/etc/passwd` + `/etc/shadow` (user accounts + hashed passwords)
  - `/etc/sudoers` (privilege escalation paths)
  - `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*` (scheduled tasks)
  - `/etc/ssh/sshd_config` + `~/.ssh/authorized_keys`
  - `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`
- **User artifacts** в `/home/<user>/`:
  - `.bash_history` — критический артефакт
  - `.ssh/` — private keys + known_hosts (доказательство compromise)
  - `.config/` — приложения, recent files
- **Temporary files** в `/tmp/` + `/var/tmp/` — часто malware staging area
- **Deleted file recovery** через `extundelete`, `photorec`, `testdisk`

### Глава 5. Investigating Evidence from Linux Logs (стр. 115–144)
- **syslog** (legacy `syslogd`, `rsyslog`, `syslog-ng`) — `/var/log/`
  - `auth.log` (Debian/Ubuntu) или `secure` (RHEL/Fedora) — аутентификация
  - `kern.log` — kernel events (включая **Bad Epoll CVE-2026-46242** trace)
  - `syslog`, `messages` — общие сообщения
  - `daemon.log`, `user.log` — service-specific
- **journald** (`systemd-journald`) — binary structured logs
  - `journalctl --since "2026-07-01" --until "2026-07-18"`
  - `journalctl -k` (kernel-only)
- **Logrotate** — ротация, gzip timestamp pattern: `auth.log.1.gz`, `auth.log.2.gz`
- **Last** command output: `last -f /var/log/wtmp` — successful logins
- **Lastb** для failed: `/var/log/btmp`
- **Bash history** как артефакт: `cat ~/.bash_history`, hidden history (HISTFILE=~/.bash_secret)

### Глава 6. Reconstructing System Boot and Initialization (стр. 145–182)
- **Boot process**: BIOS/UEFI → GRUB → kernel → initramfs → systemd
- **systemd** units: `/etc/systemd/system/*`, `/lib/systemd/system/*`
- **Boot logs**: `journalctl -b -1` (previous boot)
- **Service enablement** — какие службы стартуют при boot (indicators of persistence)
- **`last -x`** — показать reboot/shutdown events (для timeline)
- **initrd/initramfs analysis** — какие модули загружены, evidence of rootkit

### Глава 7. Examination of Installed Software Packages (стр. 183–224)
- **Package managers**:
  - Debian/Ubuntu: `dpkg`, `apt` (`.deb` files)
  - Fedora/RHEL: `rpm`, `dnf`, `yum` (`.rpm` files)
  - Arch: `pacman`
- **История установок**: `/var/log/dpkg.log`, `/var/log/yum.log`
- **Binary repositories** — какие PPA/repos добавлены (compromise indicator)
- **Checksum verification**: `debsums`, `rpm -V` (помогает найти modified binaries — rootkit indicator)
- **Library dependencies**: `ldd`, `readelf` — что было подключено

### Глава 8. Identifying Network Configuration Artifacts (стр. 225–254)
- **Network interfaces**: `/sys/class/net/`, `ip link show`, `ifconfig -a`
- **IP configuration**:
  - Static: `/etc/network/interfaces` (Debian) / `/etc/sysconfig/network-scripts/ifcfg-*` (RHEL)
  - Dynamic: NetworkManager state (`/var/lib/NetworkManager/`)
- **DNS**: `/etc/resolv.conf`, `/etc/nsswitch.conf`, `systemd-resolved`
- **ARP table**: `ip neigh show`, `/proc/net/arp`
- **Routing**: `ip route show`, `/proc/net/route`
- **Firewall**:
  - `iptables-save`, `ip6tables-save`
  - `nft list ruleset` (nftables, modern replacement)
  - `ufw status` (Ubuntu)
- **Hostname/hosts**: `/etc/hostname`, `/etc/hosts`
- **Open ports**: `ss -tulnp`, `netstat -tulnp` (legacy)

### Глава 9. Forensic Analysis of Time and Location (стр. 255–272)
- **Time formats**:
  - Unix epoch (seconds since 1970-01-01) — internal storage
  - ISO 8601 / RFC 3339 — human-readable
  - Windows FILETIME (100ns intervals since 1601) — для cross-platform
- **Timezone**: `/etc/timezone`, `/etc/localtime` (symlink to `/usr/share/zoneinfo/*`)
- **NTP**: `/etc/ntp.conf`, `chrony.conf`, `systemd-timesyncd`
- **RTC vs. system clock** — расхождения как evidence of manipulation
- **TZ environment variable** переопределение
- **Geolocation через systemd-timesyncd** + Network Time Security (NTS)

### Глава 10. Reconstructing User Desktops and Login Activity (стр. 273–324)
- **Login tracking**:
  - `last` / `lastb` (binary logs `/var/log/wtmp`, `/var/log/btmp`)
  - `utmp` (currently logged-in users)
  - `faillog` (failed login counters per user)
- **Display managers**: GDM, LightDM, SDDM — login logs в `~/.cache/gdm/`, `~/.local/share/xorg/`
- **Session info**: `loginctl`, `systemd-logind` journal entries
- **Desktop environments**:
  - GNOME (`~/.local/share/gnome-*`)
  - KDE (`~/.config/plasma-*`)
  - XFCE, MATE, Cinnamon — разные paths
- **Recent files**: `~/.local/share/recently-used.xbel`, `~/.config/gtk-3.0/recently-used.xbel`
- **Browser artifacts** (отдельно): `~/.mozilla/firefox/*/places.sqlite`, `~/.config/chromium/Default/History`
- **Bash history forensics**:
  - `~/.bash_history` (with HISTTIMEFORMAT)
  - Audit logs через `auditd` (`/var/log/audit/audit.log`)
- **sudo** logs: `/var/log/auth.log` + `journalctl _COMM=sudo`

### Глава 11. Forensic Traces of Attached Peripheral Devices (стр. 325–end)
- **USB devices**: `lsusb`, `/var/log/syslog` USB-attach events, `udev` database (`/lib/udev/rules.d/`, `/etc/udev/rules.d/`)
- **Bluetooth**: `hcitool`, `bluetoothctl` history
- **Mount points** внешних дисков: `/etc/fstab`, `/var/log/syslog` mount events, `/media/`, `/mnt/`
- **Printers**: CUPS logs в `/var/log/cups/`
- **Audio devices**: PulseAudio/PipeWire history

---

## Главные takeaways для отдела

1. **Post-mortem > live forensics** — книга фокусируется на «dead disk» подходе. Это золотое правило: ничего не модифицировать на живом хосте, делать image через `dd` + `sha256sum`.

2. **Не трогать оригинал** — даже при чтении логов на live-системе, mount может изменить timestamps. Лучшая практика: `dd if=/dev/sda of=/tmp/image.img bs=4M status=progress` + `sha256sum /tmp/image.img > /tmp/image.sha256`.

3. **Bash history — золотая жила** — даже без auditd, `~/.bash_history` расскажет много: какие команды, в каком порядке, с какими аргументами. Только если не отключен (`unset HISTFILE`).

4. **Filesystem timeline — главный инструмент** — `fls` (Sleuth Kit), `mactime`, `log2timeline/plaso` для supertimeline из всех артефактов (logs, filesystem, registry equivalent).

5. **`journalctl` > syslog** на modern дистрибутивах — структурированные бинарные логи, indexed по boot. `journalctl _UID=1000` — все события от пользователя 1000.

6. **Network artifacts быстро устаревают** — ARP cache, route table, открытые порты — всё volatile. Если forensics начинается через час после инцидента — эта инфа потеряна.

7. **Связь с lesson-020 (Threat Hunting)** — hunting генерирует hypotheses, forensics даёт evidence. На нашей UTM-VM (если скомпрометирована) — book Nikkel = roadmap реконструкции атаки.

---

## Ключевые команды

```bash
# Глава 1 — Forensic image (dead disk)
sudo dd if=/dev/sda bs=4M status=progress conv=noerror,sync of=/tmp/image.img
sha256sum /tmp/image.img > /tmp/image.sha256
# или быстрее с parallel через netcat: `dd if=/dev/sda bs=4M | nc -l 9999` на examiner

# Глава 3 — Find deleted files (ext4)
sudo extundelete /dev/sda1 --restore-all --output-dir /tmp/recovered/

# Глава 5 — Извлечь auth attempts
sudo cat /var/log/auth.log | grep -E "Accepted|Failed" | tail -100
sudo last -f /var/log/wtmp | head -50        # successful logins
sudo lastb | head -50                        # failed logins
sudo journalctl _COMM=sshd --since "2026-07-01"

# Глава 6 — Boot + service timeline
sudo journalctl -b -1                              # previous boot
sudo systemctl list-unit-files --state=enabled    # persistence services

# Глава 7 — Verify package integrity (rootkit indicator)
sudo debsums -c 2>/dev/null | grep -v "OK$"        # Debian — modified files
sudo rpm -Va | grep -E "^..5"                       # RHEL — permission/md5 mismatch

# Глава 8 — Network artifacts
sudo cat /var/log/syslog | grep -iE "DHCP|IP|ARP|link" | tail -50
sudo ss -tulnp                                      # current open ports
sudo cat /etc/iptables/rules.v4 2>/dev/null
sudo nft list ruleset

# Глава 10 — User activity timeline
sudo last -i                                        # logins с IP-адресами
sudo find /home -name ".bash_history" -exec cat {} \;
sudo cat /home/*/.local/share/recently-used.xbel 2>/dev/null | head -30

# Глава 11 — USB/Bluetooth
sudo cat /var/log/syslog | grep -iE "usb|bluetooth" | tail -50
sudo lsusb -v
```

---

## Где применить в отделе

| Зона | Агент | Как применить |
|---|---|---|
| Methodology | Хранитель | NIST IR lifecycle + forensic process в `agents/khranitel/SOP.md` |
| Linux VM forensic | Хранитель + Тень | Если UTM-VM скомпрометирована (CVE-2026-46242) — book Nikkel = playbook |
| Filesystem analysis | Скрипт | Утилиты `extundelete`, `The Sleuth Kit` (`fls`, `mactime`) |
| Timeline building | code-sentinel | `plaso/log2timeline` для supertimeline нашей `tools/` директории |
| Наша инфра | Маяк | Network artifacts + peripheral artifacts на роутерах (MikroTik) |
| Учебный стенд | Тень | GOAD-lite + forensic image в `/Volumes/WorkDrive/projects/forensic-lab/` |

---

## Релевантность для инфры Жени

- **UTM-VM Linux guest** — если применили CVE-2026-46242, эта книга = гайд по расследованию. **Ядро 6.4+**, проверяем `uname -r`.
- **MikroTik RouterOS** — Linux-based (fork). Глава 8 (Network) особенно актуальна.
- **Raspberry Pi** дома (если есть) — архитектура ARM, forensics применяется аналогично.
- **WorkDrive** — криминалистика на наших OSINT-данных (если возникнет утечка).

---

## Cross-refs

- **`lesson-020-threat-hunting-book-review.md`** — парная книга для blue team. Hunt + Forensic = complete IR.
- **`lesson-017-heap-exploitation-intro.md`** — если пишем CVE PoC, forensics помогает понять как детектить exploitation.
- **`intel/techniques/static-analysis.md`** — pre-incident scanning через semgrep/tartufo complements post-incident forensics.
- **`agents/code-sentinel/PROFILE.md`** — code-sentinel может применить Sleuth Kit к нашим инструментам.
- **`intel/lessons/lesson-013-intel-gap-review.md`** — закрывает gap «detection engineering»; Nikkel = детекция через артефакты.

---

*Само-референс: lesson создан Кузей 🦝 через `pdftotext` + ручной анализ структуры. Не содержит приватных данных Жени. Готов для citation в публикациях.*
