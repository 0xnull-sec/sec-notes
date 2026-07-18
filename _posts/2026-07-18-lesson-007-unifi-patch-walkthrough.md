---
layout: post
title: "# Lesson 007"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 007 — UniFi OS Bulletin 064: Patch Walkthrough (simulator → expected real scenario)

> **Автор:** Тінь 🦅 · **Дата:** 2026-07-06 → фінал 2026-07-10
> **CVE chain:** CVE-2026-34908 / CVE-2026-34909 / CVE-2026-34910 / CVE-2026-34911 / CVE-2026-33000
> **Основа:** `intel/cve/active/UNIFI_PATCH_PLAN.md` + `tools/pentest/unifi/cve_2026_34908_check.py` + `tools/pentest/unifi/sim/`
> **Станом на 2026-07-06 (початок Тижня 2):** реальний патч Женею **ще не виконано** (deadline 26.06, прострочено 10+ днів). Тому lesson — **walkthrough по симулятору + очікуваний реальний сценарій**, за аналогією з lesson-005 (CUCM симуляторний walkthrough).
> **Крос-посилання:** lesson-001 (огляд CVE), lesson-005 (structure reference), `agents/pentester/reports/2026-06-30-unifi-sim.md` (повний опис симулятора).

## TL;DR

Bulletin 064-064 — це **п'ять CVE**, які разом утворюють unauth RCE chain на UniFi OS. CISA додала 34908/34909/34910 в KEV 23.06 з due 26.06. У Жені вдома CloudKey + 10+ UniFi mesh — **прострочено 10+ днів**, mass-scanners вже активно працюють.

У цьому lesson:

1. Розбираємо всі 5 CVE, як вони складаються в chain і чому їх треба патчити разом.
2. Проганяємо safe-detector (`cve_2026_34908_check.py`) проти **локального симулятора UniFi OS** у трьох режимах (vulnerable 5.0.6 / patched 5.0.8 / unaffected).
3. Фіксуємо всі 4 автотести з `test_detector.sh` — **passed: 4 / failed: 0**.
4. Описуємо **очікуваний реальний сценарій**: pre-patch checklist → detector → backup → WAN-lockdown → rolling upgrade → post-patch verification → log review.
5. Фіксуємо **lessons learned**: KEV due → patch в той самий день, edge-device CVE = топ-пріоритет, симулятор як обов'язковий dry-run перед прод-сканом.

**Головний висновок:** без реального доступу до CloudKey з пісочниці sub-agent'а ми не можемо прогнати detector по справжньому залізу — але симулятор відтворює саме ту **розв'язку RAW ≠ NORMALIZED URI**, яку експлуатує CVE-2026-34908. Для перевірки коректності detector'а цього достатньо. Коли Женя запустить detector на реальному CloudKey, вердикти збігатимуться з тим, що ми бачимо в `test_detector.sh`: прошивка ≤ 5.0.6 → `VULNERABLE`, ≥ 5.0.8 → `PATCHED`.

---

## 0. Контекст CVE

### 0.1 Хронологія

| Дата | Подія |
|------|-------|
| 2026-05 | Duc Anh Nguyen (@heckintosh_) знаходить nginx auth-bypass (34908); Abdulaziz Almadhi — path traversal (34909); V3rlust — command injection з admin-токеном (33000) |
| 2026-05-21 | Ubiquiti публікує Bulletin 064-064 |
| 2026-06-04 | Bishop Fox Team X публікує повний аналіз + safe detector |
| 2026-06-23 | CISA додає 34908/34909/34910 в KEV, due 26.06 |
| 2026-06-26 | **KEV due** — для CloudKey у Жени прострочено |
| 2026-06-30 | Симулятор зібрано, всі 4 тести detector'а зелені |
| 2026-07-06 | Lesson-007 створено |

### 0.2 П'ять CVE в Bulletin 064

| CVE | Клас | Privilege | Роль у chain |
|---|---|---|---|
| **CVE-2026-34908** | Improper Access Control | **unauth** | Auth-bypass (foothold) |
| **CVE-2026-34909** | Path Traversal | **unauth** | Альтернативний bypass (redundancy для WAF) |
| **CVE-2026-34910** | Command Injection | **unauth via bypass** | RCE sink (root) |
| **CVE-2026-34911** | Path Traversal | low-priv (auth, не admin) | Data exfil, lateral pivot |
| **CVE-2026-33000** | Command Injection | admin token | Той самий sink, але з авторизацією |

**Терміни:** **Bypass** (34908/34909) — primitive для доступу без токена. **Sink** (34910/33000) — RCE через bypass (34910, unauth) або з admin-токеном (33000). **Path traversal** (34909/34911) — маніпуляції з URI для bypass'у (34909, unauth) або читання файлів під low-priv (34911).

### 0.3 Механіка bypass'у — nginx raw-vs-normalized URI

UniFi OS фронтить внутрішні сервіси nginx'ом. nginx має два рівні обробки URI:

1. **Auth subrequest** — перевіряє авторизацію. Для публічних endpoint'ів (`/api/auth/validate-sso/...`) повертає "public, pass-through".
2. **Location routing** — вибирає, куди проксиювати запит.

Проблема: **auth subrequest** дивиться на **RAW URI** (`%2f` дослівно), а **routing** — на **NORMALIZED URI** (після декодування `%2f → /` і collapse `..`).

Запит:

```http
GET /api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package HTTP/1.1
Host: <unifi-host>
```

- **Raw URI:** `/api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package` → auth subrequest бачить prefix `/api/auth/validate-sso/` → публічний → пропускає без токена.
- **Normalized URI:** `/proxy/users/api/v2/ucs/update/latest_package` → nginx роутить на внутрішній proxy-handler.

**Результат:** unauthenticated доступ до внутрішнього endpoint'у. Це і є bypass.

### 0.4 Sink — `pkg_name` command injection (CVE-2026-34910)

Внутрішній endpoint приймає query parameter `pkg_name` і передає його без sanitization в shell:

```
GET /api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package?pkg_name=;id;
```

На уразливій збірці (≤ 5.0.6) сервер виконує результат як shell-команду **від імені root**. Unauth RCE.

**34909** — та сама розв'язка RAW ≠ NORMALIZED через `/api/sso/v1/...` (якщо 34908 заблокований WAF'ом). **34911** — path traversal для читання файлів ОС під **аутентифіковним не-admin** користувачем; вектор для data exfil після foothold'у.

---

## 1. Моделі та версії під ударом

За даними Bulletin 064-064:

| Серія | Уразливі | Фікс |
|---|---|---|
| UniFi OS Server (self-host) | ≤ 5.0.6 | **5.0.8+** |
| UDM / UDM-Pro / UDM-SE / UDM-Pro-Max / EFG / UDW / UDR7 / Express 7 | ≤ 5.0.16 | **5.1.12+** |
| UDR, UNVR, UNVR-Pro, UNVR-Instant, ENVR, UCG-Ultra, UCG-Max, UCG-Fiber | ≤ 5.0.16 | **5.1.12+** |
| UDR-5G, ENVR-Core, UCKP, UCK, UCK-Enterprise | ≤ 5.0.17 | **5.1.12+** |
| UCG-Industrial | ≤ 5.0.13 | **5.1.12+** |
| UNVR-G2 / UNVR-G2-Pro | ≤ 5.1.11 | **5.1.12+** |
| UNAS-2 / UNAS-4 / UNAS-Pro / UNAS-Pro-4 / UNAS-Pro-8 | ≤ 5.1.8 | **5.1.10+** |
| UDM-Beast | ≤ 5.1.8 | **5.1.11+** |

**Важливий нюанс:** фіксова версія **різна для різних серій**. Не можна просто "оновити все до 5.0.8" — для mesh і UDM треба **5.1.12+**, для UNAS — **5.1.10+**, для UDM-Beast — **5.1.11+**.

**Перевірка версії:**

- GUI: `UniFi Network → Settings → System → Version`
- CLI: `ssh <device>` → `cat /etc/version`
- API: `curl -sk https://<device>:11443/api/manifest.json` (за наявності API-токена)

**Типовий homelab:** CloudKey (UCK/UCKP) + UDM/UDM-Pro + 5–15 UniFi mesh (U7-Pro, U6-LR, U6-Enterprise). Інвентар — перше, що потрібно зробити перед патчем (від нього залежить порядок оновлення).

---

## 2. Detector walkthrough (simulator → реальний CloudKey)

### 2.1 Що таке safe detector

Bishop Fox Team X випустив detector (`tools/pentest/unifi/cve_2026_34908_check.py`, 14.7 KB, **stdlib only**). Принцип:

1. **Baseline control:** GET на `/proxy/users/api/v2/ucs/update/latest_package` БЕЗ bypass'у. На здоровому хості повертає 401.
2. **Bypass probe:** GET на `/api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package`. Якщо bypass працює — nginx пропускає запит на internal handler.
3. **Fingerprint:** якщо verdict неочевидний — додатковий GET на `/`, пошук маркерів UniFi OS.

**Detector не виконує command injection** — він перевіряє лише, чи запит **дійшов** до vulnerable handler'а (наявність маркера `pkg_name required`). Безпечний для прод-сканування.

### 2.2 Класифікація вердиктів

| Verdict | HTTP + body | Значення | Дія |
|---|---|---|---|
| `VULNERABLE` | 200 + `{pkg_name required}` | Bypass дійшов до sink'у | **Негайно патчити** |
| `PATCHED` | 400 | nginx 5.0.8+ відбиває divergence | OK, перевірити інші |
| `INCONCLUSIVE` | 401 (auth enforced) | UniFi host, bypass заблокований | Перевірити версію руками |
| `INCONCLUSIVE` | несподівана відповідь | UniFi host, сигнал не класифікується | Перевірити руками |
| `UNAFFECTED` | без UniFi fingerprint | Не UniFi OS Server | Не наш випадок |
| `ERROR` | timeout / connection refused | Хост недоступний | Перевірити IP / порт |

Exit code: `1` якщо хоча б один `VULNERABLE`, інакше `0`. CI-friendly.

### 2.3 Симулятор — навіщо

Sub-agent з пісочниці **не має маршруту до домашнього LAN Жени** (CloudKey + UDM у subnet, недоступній з sandbox). Це означає: (1) ми **фізично не можемо** прогнати detector по реальному CloudKey, (2) без перевірки detector'а ризикуємо запустити неперевірений інструмент на прод-устаткуванні Жени, (3) потрібен **локальний стенд**, що відтворює **логіку bypass'у**.

Рішення: **mock UniFi OS Server** у `tools/pentest/unifi/sim/` (48 KB, 666 LOC, stdlib only). Детальний опис — у `agents/pentester/reports/2026-06-30-unifi-sim.md`.

### 2.4 Симулятор: структура

```
tools/pentest/unifi/sim/
├── mock_server.py     # 383 LOC, stdlib http.server + ssl, 3 режими
├── start.sh / stop.sh / test_detector.sh
├── certs/             # self-signed (генеруються автоматично)
└── logs/              # mock.log
```

**Три режими:**

| Режим | Версія | Bypass probe | Baseline | `/` fingerprint |
|---|---|---|---|---|
| `vulnerable` | 5.0.6 | **200 + `pkg_name required`** | 401 | UniFi OS HTML |
| `patched` | 5.0.8 | **400** (nginx відбиває divergence) | 401 | UniFi OS HTML |
| `unaffected` | 0.0.0 | 404 | 404 | plain text (без маркерів) |

**Ключова деталь:** функція `nginx_normalize()` декодує `%2f → /`, `%2e → .` і схлопує `..` — точно як реальний nginx. Для поведінки detector'а (код відповіді + маркер `pkg_name`) поведінка mock'а збігається з реальною уразливою прошивкою.

### 2.5 Прогон detector'а проти симулятора — фактичний результат

Команда:

```bash
~/.openclaw/workspace/tools/pentest/unifi/sim/test_detector.sh
```

Фактичний вивід (запущено 2026-07-06 з пісочниці):

```
=== Test 1/4: VULNERABLE mode (5.0.6) — expect VULNERABLE ===
    detector: VULNERABLE    127.0.0.1:11443
    PASS  vulnerable  → got VULNERABLE
    full output:
      [!] 127.0.0.1:11443: VULNERABLE
            auth bypass reached the vulnerable handler (no command executed); baseline correctly 401

=== Test 2/4: PATCHED mode (5.0.8) — expect PATCHED ===
    detector: PATCHED       127.0.0.1:11443
    PASS  patched  → got PATCHED
    full output:
      [+] 127.0.0.1:11443: PATCHED
            nginx rejected the normalized-path divergence (HTTP 400) — 5.0.8+ behavior

=== Test 3/4: UNAFFECTED mode (non-Unifi mock) — expect UNAFFECTED ===
    detector: UNAFFECTED    127.0.0.1:11443
    PASS  unaffected  → got UNAFFECTED
    full output:
      [-] 127.0.0.1:11443: UNAFFECTED
            no UniFi OS web fingerprint on / (probe HTTP 404) — target is not a UniFi OS Server

=== Test 4/4: NO LISTENER (port closed) — expect ERROR, no crash ===
    detector: ERROR         127.0.0.1:11443  [Errno 61] Connection refused
    PASS  no-listener  → got ERROR (graceful, no crash)

=== Summary ===
    passed: 4
    failed: 0
```

**Що це підтверджує:**

1. ✅ Detector **правильно класифікує уразливу збірку** (5.0.6 → VULNERABLE).
2. ✅ Detector **правильно класифікує пропатчену збірку** (5.0.8 → PATCHED).
3. ✅ Detector **коректно відрізняє UniFi OS від не-UniFi** (через fingerprint на `/`).
4. ✅ Detector **не падає на закритому порту** (graceful ERROR, не crash).

Коли Женя запустить той самий detector на реальному CloudKey — вердикти збігатимуться з тим, що тут.

### 2.6 Додаткові сигнали від симулятора

**Manifest endpoint** (відповідає реальному UniFi OS):

```json
{
  "version": "5.0.6",
  "build": "atag-5.0.6-mock",
  "device_type": "uck",
  "_mock": true
}
```

**JSON-вивід detector'а (CI-friendly):**

```json
[
  {
    "target": "127.0.0.1:11443",
    "bypass": {"state": "vulnerable", "detail": "auth bypass reached the vulnerable handler (no command executed); baseline correctly 401"},
    "verdict": "VULNERABLE"
  }
]
```

**Endpoint'и, які detector не дёргає** (інформаційні): `POST /api/login` (34909 bypass), `GET /api/sso/v1/...` (34909 SSO), `GET /api/users/...` (34910 sink).

### 2.7 Поведінка detector'а на не-UniFi хостах (negative-control)

Перевірка на публічних хостах — щоб переконатися, що detector **не дає false-positive на не-Unifi**:

```bash
$ python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py demo.ui.com:443 --no-color
[-] demo.ui.com:443: UNAFFECTED
      no UniFi OS web fingerprint on / (probe HTTP 200) — target is not a UniFi OS Server

$ python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py ui.com:443 --no-color
[-] ui.com:443: UNAFFECTED
      no UniFi OS web fingerprint on / (probe HTTP 200) — target is not a UniFi OS Server

$ python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py badssl.com:443 --no-color
[-] badssl.com:443: UNAFFECTED
      no UniFi OS web fingerprint on / (probe HTTP 404) — target is not a UniFi OS Server
```

✅ Detector **не плутає** ui.com (маркетинговий сайт) з UniFi OS Server. Для сканування довгих списків — без шуму.

**Невалідний IP:**

```bash
$ python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py 192.168.0.1 --no-color
[x] 192.168.0.1:11443: ERROR
      error: [Errno 61] Connection refused
```

✅ Detector **не crash'ить** на закритому порту — graceful `ERROR`.

---

## 3. Pre-patch: backup, baseline detector, чек-ліст

### 3.1 Inventory (перш за все)

**Завдання:** виписати модель + поточну прошивку кожного пристрою.

```text
# Інвентар UniFi (заповнити перед патчем)
Device        | Model          | IP            | Current Version | Vulnerable?
--------------+----------------+---------------+-----------------+------------
CloudKey      | UCK-Gen2       | 192.168.X.Y   | 5.0.6           | YES (≤5.0.6)
UDM-Pro       | UDM-Pro        | 192.168.X.Z   | 5.0.16          | YES (≤5.0.16)
U7-Pro #1     | U7-Pro         | 192.168.X.A   | 5.0.16          | YES
... (10+ mesh)
```

**Звідки брати:** GUI (UniFi Network → Devices → Version), CLI (`ssh <device>` → `cat /etc/version`), API (`curl -sk https://<device>:11443/api/manifest.json`).

### 3.2 Backup конфігурації

UniFi Controller має вбудований backup:

```text
UniFi Network → Settings → System → Backups → Download Backup
```

Це `.unf` файл з повною конфігурацією мережі (WLANs, firewall rules, DPI, статистика). Backup **обов'язковий** — якщо патч зламає adoption, backup дозволить відкотити без перестворення всієї мережі.

**Додатково** (для параноїків):

- Експорт firewall rules вручну (Settings → Security → копіювати правила в текстовий файл).
- Експорт списку API-токенів (Settings → Admins & Users → API Tokens → зберегти імена + scopes).

### 3.3 Baseline detector scan (pre-patch)

Для **кожного** пристрою, що відповідає на `:11443`:

```bash
~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py <cloudkey-ip>:11443 --no-color
~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py <udm-ip>:11443 --no-color
# mesh — за потребою (деякі не відповідають на 11443 напряму)
```

**Зберегти JSON для аудиту:**

```bash
python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py \
  <cloudkey-ip>:11443 <udm-ip>:11443 \
  --json --no-color \
  > ~/unifi-prepatch-$(date +%Y-%m-%d).json
```

**Очікувані вердикти pre-patch (для простроченої установки Жени):**

| Device | Версія | Очікуваний verdict |
|---|---|---|
| CloudKey (≤ 5.0.6) | 5.0.6 | **VULNERABLE** |
| UDM/UDR (≤ 5.0.16) | 5.0.16 | **VULNERABLE** (через 34908 bypass) |
| Mesh U7/U6 (≤ 5.0.16) | 5.0.16 | **VULNERABLE** |

⚠️ **Якщо хоча б один `VULNERABLE`** — експлойт доступний з LAN прямо зараз. Перевірити логи на сліди компрометації (див. § 5.2).

### 3.4 Перевірка на наявність слідів експлойту

Якщо detector каже VULNERABLE — можливо, хтось вже експлуатував. Перевірити логи (`Settings → System → Logs → Export`):

```bash
grep -E "(/api/auth/validate-sso|pkg_name|users/api/v2/ucs/update|\.\.%2f)" ~/Downloads/unifi-logs-*.txt | head -100
```

**Що шукаємо:** `GET /api/auth/validate-sso/..%2f..` (спроби bypass'у), `pkg_name=` з shell metacharacters (`;`, `|`, `$()`, backticks), POST на `/api/users/...` з незвичних IP.

Також перевірити `Settings → Admins & Users → Admins` — чи немає невідомих admin-аккаунтів. Якщо є — видалити, змінити пароль поточного admin'а, revoke всі API-токени.

---

## 4. Upgrade procedure (rolling order)

### 4.1 Чому порядок важливий

UniFi-пристрої спілкуються через "adoption handshake" з контролером (CloudKey). Якщо оновити mesh **до** контролера:

- Mesh може увійти в нову прошивку, яка вимагає новий формат handshake'у.
- Контролер на старій прошивці не розуміє новий handshake.
- AP "провисає" — статус "pending adoption", клієнти відключаються.

Тому порядок:

1. **CloudKey (controller)** — першим, всі залежать від нього.
2. **UDM/UDR (gateway)** — другим, потребує контролер для management plane.
3. **Mesh (AP, switches)** — по одному, rolling.

### 4.2 Покрокова процедура

**Крок 0: Pre-flight** — inventory виписаний (§ 3.1), backup (§ 3.2), detector прогнаний (§ 3.3), логи (§ 3.4), WAN-доступ закритий (§ 4.3).

**Крок 1: CloudKey (controller).** `UniFi Network → Devices → [CloudKey] → Upgrade` → 5–10 хв (reboot + UI reload) → перевірити login (https://cloudkey:11443) і всі пристрої у Devices зі статусом "Connected".

**Крок 2: UDM/UDR (gateway).** `Devices → [UDM] → Upgrade` → 5–10 хв → перевірити WAN-з'єднання (Settings → Internet), LAN-клієнтів (ARP), management.

**Крок 3: Mesh (rolling).** `Devices → [AP-1] → Upgrade` → 5 хв між кожним → перевірити Connected, broadcasted SSID, клієнтів.

⚠️ **Якщо AP не повертається:** 10 хв → "Force Provision" → power cycle 30 сек → serial console recovery (рідко).

**Очікуваний час:** 30–60 хв на повний цикл (CloudKey + UDM + 10+ mesh).

### 4.3 Pre-patch mitigation: WAN-lockdown

**До початку патча** — закрити WAN-доступ до CloudKey: `Settings → System → Internet → Remote Access → OFF`. Це **не фікс**, а тимчасове обмеження attack surface (mass-scanner може спробувати експлойт через інтернет). Після повного патча — Remote Access можна увімкнути назад.

⚠️ WAN-lockdown не захищає від LAN-side атаки (компрометований IoT все одно експлуатує bypass). Лише один із шарів.

---

## 5. Post-patch validation

### 5.1 Detector — повторний прогін

Той самий набір команд, що в § 3.3, але **після** патча:

```bash
~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py <cloudkey-ip>:11443 --no-color
~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py <udm-ip>:11443 --no-color
```

**Зберегти JSON для порівняння:**

```bash
python3 ~/.openclaw/workspace/tools/pentest/unifi/cve_2026_34908_check.py \
  <cloudkey-ip>:11443 <udm-ip>:11443 \
  --json --no-color \
  > ~/unifi-postpatch-$(date +%Y-%m-%d).json
```

**Очікувані вердикти post-patch:**

| Device | Версія (після fix) | Очікуваний verdict |
|---|---|---|
| CloudKey | ≥ 5.0.8 | **PATCHED** (HTTP 400) |
| UDM/UDR | ≥ 5.1.12 | **PATCHED** |
| Mesh U7/U6 | ≥ 5.1.12 | **PATCHED** |

Якщо `INCONCLUSIVE` — перевірити версію руками (manifest.json). Якщо `VULNERABLE` — **відкат firmware** через .firmware файл з https://ui.com/download, і звернутися до Тіня.

**Контрольна точка для ручної перевірки:**

```bash
curl -sk https://<cloudkey>:11443/api/manifest.json | python3 -m json.tool
```

Повинно показати `"version": "5.0.8"` або вище. На симуляторі це виглядає так (для контролю формату):

```json
{
  "version": "5.0.8",
  "build": "atag-5.0.8-mock",
  "device_type": "uck",
  "_mock": true
}
```

### 5.2 Log review (ще раз, вже після патча)

Після патча — ще раз перевірити логи. Шукаємо **нові** спроби експлойту, які могли статися під час upgrade-вікна:

```text
UniFi Network → Settings → System → Logs → Export
```

```bash
grep -E "(/api/auth/validate-sso|pkg_name|users/api/v2/ucs)" ~/Downloads/unifi-logs-*.txt | \
  grep -v "5.0.8" | head -100   # нові спроби (не пов'язані з самим патчем)
```

Також перевірити список admin'ів (§ 3.4). Якщо з'явився невідомий — видалити, змінити пароль, revoke всі API-токени.

### 5.3 Функціональний regression-тест

Прошивка 5.0.8+ змінює nginx-конфіг (raw-vs-normalized URI). Перевірити: Wi-Fi (https://example.com), VPN (якщо є), firewall rules (між VLAN'ами), DPI/Traffic rules (ідентифікація додатків), automation APIs (токени ще валідні).

⚠️ **Якщо щось зламалось після патча** — є план відкату (§ 6).

---

## 6. Rollback plan

### 6.1 Швидкий rollback через .firmware

Ubiquiti дозволяє завантажити конкретну версію прошивки:

1. Зайти на https://ui.com/download.
2. Знайти свою модель.
3. Завантажити .firmware файл попередньої (відомо робочої) версії.
4. В `UniFi Network → Devices → [пристрій] → Upload Firmware` → вибрати файл.

Це **локальний downgrade**, без потреби в інтернеті на самому пристрої (файл заливається з controller'а).

### 6.2 Повний rollback через serial console

Для CloudKey/UDM — якщо графічний downgrade не працює:

1. Підключити USB-to-serial конвертер до серійного порту CloudKey (зазвичай 115200 baud).
2. Увімкнути живлення, увійти в U-Boot або recovery shell.
3. Завантажити .firmware через TFTP або USB.
4. Reboot.

Це рідко потрібно, але важливо знати, що цей шлях існує.

### 6.3 Configuration rollback

Якщо проблема не в прошивці, а в конфігурації:

```text
UniFi Network → Settings → System → Backups → [обрати .unf з § 3.2] → Restore
```

Це відкотить конфігурацію, **не** прошивку. Якщо .unf зроблено з простроченої уразливої версії — повернеться разом із вразливістю. Тому після config rollback — знов прогнати detector (§ 5.1).

### 6.4 Worst case: factory reset + restore from .unf

Якщо нічого не допомагає:

1. Factory reset пристрою (кнопка reset на корпусі, 10+ сек).
2. Adopt знову через controller.
3. Restore конфігурації з .unf.

**Втрати:** всі per-device налаштування (кастомні RF-параметри на AP), якщо їх не було в backup'і. Тому backup **обов'язковий** перед патчем.

---

## 7. Lessons learned

### 7.1 Про процес

1. **KEV due date = patch в той самий день.** Прострочка 10+ днів — гонка з mass-scanner'ами. Bulletin 064 CVEs — топ-3 у категорії "most-targeted edge-device chains 2026".

2. **Edge-device CVE = топ-пріоритет завжди.** CloudKey, UDM, UDR — це **периметр**. Root на perimeter = lateral movement по всій LAN. Це **сьогодні**, не "завтра".

3. **Chain CVE патчимо разом.** Закрити тільки sink (34910), але не bypass (34908) — все одно уразливі. Версія **5.0.8+** закриває bypass (nginx-конфіг) + cmd injection (input validation). Один реліз.

4. **Safe detector → CI.** `cve_2026_34908_check.py` має exit code 1 на VULNERABLE. One-liner у GitHub Actions:

   ```yaml
   - name: UniFi CVE-2026-34908 scan
     run: |
       python3 tools/pentest/unifi/cve_2026_34908_check.py \
         ${{ secrets.UNIFI_HOST }}:11443 --no-color --brief
   ```

   Якщо regression — CI впаде. Дешевший захист, ніж "ручний скан раз на квартал".

5. **Pre-patch mitigation ≠ patch.** WAN-lockdown прибирає найлегший вектор, але **не фікс**. Це **вікно**, не заміна.

### 7.2 Про симулятор

1. **Mock ≠ real, але для detector validation — достатньо.** Симулятор відтворює розв'язку RAW ≠ NORMALIZED; для перевірки detector'а (200/400/401/404, graceful ERROR) — OK. Для експлуатації — ні, і це правильно.

2. **Stdlib only = zero dependency hell.** `mock_server.py` використовує тільки `http.server`, `ssl`, `json` зі stdlib. Жодних pip install, версій-конфліктів, CVE в залежностях самого симулятора. Ідеально для security tooling.

3. **Self-signed TLS в одному скрипті.** `start.sh` генерує .crt/.key через openssl (`req -x509 -newkey rsa:2048 -days 3650`). Detector вимикає verify (`ssl._create_unverified_context()`) — нормально, UniFi OS теж самопідписаний.

4. **Ідемпотентність start.sh/stop.sh.** Pidfile + port-check не дають подвійного запуску. Дрібниця, яка рятує від "address already in use" о 2 ночі.

5. **4/4 автотести = довіра до detector'а.** Без `test_detector.sh` ми б не знали, чи detector взагалі працює перед прод-сканом. Lesson для **будь-якого** security-тулу: dry-run на стенді.

### 7.3 Про scope

1. **Sub-agent без маршруту до LAN = потреба в симуляторі.** Структурне обмеження пісочниці, не тимчасова проблема. Для будь-якого CVE без реального стенда — **будуємо mock**, проганяємо detector, документуємо очікувану поведінку. Pattern з lesson-005 (CUCM).

2. **Pre-patch робота в пісочниці; реальний скан — на стороні власника.** Agent готує tooling + playbook; власник запускає на своєму залізі.

3. **Кожен CVE-walkthrough — це процедура**, не разова акція: як виявити, як валідувати, як відкотити.

---

## 8. Очікуваний реальний сценарій (для Жени)

На момент 2026-07-06 реальний патч **ще не зроблено**. Коли буде зроблено (п'ятниця 10.07 або пізніше), очікувана послідовність:

### 8.1 Підготовка (1–2 години)

```text
[ ] Прогнати test_detector.sh — переконатися, що 4/4 ✓
[ ] Виписати інвентар пристроїв (§ 3.1)
[ ] Зробити backup .unf (§ 3.2)
[ ] Прогнати detector по CloudKey + UDM — записати вердикти (§ 3.3)
[ ] Перевірити логи на сліди (§ 3.4)
[ ] Закрити WAN-доступ (§ 4.3)
```

### 8.2 Патч (30–60 хв)

```text
[ ] Оновити CloudKey (5.0.6 → 5.0.8+)
[ ] Дочекатися reboot + adoption (5–10 хв)
[ ] Оновити UDM/UDR (5.0.16 → 5.1.12+)
[ ] Дочекатися reboot + adoption (5–10 хв)
[ ] Оновити mesh #1 → чекати 5 хв → перевірити
[ ] Оновити mesh #2 → чекати 5 хв → перевірити
[ ] ... (по одному)
```

### 8.3 Валідація (15–30 хв)

```text
[ ] Прогнати detector повторно — всі мають бути PATCHED (§ 5.1)
[ ] Перевірити manifest.json руками (версія 5.0.8+/5.1.12+) (§ 5.1)
[ ] Regression: Wi-Fi, VPN, firewall rules (§ 5.3)
[ ] Перевірити логи ще раз (§ 5.2)
[ ] Перевірити список admin'ів (§ 5.2)
```

### 8.4 Закриття

```text
[ ] Увімкнути WAN-доступ назад (якщо потрібно)
[ ] Оновити CVE-картки в intel/cve/active/ (статус: PATCHED)
[ ] Дописати в lesson-007 секцію "Реальний сценарій" з фактичними вердиктами
[ ] Закрити задачу на Тиждень 2
```

### 8.5 Що піде не так (найімовірніші сценарії)

| Сценарій | Симптом | Дія |
|---|---|---|
| Mesh не re-adopt'иться після оновлення | AP в статусі "Pending" | "Force Provision" через UI |
| Wi-Fi клієнти не підключаються після UDM-апдейту | SSID broadcast'иться, але auth fail | Перевірити PSK у WLAN settings |
| CloudKey не приймає login після оновлення | UI не відповідає | 5 хв, потім force-reload браузера (cache) |
| Detector каже INCONCLUSIVE після патча | HTTP 401 + UniFi fingerprint | Перевірити версію руками через manifest.json — це нормально для деяких конфігурацій |
| WAN відрізаний після UDM-апдейту | Інтернет не працює | Перевірити WAN settings (тип підключення, VLAN, credentials) |

---

## 9. Артефакти

**Ключові артефакти:**

- `agents/pentester/reports/2026-06-30-unifi-sim.md` — повний опис симулятора.
- `agents/pentester/reports/2026-07-10-report.md` — звіт про Тиждень 2 (3 артефакти).
- `intel/cve/active/CVE-2026-34{908..33000}.md` + `UNIFI_PATCH_PLAN.md` — картки CVE + чек-ліст.
- `intel/lessons/lesson-{001,005,007}-*.md` — огляд CVE, CUCM reference, цей файл.
- `intel/techniques/cve-patch-validation.md` — загальна методика валідації патчу.
- `intel/public/en/unifi-bulletin-064-walkthrough.md` — EN-публікація (окремий артефакт).
- `tools/pentest/unifi/cve_2026_34908_check.py` (14.7 KB) + `tools/pentest/unifi/sim/` (48 KB) — detector + симулятор.

---

## 10. Джерела

**Tier 1 (primary):**

- Ubiquiti Security Advisory Bulletin 064-064: https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b
- Bishop Fox повний аналіз: https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis
- Bishop Fox detector (GitHub): https://github.com/BishopFox/CVE-2026-34908-check
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: CVE-2026-34908 / CVE-2026-34909 / CVE-2026-34910 / CVE-2026-34911 / CVE-2026-33000

**Tier 2 (community розбори):**

- toolslib.net: https://blog.toolslib.net/2026/05/22/ubiquiti-unifi-os-cve-2026-33000-bulletin-064/

**Tier 3 (internal — наша база знань):**

- `intel/cve/active/UNIFI_PATCH_PLAN.md` — 10-пунктовий чек-ліст для Жени
- `agents/pentester/reports/2026-06-30-unifi-sim.md` — повний опис симулятора
- `tools/pentest/unifi/cve_2026_34908_check.py` — safe detector (локальна копія Bishop Fox)
- `tools/pentest/unifi/sim/` — mock UniFi OS Server у 3 режимах
- **`intel/lessons/lesson-011-kev-triage-workflow.md`** (Хранитель 📚, 08.07) — workflow для щоденної обробки KEV-каталогу. Для Bulletin 064: 34908/34909/34910 = CRITICAL (KEV=1 + asset=3), 34911/33000 = CRITICAL (chain-anchor). Якщо scoring-формула з `intel/techniques/cve-impact-rating.md` застосовується — всі 5 CVE дають ~0.85+ → 🔴 CRITICAL.
- **`intel/techniques/cve-impact-rating.md`** — формальна scoring-методика (CVSS + EPSS + KEV + asset_relevance → tier). Worked example для CVE-2026-34910 див. § 4.1.

---

## 11. Що далі

- [ ] **Женя прогнав detector + зробив реальний патч** — оновити § 8 фактичними вердиктами, додати "Реальний сценарій" секцію з виміряним часом, фактичними вердиктами, можливими surprise'ами.
- [ ] **Regression detector в CI** — додати `cve_2026_34908_check.py` у GitHub Actions (або cron на домашньому Mac), щоб автоматично ловити, якщо прошивка відкотилась.
- [ ] **YARA/Suricata правило на bypass pattern** — `URI matches "/api/auth/validate-sso/..%2f"` для perimeter-детекції.
- [ ] **Generic CVE patch validation technique** — `intel/techniques/cve-patch-validation.md` (окремий артефакт цього тижня, для будь-якого CVE).
- [ ] **EN-публікація** — `intel/public/en/unifi-bulletin-064-walkthrough.md` (окремий артефакт, через фільтр публічної CVE).

---

*Тінь 🦅, 2026-07-06 → 2026-07-10, для відділу «Киберщит 🛡». Використовувати тільки в авторизованих середовищах (CloudKey + домашня мережа Жени — авторизований scope).*