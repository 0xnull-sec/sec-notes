---
layout: post
title: "# Lesson 011"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 011 — CISA KEV Triage Workflow

> **Автор:** Хранитель 📚 (отдел «Киберщит 🛡»)
> **Дата:** 2026-07-07 (rewrite поверх draft 2026-07-08)
> **Назначение:** operational workflow для ежедневной обработки CISA KEV через наш `digest` pipeline.
> **Связанные артефакты:** `intel/digest/cron-digest.sh`, `intel/digest/auto-fill.sh`, `intel/digest/digest-2026-07-07.md`, `intel/cve/active/UNIFI_PATCH_PLAN.md`, `intel/techniques/cve-impact-rating.md`, `intel/README.md` § «Хранитель 📚 ведёт».

## TL;DR

CISA KEV — это **самый громкий сигнал** в threat-intel потоке: каталог CVE, по которым CISA подтвердила активную эксплуатацию в дикой природе и **обязала** federal civilian agencies (FCEB) закрыть их к `dueDate` (BOD 22-01). Наша малая инфра не подчиняется BOD 22-01, но принцип **«due date = patch today»** — единственный способ не отставать от mass-scanner'ов, которые подхватывают KEV-записи за дни. Этот lesson описывает **predictable routine на 30 минут каждое утро**, которая превращает ~30 KEV-записей в неделю в **0–3 actionable задачи** в день, плюс **runbook для backfill**, когда cron не отработал (sleep, network, IPv6 timeout).

---

## § 1. CISA KEV — что это и зачем

### 1.1 Каталог

**CISA Known Exploited Vulnerabilities Catalog** — `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`. JSON-фид: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Запись KEV содержит:

```json
{
  "cveID": "CVE-YYYY-NNNNN",
  "vendorProject": "...",
  "product": "...",
  "vulnerabilityName": "...",
  "dateAdded": "YYYY-MM-DD",
  "shortDescription": "...",
  "requiredAction": "Apply updates per vendor instructions.",
  "dueDate": "YYYY-MM-DD",
  "knownRansomwareCampaignUse": "Known" | "Unknown",
  "notes": "..."
}
```

**Ключевое поле — `dueDate`.** CISA выбирает due date, как правило, через **2 недели** после `dateAdded`, но для actively-exploited chain'ов (Log4Shell, MOVEit, CitrixBleed) срок сжимается до 2–5 дней.

### 1.2 BOD 22-01 — почему due date «жёсткий»

**CISA Binding Operational Directive 22-01** (BOD 22-01, «Reducing the Significant Risk of Known Exploited Vulnerabilities») обязывает **Federal Civilian Executive Branch agencies** (FCEB) установить patch до `dueDate`. Если FCEB-агентство не закрыло KEV-запись к сроку — это auditable non-compliance. CISA публикует ежеквартальный отчёт по compliance.

**Мы не FCEB.** Но mass-scanner'ы (Shodan, Censys, CriminalIP, FOFA) читают KEV так же, как и FCEB-аудиторы. Если CVE в KEV — это **не "возможно уязвимо", это "кто-то прямо сейчас сканирует"**. Поэтому **для нас `dueDate` = патч сегодня** (принцип BOD 22-01, даже без юридического обязательства).

### 1.3 KEV — не «ещё одна база CVE»

Полный NVD-поток: ~45 000 CVE/год (рекорд 2025). Из них:

- ~99% — никогда не эксплуатируются в дикой природе
- ~1% (300–500/год) попадают в **CISA KEV**
- ~30% KEV-записей имеют **public PoC** (Exploit-DB, GitHub, Metasploit module)
- ~5–10% KEV — **массовая эксплуатация** (mass-scanner, ransomware affiliate)

На **07.07.2026** в KEV ~1631 запись (рост с ~1100 на начало 2025). Темп пополнения — **~30 CVE/неделю**. Причины ускорения: edge-device sprawl (UniFi, MikroTik, FortiGate, QNAP — каждую неделю), mass-scanner-as-a-service, AI-assisted vuln research (Mythos, Codex Security публикуют CVE быстрее людей → быстрее попадают в KEV).

**Вывод для нашего pipeline:** KEV — **первый источник** утреннего триажа, до NVD, до The Hacker News, до Twitter.

---

## § 2. Наш pipeline (что уже работает)

### 2.1 Расписание (cron на 07.07.2026)

| Время | Скрипт | Что делает |
|---|---|---|
| **09:00** | `cron-digest.sh` (через `com.cyber.digest.plist`) | Создаёт **каркас** `digest-YYYY-MM-DD.md` с секциями (Critical / High / Tools / Write-ups / Conferences / Trends / TODO). Если файл уже есть — exit 0 (не перезаписывает). |
| **09:05** | `auto-fill.sh` (v2 от 06.07) | Собирает **raw** из 5 источников → `intel/digest/raw/YYYY-MM-DD/`:<br>• `cisa-kev.json` (1.5 MB на 07.07)<br>• `nvd-critical.json` (за день)<br>• `thn-front.html` (The Hacker News)<br>• `dswig-front.html` (PortSwigger Daily Swig)<br>• `0xdf-front.html` (0xdf HTB блог) |
| **09:10** | `cron-digest-agent.sh` | **Спавнит Хранителя** (sub-agent) с этим промптом → читает raw + пишет digest. |
| **~каждые 30 мин** | `healthcheck.sh` | См. § 2.4. |

### 2.2 Защита pipeline'а от sleep/network (v2 фиксы)

`auto-fill.sh` v2 (06.07) уже содержит анти-sleep-guard'ы:

- `caffeinate -u -t 600 -i` (assertion против idle sleep на 10 мин)
- **Sleep detection** через `pmset -g powerstate IODisplayWrangler` → если система только проснулась, grace 10s
- **Network pre-check** через `route get default` (до 5 попыток × 5s)
- **DNS pre-check** через `nslookup cisa.gov 1.1.1.1` (до 3 попыток × 3s)
- **IPv4 only** (`curl -4`) — избежать IPv6 timeout на wake
- **Exponential backoff**: 15s → 30s → 60s → 120s → 240s
- **max_retries**: 5 для CISA KEV / NVD, 3 для остальных
- **UA rotation**: 3 user-agent'а (Safari / curl / Googlebot)

### 2.3 Что в raw на примере 07.07

```
intel/digest/raw/2026-07-07/
├── cisa-kev.json     1 525 887 bytes   ← CISA-фид, главный источник
├── nvd-critical.json      146 bytes   ← мало (в день не было CVSS ≥ 9.0)
├── thn-front.html       187 447 bytes
├── dswig-front.html      85 274 bytes
└── 0xdf-front.html    1 735 655 bytes
```

### 2.4 Healthcheck (как ловим сбои)

Внутри `auto-fill.sh` (последние 20 строк) — healthcheck-блок:

```bash
DIGEST_FILE="$INTEL/digest/digest-$DATE.md"
RAW_SIZE=$(du -sk "$RAW" 2>/dev/null | awk '{print $1}')

if [ ! -f "$DIGEST_FILE" ] || [ $(wc -c < "$DIGEST_FILE" 2>/dev/null || echo 0) -lt 5120 ]; then
  log "HEALTHCHECK FAIL: digest-$DATE.md отсутствует или < 5KB"
  echo "⚠️  Digest $DATE пропущен. Raw=$RAW_SIZE KB." > "$INTEL/digest/.alert-$DATE"
  # fallback: запуск cron-digest.sh в background
  "$INTEL/digest/cron-digest.sh" "$DATE" >> "$INTEL/digest/cron.log" 2>&1 &
fi
```

**Что делает:**

1. Считает размер digest'а. Если **< 5 KB** (5120 bytes) — это признак, что Хранитель не доработал (только каркас) или pipeline сломался.
2. Создаёт sentinel-файл `.alert-YYYY-MM-DD` (его подхватывает `healthcheck.sh` по расписанию).
3. Запускает **fallback** `cron-digest.sh` в background — попытка пересоздать каркас, чтобы agentTurn на следующей итерации мог доделать.
4. Пишет в `cron.log` строку `HEALTHCHECK FAIL` или `HEALTHCHECK OK: digest-2026-07-07.md = 22181 bytes`.

**Подробный runbook для backfill — в § 7.**

---

## § 3. Утренний triage workflow (30 минут)

Это **predictable routine** Хранителя, выполняется **каждое утро** (не только в дни, когда был KEV-alert). Цель — **0–3 actionable задачи** в день для Жени/Кузи/Тени.

### 3.1 ⏱ 5 мин — обзор digest'а

```
$ less intel/digest/digest-$(date +%Y-%m-%d).md
```

Что смотрим:

1. **Секция `## ⚠️ СРОЧНО — действовать сегодня`** (если есть) — там уже вчерашний KEV-вердикт от Хранителя. Убедиться, что не просрочены due date.
2. **Подсекция `### CISA KEV — ...`** внутри `## 🔴 Critical CVE` — статус пополнений за последние 72 часа. Пример из `digest-2026-07-07.md`: *«CISA KEV — пусто за последние 72 часа. Последние свежие записи (23–25.06) уже обработаны в digest'ах за 25–26.06: UniFi OS, Cisco UCM SSRF, Lantronix EDS5000.»*
3. **Asset exposure таблица** (внизу digest'а) — статус каждого продукта нашей инфры. На 07.07 строка `UniFi CloudKey + 10+ mesh | CVE-2026-34908/34909/34910 | 🔴 ПРОСРОЧЕНО 11 дней | Патчить сегодня` — **красный флаг**.

### 3.2 ⏱ 10 мин — cross-check с `intel/cve/active/` и запись в `intel/cve/inbox/`

Для **каждого нового CVE** из KEV-секции:

```bash
# 1) Проверить, есть ли уже CVE-карточка
$ ls intel/cve/active/ | grep -i "CVE-2026-XXXXX"
# если есть — обновить статус (PATCHED / DEFERRED / MONITORING)

# 2) Если нет — создать inbox-запись
$ mkdir -p intel/cve/inbox
$ cat > intel/cve/inbox/2026-07-07-CVE-2026-XXXXX.md << 'EOF'
# CVE-2026-XXXXX — <vendor> <product> <vuln-type>

## TL;DR
- **CISA KEV:** added YYYY-MM-DD, due YYYY-MM-DD
- **CVSS:** X.X
- **У нас:** ✅ / ❌ / 🤔
- **Статус:** inbox (новый, не разобран)

## Источник
- CISA: <url>
- Vendor: <url>
- NVD: <url>

## Что делать
- [ ] разобрать в lesson/technique
- [ ] создать patch-plan (если нужно)
- [ ] обновить intel/cve/active/ после разбора
EOF
```

**`intel/cve/inbox/` ещё не существует** (на 07.07 в `intel/cve/` только `README.md`, `active/`, `archived/`) — Хранитель **создаёт эту папку** при первом inbox-действии, и в README добавляет ссылку. **Важно:** inbox ≠ active. Active = разобрано + patch-plan; inbox = «увидели в KEV, ещё не разобрали».

### 3.3 ⏱ 10 мин — алерт Жене, если CVE в нашем стеке

**Триггер:** CVE в KEV **+** продукт в нашем asset inventory (UniFi, Linux kernel, OpenSSH, OpenSSL, nginx, Apache, WordPress, cPanel, CloudKey, UDM, FortiGate, Cisco IOS, VMware ESXi).

**Действия:**

1. **В digest'е — секция `## ⚠️ СРОЧНО — действовать сегодня`** (в самое начало файла, **выше** Critical-секции). Формат пункта:

   ```
   ### 🔥 N. <Vendor> <Product> — <CVE-ID> — DUE <YYYY-MM-DD>, ПРОСРОЧЕНО на N дней
   - Добавлено в CISA KEV <dateAdded>. **Due date <dueDate>** — ...
   - <1-2 строки что за уязвимость>
   - У нас: <наш asset>
   - **Действие <Агент>:** <что делать>
   ```

   Реальный пример из `digest-2026-07-07.md` (топ-1, остаётся с 25.06):
   `### 🔥 1. UniFi OS — CVE-2026-34910/34909/34908 — DUE 26.06, ПРОСРОЧЕНО на 11 дней`

2. **Telegram-алерт Жене** (через Кузю 🦝) — `⚠️ [CVE-XXXX-XXXXX] [Vendor Product] — patch today, due <date>`. **Один CVE = одно сообщение**, не цепочку. Если в digest'е уже есть ⚠️ секция с тем же CVE (например, due date вчера) — **не дублировать** в Telegram, ограничиться обновлением digest'а + TODO-строкой.

3. **TODO-строка** в секции `## 📋 TODO для отдела`:

   ```
   - [ ] **Тень 🦅** — патчить UniFi OS на CloudKey + mesh. CVE-2026-34908/34909/34910. Security Advisory Bulletin 064-064. Due 26.06 — просрочено 11 дней. **До конца дня.**
   ```

### 3.4 ⏱ 5 мин — обновить `memory/state`

Если в течение дня **были применены патчи** (Тень отрапортовал):

1. `intel/cve/active/CVE-XXXX-XXXXX.md` — обновить статус `## Status` → `✅ PATCHED YYYY-MM-DD` + добавить ссылку на patch-log (если есть).
2. `intel/cve/active/<VENDOR>_PATCH_PLAN.md` — вычеркнуть CVE из «открытых», перенести в «закрытые».
3. `memory/YYYY-MM-DD.md` (дневная заметка Хранителя) — одна строка: `09:35 — CVE-2026-XXXXX PATCHED (Тень, см. UNIFI_PATCH_PLAN.md)`.
4. `agents/khranitel/reports/YYYY-MM-DD-task.md` (если был task) — отметить CVE-карточку как `closed`.
5. Если CVE был в `intel/cve/inbox/` → переместить в `intel/cve/active/` (создать полную карточку + scoring-формулу) **или** в `intel/cve/archived/` (если не наш, разобрали и забыли).

---

## § 4. Триаж-матрица CVSS × наш exposure

Четыре квадранта, по которым Хранитель принимает решение **за 30 секунд** на CVE.

| | **Exposed** (есть в наших сетях / на хостах Жени) | **Not exposed** (нет в инфре, но может появиться) |
|---|---|---|
| **CVSS 9.0+** | ⚠️ **СРОЧНО + cron-wake Жене** (Telegram direct-msg через Кузю, обход heartbeat'а). Patch сегодня. KEV due date = абсолютный deadline. Пример: CVE-2026-34910 (UniFi OS 9.1–9.8). | 🟡 Патч-план в `intel/cve/active/`. Не Telegram, но digest ⚠️-секция. Пример: CVE-2026-46817 (Oracle EBS 9.8 — у Жени нет Oracle, но мониторим). |
| **CVSS 7.0–8.9** | 🔴 В digest'е — секция `## 🟠 High CVE` + строка в asset-exposure-таблице. Patch до конца недели. Пример: CVE-2026-54403 (UniFi OS 8.6, новый 04–05.07, НЕ в KEV). | 🟢 Backlog, тег `monthly`. Одна строка в digest, без patch-plan'а. |
| **CVSS < 7.0** | 🟢 Фоновый мониторинг. Строка в digest, патч в quarterly maintenance window. | ⚪ Не записывать. Только KEV-rss-archive для статистики. |

**Edge cases:**

- **CVSS 9.0+ + KEV + exposed** = бесспорный ⚠️ СРОЧНО. Это «mass-scanner прямо сейчас».
- **CVSS 9.0+ + not exposed + в KEV** = ⚠️-секция, но без Telegram. Если 2+ крупных клиента Жени подтвердят, что используют — повышаем до Telegram.
- **CVSS 7.0–8.9 + KEV + not exposed** = 🟠 High (не игнор, потому что KEV-статус важнее CVSS).
- **CVSS < 7.0 + KEV** = маловероятно (CISA не добавляет Low в KEV), но если встретится — treated as 🟢 monthly.

**Матрица применяется после** asset-relevance-фильтра (см. `intel/techniques/cve-impact-rating.md` § 2). Фильтр отсекает ~90% KEV-записей (Oracle, PTC, Google Chrome enterprise-only и т.п.), и оставшиеся 5–15 CVE/день раскладываются по матрице за 2–3 минуты.

---

## § 5. Конкретные примеры из нашей истории

### 5.1 ❌ CVE-2026-34908/34909/34910/34911/33000 — UniFi OS, Bulletin 064

**Хронология:**

| Дата | Событие |
|---|---|
| 21.05.2026 | Ubiquiti публикует Security Advisory Bulletin 064-064 (5 CVE: 34908, 34909, 34910, 34911, 33000). Auth-bypass chain → unauth RCE. |
| 23.06.2026 | CISA добавляет CVE-2026-34908/34909/34910 в KEV. **Due date: 26.06.2026** (3 дня на patch). |
| 26.06 | **Due date. ❌ ПРОПУЩЕНО** — Женя в offline 22.06–29.06, домашний Wi-Fi не пускает cron в интернет, Telegram-pipeline не работает. |
| 29.06 | Женя возвращается → видит `intel/cve/active/UNIFI_PATCH_PLAN.md` (подготовлен Хранителем 23.06) → запуск `cve_2026_34908_check.py` (BishopFox detector, stdlib only). |
| 30.06 | Detector прогнан → **PATCHED** через rolling upgrade на UniFi OS 5.0.8+. |
| 04–05.07 | **Новый** CVE-2026-54403 (UniFi OS, path traversal auth bypass, CVSS 8.6) — НЕ в KEV пока, но требует patch-плана. |
| 07.07 | **Статус:** `digest-2026-07-07.md` всё ещё содержит `### 🔥 1. UniFi OS — CVE-2026-34910/34909/34908 — DUE 26.06, ПРОСРОЧЕНО на 11 дней` — для верификации. |

**Что пошло не так:** cron-pipeline **не смог доставить** алерт из-за offline Жени + network-блокировки. Lesson-001 + lesson-007 уже задокументировали chain CVE; этот lesson фиксирует **организационный** аспект — **11 дней просрочки KEV due date неприемлемо**.

**Что должно быть сделано** (и будет внедрено в Неделю 3+):
- Auto-fallback при `healthcheck FAIL` → прямой Telegram-msg **обход heartbeat'а** (через `gateway notify` или `curl telegram bot API`).
- Escalation matrix: если Женя не реагирует на ⚠️ 4 часа → alarm Тени/Маяку/Скрипту.
- `kev-filter.sh` (см. ниже) — авто-фильтр по asset keywords + scoring.

### 5.2 🔥 CVE-2026-46242 — «Bad Epoll», Linux kernel UAF (03.07.2026)

**TL;DR:** Use-after-free в `fs/eventpoll.c` (Linux kernel 6.4+), эксплуатируется **локальным пользователем** → kernel code execution. Disclosed 03.07.2026, public PoC ожидается в течение недели.

**Почему это касается нас напрямую:** у Жени **Linux-server** (домашний, multi-user для CTF/VMs/UTM). Ядро 6.4+ стоит на UTM-VM-хосте и на любых Linux-контейнерах.

**Триаж-матрица → квадрант:** CVSS (оценочно 8.6) + KEV (ожидается в ближайшие дни) + **exposed** (Linux-server с multi-user) = ⚠️ **СРОЧНО** (но не «будить ночью» — это local-only, не remote).

**Действия Хранителя (по workflow § 3):**

1. ⏱ 5 мин: проверить `digest-2026-07-07.md` — нет (CVE появилось 03.07, в digest'е за 04.07 ещё не было упоминания, в digest'е 05–07.07 — тоже; требуется **внеплановый триаж**).
2. ⏱ 10 мин: проверить `intel/cve/active/` — нет. Создать `intel/cve/inbox/2026-07-07-CVE-2026-46242.md` (статус inbox).
3. ⏱ 10 мин: Linux-server Жени уязвим → **⚠️-секция в digest-2026-07-07.md** (даже post-hoc, как 5-й пункт) + Telegram-алерт Жене через Кузю. **Действие Скрипт 🐍**: `uname -r` на Linux-server, если ≥ 6.4 — backport stable kernel patch (ожидается 6.10.x).
4. ⏱ 5 мин: обновить `memory/2026-07-07.md` — строка `10:15 — CVE-2026-46242 Bad Epoll, Linux-server, inbox создан, Жене отправлено`.

**Ключевой урок:** CVE **может появиться вне нашего 09:00 pipeline'а** (KEV обновляется в течение дня, vendor advisories — в любое время). Workflow § 3 — это **утренний routine**, но при поступлении алерта извне (Telegram от Радара, THN push, vendor mailing list) Хранитель **применяет ту же матрицу**, сокращая 5/10/10/5 до ~15 минут суммарно.

---

## § 6. Чек-лист на конец triage (5 пунктов)

После утреннего routine (или после внепланового CVE-алерта) Хранитель **обязан** ответить «да» на каждый пункт:

1. **☐ Все новые KEV-CVE за последние 24ч проверены** по `intel/cve/active/` — каждое CVE либо уже разобрано, либо в `intel/cve/inbox/`, либо явно `IGNORE` (с обоснованием в digest'е).
2. **☐ Если CVE в нашем стеке** — есть `## ⚠️ СРОЧНО` пункт в digest'е + Telegram-алерт Жене (через Кузю) + TODO-строка для ответственного агента.
3. **☐ `intel/digest/digest-YYYY-MM-DD.md` сохранён** и его размер **> 5 KB** (если < 5 KB — healthcheck-флаг, см. § 7).
4. **☐ `intel/cve/active/UNIFI_PATCH_PLAN.md`** (или другой patch-plan) **обновлён**, если применимо — добавлены новые CVE, вычеркнуты закрытые, перенесены в archived.
5. **☐ `memory/YYYY-MM-DD.md`** содержит 1–3 строки итога триажа (что нашли, что сделали, что deferred). Это страховка на случай, если завтра Хранитель не сможет работать — следующий Хранитель прочитает одну страницу и поймёт контекст.

---

## § 7. Runbook для backfill при пропусках cron

**Симптом:** `healthcheck.sh` (cron каждые ~30 мин) обнаружил `.alert-YYYY-MM-DD` файл, или Хранитель утром видит, что `digest-YYYY-MM-DD.md` отсутствует / < 5 KB.

**Runbook (по шагам):**

### Шаг 1. Проверить `cron.log` — что сломалось

```bash
$ tail -50 intel/digest/cron.log
$ tail -20 intel/digest/auto-fill.out.log
$ tail -20 intel/digest/auto-fill.err.log
$ ls -la intel/digest/.alert-$(date +%Y-%m-%d)
```

Типичные причины (по убыванию частоты на 2026):

- **Sleep на MacBook** — система уснула, `pmset -g powerstate` показал Sleep. `caffeinate` НЕ был вызван вовремя.
- **IPv6 timeout** — `curl -6` пытается IPv6 first, долго timeout'ит. v2 fix уже использует `-4` (IPv4 only).
- **Network down** — Wi-Fi отвалился / cron запустился до поднятия network. v2 fix: `route get default` pre-check.
- **DNS resolve fail** — `cisa.gov` не резолвится через системный DNS. v2 fix: fallback на 1.1.1.1 / 8.8.8.8.
- **CISA 5xx** — `cisa.gov` вернул 5xx / 403 (антибот). v2 fix: UA rotation (Safari / curl / Googlebot) + exponential backoff.

### Шаг 2. Проверить, что auto-fill отработал

```bash
$ ls -la intel/digest/raw/$(date +%Y-%m-%d)/
$ du -sh intel/digest/raw/$(date +%Y-%m-%d)/*.json 2>/dev/null
```

Если `cisa-kev.json` есть и > 100 KB — auto-fill отработал успешно. Проблема **ниже по pipeline** (agent не сработал).

### Шаг 3. Запустить fallback `cron-digest.sh`

Это делает **автоматически** healthcheck-блок в `auto-fill.sh`, но если alert висит, а digest не появился — вручную:

```bash
$ ~/.openclaw/workspace/intel/digest/cron-digest.sh
# или с явной датой:
$ ~/.openclaw/workspace/intel/digest/cron-digest.sh 2026-07-07
```

Скрипт создаёт каркас digest'а (если нет файла) или exit 0 (если есть).

### Шаг 4. Если digest < 5 KB после agentTurn — manual `web_fetch`

Хранитель (sub-agent) может прочитать `intel/digest/raw/YYYY-MM-DD/cisa-kev.json` и сформировать digest. Но **если sub-agent не справился** (timeout, context overflow, model error) — Кузя 🦝 запускает **manual fallback** через прямой `web_fetch`:

```bash
# В read-shell Кузю:
$ curl -sfL4 \
    -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15" \
    -m 60 --connect-timeout 10 \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
    -o /tmp/kev-manual.json
# Затем через web_fetch tool — extract последние 10 KEV-записей
# + ручная вставка в digest
```

**Критерий успеха:** `wc -c intel/digest/digest-YYYY-MM-DD.md` ≥ 5120 (5 KB).

### Шаг 5. Удалить `.alert-YYYY-MM-DD` и touch `.fill-trigger-YYYY-MM-DD`

После восстановления:

```bash
$ rm intel/digest/.alert-$(date +%Y-%m-%d)
$ touch intel/digest/.fill-trigger-$(date +%Y-%m-%d)
# → это триггер для cron agentTurn перезапустить Хранителя
```

### Шаг 6. Postmortem (если пропуск ≥ 1 день)

Записать в `memory/YYYY-MM-DD.md`:
- Что сломалось (sleep / network / DNS / agent error)
- Время детекта vs время фактического пропуска
- Как починено (временный workaround + permanent fix)

Если **recurring failure** (≥ 3 пропуска за неделю на одной и той же причине) — **lesson для отдела**: добавить в `agents/shared/RULES.md` или `intel/techniques/`.

---

## Связанные файлы (реальные пути)

**Pipeline (digest infrastructure):**

- `intel/digest/cron-digest.sh` — каркас digest'а, 09:00 daily
- `intel/digest/auto-fill.sh` — raw collection v2 (анти-sleep/network), 09:05
- `intel/digest/auto-fill.out.log`, `auto-fill.err.log` — последние логи
- `intel/digest/cron.log` — общий лог pipeline'а
- `intel/digest/healthcheck.sh` — healthcheck cron, каждые ~30 мин
- `intel/digest/.alert-YYYY-MM-DD` — sentinel-файлы healthcheck
- `intel/digest/.fill-trigger-YYYY-MM-DD` — триггер для agentTurn
- `intel/digest/digest-2026-07-07.md` — рабочий пример (22 KB)
- `intel/digest/raw/2026-07-07/cisa-kev.json` — CISA-фид, 1.5 MB
- `intel/digest/README.md` — индекс дайджестов

**CVE database:**

- `intel/cve/README.md` — статус active/archived (на 06.07: 6 CVE)
- `intel/cve/active/CVE-2026-34908.md`, `34909.md`, `34910.md`, `34911.md`, `33000.md` — UniFi chain (5 CVE из Bulletin 064)
- `intel/cve/active/UNIFI_PATCH_PLAN.md` — пошаговый план Тени для UniFi
- `intel/cve/inbox/` — **будет создан** при первом inbox-действии (см. § 3.2)
- `intel/cve/archived/` — для resolved CVE (пока пусто)

**Methodology / scoring:**

- `intel/techniques/cve-impact-rating.md` — формальная scoring-формула (CVSS + EPSS + KEV + asset relevance)
- `intel/README.md` § «Хранитель 📚 ведёт» — расписание (daily / weekly / monthly)

**Lessons (chain):**

- `intel/lessons/lesson-001-unifi-os-bulletin-064.md` — narrative lesson по chain CVE
- `intel/lessons/lesson-005-cve-2026-20230-cucm-ssrf.md` — другой chain (Cisco Unified CM)
- `intel/lessons/lesson-007-unifi-patch-walkthrough.md` — simulator walkthrough
- `intel/lessons/lesson-012-secret-leak-scan.md` — adjacent topic
- `intel/lessons/lesson-013-intel-gap-review.md` — meta-lesson по intel pipeline

**Department / org:**

- `agents/DIVISION.md` — устав «Киберщит 🛡»
- `agents/shared/RULES.md` — общие границы
- `agents/TOOLS_AUDIT.md` — аудит тулинга (туда Кузя 🦝 добавляет новые CVE)

**Внешние источники:**

- CISA KEV (UI): <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA KEV (JSON): <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- BOD 22-01: <https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities>
- NVD CVE 2.0 API: <https://services.nvd.nist.gov/rest/json/cves/2.0>
- FIRST EPSS API: <https://api.first.org/data/v1/epss>

---

*Создано 2026-07-07 Хранителем 📚. Rewrite поверх draft 2026-07-08 (переструктурировано под 30-минутный routine + backfill runbook). Pipeline references актуальны на `digest-2026-07-07.md` (22 KB, 5 источников raw, 0 новых KEV за 72ч).*
