---
layout: post
title: "# Lesson 006"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 006 — Semgrep Static Analysis on Our Tools

> **Автор:** code-sentinel 🛡
> **Дата:** 30.06.2026
> **Задача:** `agents/code-sentinel/reports/2026-06-29-task.md`
> **Сырой JSON:** `agents/code-sentinel/reports/semgrep-2026-06-30-raw.json`

## Цель

Прогнать static analysis на **наших собственных** Python-скриптах в `~/.openclaw/workspace/tools/` и посмотреть, не написали ли мы себе CVE до того, как кто-то их найдёт.

## Scope

Только **наш** код. Не сканировали third-party репы (`netexec`, `sherlock`, `maigret`, `holehe`, `theHarvester`, `spiderfoot`, `OsintGram`, `empire`, `burp`, `wifite2`, `unifi/` — там только наш detector, `jan-ai`, `gpt-sovits`, `photo-colorizer`, и т.д.) — это чужие проекты, их аудит отдельная задача со своим baseline'ом.

Просканировано **9 файлов** (118 + 112 + 91 + 101 + 144 + 316 + 165 + 204 + 370 = **1621 строк** нашего Python):

| Файл | LOC | Назначение |
|---|---:|---|
| `tools/intel/bleeping_fetch.py` | 118 | RSS-парсер для дайджеста |
| `tools/intel/digest_builder.py` | 112 | Сборка daily digest |
| `tools/intel/nvd_fetch.py` | 91 | Запросы в NVD API |
| `tools/osint/face-search.py` | 101 | DeepFace-обёртка |
| `tools/osint/phone-by-username.py` | 144 | maigret + regex по телефонам |
| `tools/osint/setup-apis.py` | 316 | macOS Keychain → SpiderFoot cfg |
| `tools/osint/tg-groups.py` | 165 | Telethon-клиент |
| `tools/osint/ua-sites.py` | 204 | Парсер UA-сайтов |
| `tools/pentest/unifi/cve_2026_34908_check.py` | 370 | Наш safe-detector из lesson-001 |

OSINT-скрипты, которые импортируют `subprocess`, проверены отдельно: везде `subprocess.call/run(check_output)` со **списком аргументов**, `shell=True` нигде не используется. Shell-injection-вектор отсутствует.

## Команда

```bash
semgrep scan \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --config p/python \
  --metrics off \
  --json --output semgrep-raw.json \
  --no-git-ignore \
  <список из 9 файлов>
```

- semgrep 1.167.0 (pipx, Python 3.14)
- Rulesets: **security-audit** (198 правил), **owasp-top-ten** (7 multilang), **python** (198 правил) → итого 205 активных правил на нашем scope
- 100% парсинг, 0 ошибок линтера
- **5 findings** (2 ERROR + 3 WARNING)

## Findings (raw)

| # | rule_id | file | line | severity | описание |
|---|---|---|---:|---|---|
| 1 | `python.lang.security.use-defused-xml.use-defused-xml` | `tools/intel/bleeping_fetch.py` | 7 | ERROR | `xml.etree.ElementTree` уязвим к XXE (CWE-611). Рекомендуется `defusedxml`. |
| 2 | `python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected` | `tools/intel/bleeping_fetch.py` | 34 | WARNING | URL в `urllib.request.urlopen` строится из переменной, а не литерала. Audit (B310). |
| 3 | `python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected` | `tools/intel/nvd_fetch.py` | 32 | WARNING | То же: URL в `urlopen` строится через `urllib.parse.urlencode()`. |
| 4 | `python.lang.security.unverified-ssl-context.unverified-ssl-context` | `tools/pentest/unifi/cve_2026_34908_check.py` | 145 | ERROR | `ssl._create_unverified_context()` — TLS без проверки сертификата (CWE-295). |
| 5 | `python.lang.security.audit.httpsconnection-detected.httpsconnection-detected` | `tools/pentest/unifi/cve_2026_34908_check.py` | 146 | WARNING | Используется `http.client.HTTPSConnection` напрямую — обход любых wrapper'ов. |

## False Positive Triage

### Finding #1 — XXE в `bleeping_fetch.py:7` → **РЕАЛЬНЫЙ (low-risk)**

**Где:** `import xml.etree.ElementTree as ET`.

**Реально ли:** Да, технически `ET.fromstring()` в стандартной библиотеке Python уязвим к XXE/billion-laughs при парсинге недоверенного XML. Семантика правильная.

**Но:** мы парсим только 4 хардкод-RSS-фида (BleepingComputer, Krebs, Hacker News, Schneier, SANS). Все — крупные trusted-источники, контролируемые нашими операторами. Если кто-то из них скомпрометирован — у нас проблемы посерьёзнее, чем XXE в RSS-ридере.

**Решение:** тем не менее, **defense-in-depth** стоит копейки. Замена:

```python
# было
import xml.etree.ElementTree as ET
root = ET.fromstring(content)

# стало
from defusedxml.ElementTree import fromstring
root = fromstring(content)
```

`defusedxml` — stdlib drop-in, ~30 КБ, никаких breaking changes. **Завести в следующий sprint.**

**Вердикт:** ✅ Легитимный finding, fix запланирован. Severity ERROR завышен для нашего контекста → по факту LOW (likelihood LOW × impact MEDIUM).

### Findings #2 и #3 — `dynamic-urllib-use-detected` → **FALSE POSITIVE**

**Где:**
- `bleeping_fetch.py:34` — `urllib.request.urlopen(req, ...)` где `req` собран из URL из dict-литерала `FEEDS = {...}`.
- `nvd_fetch.py:32` — `urllib.request.urlopen(req, ...)` где URL собран через `urllib.parse.urlencode(params)` с **только хардкод-ключами** (`pubStartDate`, `pubEndDate`, …), значения — `datetime.strftime(...)` от текущего времени на нашей машине.

**Почему FP:**
1. URL **не контролируется пользователем** ни в одном из случаев. В `bleeping_fetch` — литерал из `FEEDS`, в `nvd_fetch` — `urlencode` от `datetime`.
2. **file:// scheme concern неприменим:** `urlopen` в Python 3 по умолчанию принимает `http/https/file/ftp`. Да, `file://` теоретически проходит, но для этого нужно, чтобы URL **начинался с `file://`** — а у нас URL начинается с `https://` (хардкод) + `?query`. Семантика правила "URL из переменной → может быть file://" здесь не срабатывает: схема всегда https://, зашитая в `NVD_API = "https://..."` или `FEEDS["..."] = "https://..."`.
3. Семантика самого правила: "audit use" — confidence LOW, subcategory `audit`. Само правило помечено как **audit-grade**, не как exploitable finding.

**Вердикт:** ❌ False positive. Подавляем через `# nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected` с комментарием «URL built from hardcoded https:// base + urlencode of hardcoded keys» для будущих ревьюеров.

### Findings #4 и #5 — Unverified SSL + HTTPSConnection в UniFi-detector → **JUSTIFIED EXCEPTION**

**Где:** `cve_2026_34908_check.py:145-146`:

```python
ctx = ssl._create_unverified_context()
conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
```

**Почему не FP, но и не фиксится просто так:**
- UniFi CloudKey/UDM/UDR/U7 **по дефолту** идут с self-signed сертификатом. Если оставить `ssl.create_default_context()` — detector получит `ssl.CertificateError` на каждом живом устройстве.
- `http.client.HTTPSConnection` используется **намеренно**: `requests`/`urllib3` нормализуют `..%2f` в path перед отправкой, а нам нужно, чтобы payload **ушёл на сервер неизменным** (это суть CVE-2026-34908 — divergence raw vs normalized URI). Документировано в docstring функции `fetch()`:
  ```
  `http.client` sends the path verbatim, which is required so the literal
  "..%2f" survives to the server (libraries like `requests` would re-normalize
  or re-encode it).
  ```

**Hardening (для следующей версии detector):**
1. CLI-флаг `--verify-ssl` (default off — backward-compat) для случаев, когда пользователь знает CA-bundle устройства.
2. Возможность передать `--ca-bundle /path/to/ca.pem`.
3. Опциональный `--allow-insecure` дефолт для LAN-режима, но **warning в stderr** при каждом запуске.

**Вердикт:** ⚠️ Justified exception. Код-ревью должен подтверждать оба `# nosemgrep` инлайн-комментариями со ссылкой на CVE-2026-34908. Когда появится CA-режим, переходим на default-verified.

## Что мы НЕ нашли (что хорошо)

Просканировав 1621 строк, **не сработали** следующие классы правил, которые обычно находят в нашем типе кода:

- ❌ Hardcoded credentials / API keys (наши ключи живут в macOS Keychain через `security add-generic-password` — спасибо `setup-apis.py`).
- ❌ `shell=True` / `os.system` / `os.popen` (везде `subprocess` со списком аргументов).
- ❌ `eval` / `exec` (нет ни в одном из 9 файлов).
- ❌ `pickle.loads` от user input (используется только `json.loads`, который safe).
- ❌ SQL injection patterns (мы не используем raw SQL; там, где SQL есть — в third-party `spiderfoot`, не наш scope).
- ❌ Path traversal в `pathlib` (все пути либо литералы, либо `Path.expanduser("~/.openclaw/...")`).
- ❌ Weak crypto (`hashlib.md5`/`sha1` для security purposes) — не нашли. md5/sha1 используются только как etag-cache в `bleeping_fetch`-подобных, не как security primitive.
- ❌ `random.random()` для крипто (везде `secrets` или `os.urandom`, где нужно; либо non-security usage).

**Это положительный baseline**: наши скрипты написаны достаточно аккуратно. 5 findings из 1621 строк = 0.31% плотность, причём 3 из 5 — false positives или justified exceptions.

## Метрика

| Метрика | Значение |
|---|---|
| Файлов просканировано | 9 |
| Строк кода | 1621 |
| Rulesets | 3 (security-audit, owasp-top-ten, python) |
| Правил применено | 205 |
| Findings (raw) | 5 |
| Real (actionable) | 1 |
| False positives | 2 |
| Justified exceptions | 2 |
| Время скана | ~3 сек |
| Плотность findings | 0.31 / 100 LOC |

## Action items

| # | Действие | Владелец | ETA |
|---|---|---|---|
| 1 | Добавить `defusedxml` в `bleeping_fetch.py` | code-sentinel | 02.07 |
| 2 | Подавить #2 и #3 через `# nosemgrep` с inline-justification | code-sentinel | 30.06 |
| 3 | Задокументировать `# nosemgrep` для #4/#5 в UniFi-detector | code-sentinel | 30.06 |
| 4 | Добавить `--verify-ssl` + `--ca-bundle` в UniFi-detector v2 | Радар + code-sentinel | 11.07 |
| 5 | Включить semgrep в pre-commit hook (см. `intel/techniques/static-analysis.md`) | code-sentinel | 04.07 |

## Артефакты

- Сырой JSON: `agents/code-sentinel/reports/semgrep-2026-06-30-raw.json`
- Методичка по инструментам: `intel/techniques/static-analysis.md`
- Исходная задача: `agents/code-sentinel/reports/2026-06-29-task.md`
- Отчёт: `agents/code-sentinel/reports/2026-06-30-report.md`
- Связанный lesson: `intel/lessons/lesson-001-unifi-os-bulletin-064.md` (UniFi-detector)

## Связанные lessons

- **`intel/lessons/lesson-011-kev-triage-workflow.md`** (Хранитель 📚, 08.07) — про scoring CVE для приоритизации. В контексте semgrep: если semgrep/findings cross-reference'ит CVE (например, `python.lang.security.use-defused-xml` связан с CVE-2013-1669 XXE-class), то scoring-формула из lesson-011 + technique/cve-impact-rating даёт **tier** для каждого finding (REAL → CRITICAL/HIGH → fix в CI; FP/Exception → `# nosemgrep`).
- **`intel/techniques/cve-impact-rating.md`** — формальная scoring-методика (CVSS+EPSS+KEV+asset_relevance → tier).

## Уроки команды

1. **Правильный scope экономит время.** 2285 .py файлов vs. 9 наших = фокус на своём коде, а не на upstream-шуме.
2. **Semgrep severity ≠ наша severity.** ERROR в семантике правила (potential XXE) в нашем контексте (trusted RSS feeds) — LOW. Семантический triage обязателен.
3. **# nosemgrep с inline-justification** — допустимо, но каждое подавление должно иметь объяснение в 1 строку. Иначе через год никто не вспомнит, почему оно там.
4. **Detector-style код** (типа UniFi-check) — особый класс. Валится на SSL/UA-проверках по дизайну. Нужны CLI-флаги для hardening, не молчаливое подавление.
5. **Baseline метрики полезны.** 0.31% плотность findings — это baseline для следующих прогонов. Если в следующий раз будет 2% — значит, что-то поменялось в худшую сторону.
6. **Defense-in-depth даже для trusted источников.** XXE в RSS-ридере стоит 30 КБ зависимости и 0 риска. Делать.

## Источники

- Semgrep rulesets: <https://semgrep.dev/r/security-audit>, <https://semgrep.dev/r/owasp-top-ten>, <https://semgrep.dev/r/python>
- defusedxml: <https://github.com/tiran/defusedxml>
- Bandit B310 (urllib dynamic): <https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b310-urllib-urlopen>
- CWE-295 (Improper Certificate Validation): <https://cwe.mitre.org/data/definitions/295.html>
- CWE-611 (XXE): <https://cwe.mitre.org/data/definitions/611.html>
- CWE-939 (Custom URL Scheme): <https://cwe.mitre.org/data/definitions/939.html>

---

*Создано 30.06.2026 code-sentinel 🛡 в рамках задачи 30.06–06.07.*