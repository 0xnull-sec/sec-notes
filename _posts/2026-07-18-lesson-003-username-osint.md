---
layout: post
title: "# Lesson 003"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 003 — Username-OSINT Walkthrough (sherlock × maigret × holehe × h8mail)

> **Третий урок отдела «Киберщит».** Прогон 5 разных username через 4 OSINT-инструмента.
> Автор: Радар 📡 · Дата: 30.06.2026 · Задача: `agents/radar/reports/2026-06-29-task.md`

## Что делали

Взяли **5 разных username** разной "шумности" и прогнали через **четыре** инструмента:

| # | Username | Почему такой |
|---|----------|--------------|
| 1 | `pentester_demo` | Явный self-describing handle — обычно dry-username |
| 2 | `security_owl` | Концепт-имя (тема + сущ.), должно много шуметь |
| 3 | `osint_raccoon` | Тематический (osint + mascot) |
| 4 | `johndoe2026` | Максимально generic — должно вылезти везде, где есть префикс-фильтр |
| 5 | `kuzya_the_raccoon` | Узнаваемое имя (Кузя 🦝) + тематический суффикс |

Email-паттерны для `holehe` / `h8mail`:

- `pentester_demo@gmail.com`
- `security_owl@protonmail.com` — намеренная вариация (proton — не gmail)
- `osint_raccoon@gmail.com`
- `johndoe2026@gmail.com`
- `kuzya_the_raccoon@gmail.com`

## Tools

| Tool | Версия | Что делает | Сколько сайтов |
|------|--------|------------|---------------:|
| sherlock | 0.16.1 | HTTP HEAD/GET по username-URL, маркирует Claimed | ~400 |
| maigret | 0.6.1 | Расширенный sherlock + извлечение profile IDs/avatars | ~3166 (default top 509) |
| holehe | latest | Проверка email через forgot-password на 120+ сайтах | 123 active |
| h8mail | 2.5.6 | Email leak aggregator (HIBP, leak-lookup, dehashed…) | по ключам |

Запуск через единый wrapper:

```bash
~/.openclaw/workspace/tools/osint/run.sh {sherlock|maigret|holehe|h8mail} <args>
```

## Команды

```bash
# Sherlock (CSV + folder per username)
run.sh sherlock pentester_demo --timeout 15 --no-color --print-found \
  --csv --folderoutput raw/sherlock/pentester_demo
# ... × 5 username

# Maigret (txt report per username)
run.sh maigret pentester_demo --timeout 20 --no-color --no-progressbar \
  --folderoutput raw/maigret/pentester_demo -T
# ... × 5

# Holehe (email -> which sites accept forgot-password)
run.sh holehe --no-color --timeout 20 pentester_demo@gmail.com \
  > raw/holehe/pentester_demo_gmail.com.txt
# ... × 5

# h8mail (leak check)
run.sh h8mail -t pentester_demo@gmail.com --hide \
  -o raw/holehe/h8mail_pentester_demo_gmail.com.txt
# ... × 5
```

Полные артефакты:

- `agents/radar/reports/raw/sherlock/<u>/<u>.csv` — 5 файлов
- `agents/radar/reports/raw/maigret/<u>/report_<u>.txt` — 5 файлов
- `agents/radar/reports/raw/holehe/<e>.txt` — 10 файлов (5 holehe + 5 h8mail)
- `agents/radar/reports/raw/results.json` — агрегация
- `agents/radar/reports/raw/scan-summary.md` — итоговая сводка
- `agents/radar/reports/raw/commands-run.md` — команды + сокращённый вывод

## Findings — таблица

| Username | sherlock | maigret | **unique** | holehe `[+]` | h8mail leaks | top-3 (по приоритету) |
|----------|---------:|--------:|-----------:|-------------:|-------------:|----------------------|
| `pentester_demo` | 4 | 3 | **6** | 0 / 69 RL | 0 | TikTok · Xing · Mastodon |
| `security_owl` | 8 | 10 | **16** | 1 (protonmail.ch) | 0 | Twitter · YouTube · Xing |
| `osint_raccoon` | 4 | 2 | **5** | 0 / 71 RL | 0 | Mastodon · Odysee · TikTok |
| `johndoe2026` | 40 | 49 | **69** | 1 (spotify.com) | 0 | GitHub · HuggingFace · Twitter |
| `kuzya_the_raccoon` | 4 | 4 | **7** | 1 (naturabuy.fr) | 0 | Xing · Instagram · Mastodon |

`unique` = дедупликация URL после нормализации (`host + path`, без `www.`).
`holehe [+] / RL` = подтверждённых регистраций через forgot-password / rate-limit-ответов.

### Top-3 развёрнуто

**`pentester_demo` (low-noise, self-describing)**
- `https://mastodon.cloud/@pentester_demo` — Fediverse handle
- `https://www.tiktok.com/@pentester_demo` — TikTok
- `https://odysee.com/@pentester_demo` — Odysee
- `https://www.xing.com/profile/pentester_demo` — Xing (LinkedIn-DE)

**`security_owl` (mid-noise, концепт-имя)**
- `https://twitter.com/security_owl` — main presence
- `https://www.youtube.com/@security_owl/about` — YouTube
- `https://www.xing.com/profile/security_owl` — Xing
- `https://scholar.google.com/scholar?q=security_owl` — Google Scholar (search, не profile)

**`osint_raccoon` (low-noise)**
- `https://mastodon.cloud/@osint_raccoon` — Mastodon
- `https://odysee.com/@osint_raccoon` — Odysee
- `https://www.tiktok.com/@osint_raccoon` — TikTok

**`johndoe2026` (high-noise, 67+ уникальных сайтов)**
- `https://github.com/johndoe2026` — GitHub (developer surface)
- `https://huggingface.co/johndoe2026` — HuggingFace
- `https://twitter.com/johndoe2026` — Twitter
- `https://soundcloud.com/johndoe2026` — SoundCloud
- `https://t.me/johndoe2026` — Telegram
- `https://substack.com/@johndoe2026` — Substack (публикации)
- `https://api.mojang.com/users/profiles/minecraft/johndoe2026` — Minecraft

**`kuzya_the_raccoon` (low-noise, узнаваемый)**
- `https://www.xing.com/profile/kuzya_the_raccoon` — Xing
- `https://www.instagram.com/kuzya_the_raccoon/` — Instagram
- `https://mastodon.cloud/@kuzya_the_raccoon` — Mastodon

## Email leaks (через holehe "email used" сигналы)

| Email | holehe `[+]` | Заметка |
|-------|-------------:|---------|
| `pentester_demo@gmail.com` | 0 | ~70 ответов rate-limited |
| `security_owl@protonmail.com` | **1** | `protonmail.ch` — сам провайдер, account creation `2025-01-18 14:14:51` |
| `osint_raccoon@gmail.com` | 0 | ~71 rate-limited |
| `johndoe2026@gmail.com` | **1** | `spotify.com` |
| `kuzya_the_raccoon@gmail.com` | **1** | `naturabuy.fr` |

**h8mail** по всем 5 — `Not Compromised` (leak-lookup public API, без HIBP/dehashed ключей).

## False positives (что sherlock/maigret помечают, но не подтверждает реальный аккаунт)

| Сайт | Что происходит | Как верифицировать |
|------|----------------|--------------------|
| `venmo.com` | Возвращает 403 на `/u/<name>` для всех запросов, маркирует `Claimed` | `curl -L -A "Mozilla/5.0" https://venmo.com/u/<name>` + парсить `User not found` |
| `discord.com` | Возвращает 200 на `/` независимо от username, sherlock считает Claimed | Нет публичного lookup — только invite links |
| `archiveofourown.org/users/<name>` | Возвращает 200 (Work-Listing page может отдаваться и для пустого юзера) | Проверить наличие `works` count в HTML |
| `wikipedia.org/wiki/Special:CentralAuth/<name>` | 200 на missing pages с сообщением "There is no global account" | Парсить `centralauth-not-existent` |
| `xboxgamertag.com/search/<name>` | Search-страница всегда 200 | Парсить `Found`/`No results` |
| `wikipedia.org/wiki/User:<name>` | User-page может существовать, но быть пустой | Парсить `mw-userpage-userdoesnotexist` |

**Вывод:** sherlock/maigret дают **.top-кандидатов**, не верифицированный список. Для OSINT-отчёта **обязательно** ручная верификация top-5 URL через fetch HTML.

## Rate limits / антибот

Из holehe (123 сайта):

| Тип ответа | Count (avg) | Что это |
|------------|------------:|---------|
| `[+]` Email used | 0–2 | Реальная регистрация |
| `[-]` Email not used | ~43 | Стандартный "нет такого" |
| `[x]` Rate limit | ~70 | Cloudflare / Akamai / кастомный 429 |
| `[!]` Error | <1 | Таймаут, парс-ошибка |

**Итог:** ~57% сайтов из holehe-базы упираются в rate-limit. Если запустить с `--only-used` (по умолчанию off), показывает только `[+]`, что **экономит трафик**.

Maigret: `7.47%` "Just a moment: bot redirect challenge" — Cloudflare interstitial.

## GDPR / этика (PII)

- **Не логируем** PII (email, телефон, реальное имя) в `agents/radar/reports/` без явного запроса от Жени.
- Email-паттерны в walkthrough — **синтетические** (`username@gmail.com`), не реальные адреса целей.
- h8mail результаты `Not Compromised` — это сигнал "не утекли в публичные базы", не доказательство "цель не скомпрометирована".
- Sherlock/maigret делают **только публичные** HTTP-запросы, не обходят auth — не нарушают CFAA/UK CMA.

## Уроки команды

1. **Объединять sherlock + maigret** — они комплементарны. Sherlock: 4/8/4/40/4, maigret: 3/10/2/49/4. В сумме уникальных: 6/16/5/69/7. Ни один из них отдельно не покрывает всё.
2. **Generic username = шум.** `johndoe2026` даёт 69 уникальных сайтов, из которых ~30% — false positives (AO3, Wikipedia, centralauth, xboxgamertag search). **Фильтровать** надо вручную.
3. **Holehe ≠ leak check.** Holehe показывает "email когда-то регистрировался на сайте", это **не breach**. Реальные breaches — это h8mail / HIBP / dehashed (платные ключи).
4. **Rate limits мажорские.** ~57% holehe-сайтов возвращают rate-limit → результаты holehe **занижены**. Для полноты — повторять через час, или сменить IP.
5. **Top-3 приоритизировать** по категории: developer (GitHub/HF) > mainstream (Twitter/Instagram) > niche (forum/gaming) > dead (Tumblr).
6. **Venmo false positive** надо явно отфильтровывать из отчёта (любой username даёт Claimed).
7. **h8mail нужен API-ключ** для HIBP / dehashed / hunter.io — иначе сигнал пустой.

## Что улучшить (action items)

- [ ] Запросить у Жени **HIBP API key** + **dehashed key** → полноценный breach-check
- [ ] Добавить в `run.sh` обёртку `osint-username <name>` → запускает все 4 тула одной командой, агрегирует в `raw/<name>/`
- [ ] Написать пост-процессор на Python: фильтрует venmo/Discord/Wikipedia FPs → выдаёт top-N
- [ ] SpiderFoot cross-check: импортнуть username → посмотреть какие ещё модули (Leaks, Emailaddr) дадут дополнительные сигналы

## Артефакты

- `intel/lessons/lesson-003-username-osint.md` (этот файл)
- `intel/techniques/username-enumeration.md` — методичка
- `agents/radar/reports/2026-06-30-report.md` — финальный отчёт
- `agents/radar/reports/raw/sherlock/<5 users>/<5 csv>`
- `agents/radar/reports/raw/maigret/<5 users>/<5 txt>`
- `agents/radar/reports/raw/holehe/<5 holehe txt + 5 h8mail txt>`
- `agents/radar/reports/raw/results.json`
- `agents/radar/reports/raw/scan-summary.md`
- `agents/radar/reports/raw/commands-run.md`

## Связанные

- **`intel/lessons/lesson-011-kev-triage-workflow.md`** (Хранитель 📚, 08.07) — общий workflow для обработки KEV-уведомлений. Lesson-003 — про OSINT-разведку, lesson-011 — про scoring CVE. Если OSINT-разведка выявит новый сервис в нашей инфре (например, RMM в списке Anubis) → asset_relevance для этого сервиса повышается в lesson-011 § 2.1.
- **`intel/techniques/cve-impact-rating.md`** — для случая, когда username-enumeration выводит на CVE (например, профиль в LinkedIn указывает на версию ПО → свежий CVE).

## Источники

- Sherlock: https://github.com/sherlock-project/sherlock
- Maigret: https://github.com/soxoj/maigret
- Holehe: https://github.com/megadose/holehe
- h8mail: https://github.com/khast3x/h8mail
- SpiderFoot: https://github.com/smicallef/spiderfoot