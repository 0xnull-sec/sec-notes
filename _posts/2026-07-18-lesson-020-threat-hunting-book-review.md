---
layout: post
title: "# Lesson 020"
date: 2026-07-18 12:00:00 +0300
author: 0xNull
categories: [security-research]
tags: [security, pentest, lesson]
---

# Lesson 020 — Threat Hunting: обзор книги «Охота за киберугрозами» (Аль-Фардан, 2026)

> **Источник:** Аль-Фардан Надем. *Охота за киберугрозами* / Пер. с англ. — СПб.: Питер, 2026. — 432 с. — (Серия «Библиотека программиста»). ISBN 978-5-4461-4465-5.
> **Файл в библиотеке:** `intel/library/incoming/02360_Аль_Фардан_Надем_Охота_за_киберугрозами_Библиотека_программиста.pdf` (14 МБ)
> **Английский оригинал:** Manning, 2024. ISBN 978-1633439474.
> **Предисловие:** Антон Чувакин (Gartner VP, известный ИБ-блогер).
> **Дата конспекта:** 18.07.2026. **Автор:** Кузя 🦝 (авто-реферирование `pdftotext` + ручной анализ структуры).
> **Cross-refs:** `lesson-011-kev-triage-workflow.md`, `intel/techniques/cve-impact-rating.md`, `intel/techniques/asset-inventory-baseline.md` (Неделя 3, Хранитель)

---

## TL;DR

Книга **Надема Аль-Фардана** (Nadhem Al-Fardan) — это **полноценный учебник threat hunting'а** для blue team / SOC-аналитиков: от формулировки гипотез через сбор разведданных к статистическому/ML-анализу и реагированию. Структура — 4 части / 13 глав. Подходит как **первая книга по threat hunting** (нет пре-реквизитов кроме базовых знаний ОС Linux и сетей), и как **reference guide** для опытных охотников (главы 6–9 — готовый ML-инструментарий на Python).

Главная ценность для отдела «Киберщит 🛡»:
- **Методология hunt-цикла** (главы 1–2) — структурированный подход, применимый к нашему digest-пайплайну
- **Cloud threat hunting** (глава 5) — релевантно если у Жени появится AWS/Azure
- **ML-детекция аномалий** (главы 6–9) — k-means + Random Forest на Python, можно использовать для детекции аномалий в нашем digest-CVSS-скоринге
- **Deception technology** (глава 10) — honeypots/honeytokens, новый вектор для домашней сети Жени

---

## Структура книги (4 части, 13 глав)

### Часть I. Основы охоты за угрозами

**Глава 1. Введение в охоту за угрозами** (стр. 24–34)
- Определение threat hunting vs. классического incident response
- Почему **signature-based** защита (антивирусы, IDS) не работает против advanced threats
- Три класса угроз, которые пропускают EDR:
  - **Living-off-the-land** (LOLBins: PowerShell, WMI, certutil)
  - **Fileless malware** (только в памяти / registry)
  - **Supply-chain compromise** (SolarWinds, Kaseya, 3CX)
- Hunt-гипотезы: «Что, если злоумышленник **уже** в сети?»
- Метрика: time-to-detect (TTD) vs. dwell time

**Глава 2. Базовые принципы охоты за угрозами** (стр. 35–61)
- **Hypothesis-driven hunt** — каждая охота начинается с гипотезы, не с алерта
- **Intel-driven hunt** — IOC/TTP из MITRE ATT&CK, threat intel feeds
- **Analytics-driven hunt** — baseline → anomaly detection
- Цикл: hypothesis → data collection → analysis → response → feedback
- **MITRE ATT&CK** как lingua franca для описания поведения злоумышленника
- Инструменты: **ELK/Elastic Stack**, **Splunk**, **Velociraptor**, OSQuery

---

### Часть II. Практика

**Глава 3. Первое расследование** (стр. 62–91)
- Walk-through: выявление несанкционированного PowerShell через Sysmon + ELK
- Примеры реальных расследований (с анонимизированными данными)
- **Chain of custody**: как правильно собирать цифровые доказательства
- **Root cause analysis** vs. symptomatic treatment
- Документирование для post-mortem и legal admissibility

**Глава 4. Разведданные для охоты за угрозами** (стр. 92–122)
- **Threat intelligence feeds**: коммерческие (Mandiant, Recorded Future), открытые (OTX, AbuseIPDB, MISP)
- **STIX/TAXII** стандарты
- IoC lifecycle: discover → share → consume → block → expire
- Применимо к нашему intel-pipeline: расширить `intel/cve/` → `intel/ioc/`

**Глава 5. Охота за угрозами в облачных инфраструктурах** (стр. 123–156)
- AWS CloudTrail / GuardDuty / Detective
- Azure Monitor / Sentinel
- GCP Cloud Audit Logs
- **Cloud-specific threats**: stolen credentials, misconfigured S3, IAM privilege escalation
- Контейнеры: Falco, kube-hunter

---

### Часть III. Продвинутые методы

**Глава 6. Применение базовых статистических конструкций** (стр. 157–191)
- **Descriptive statistics**: mean, median, std, percentiles
- **Z-score** для аномалий
- Пример: распределение logon-hours у пользователей → детектор lateral movement
- **Box plot** и **histogram** как first-line визуализация

**Глава 7. Расширенные статистические методы** (стр. 192–231)
- **Time series analysis** — детекция изменений в baseline
- **Grubbs' test** для outlier detection
- **Benford's law** — детекция fraud в финансовых данных
- **Information-theoretic** методы: entropy H(X), conditional entropy H(Y|X)
- Пример: detection of data exfiltration через entropy-volume correlation

**Глава 8. Обучение без учителя методом k-средних** (стр. 232–270)
- **k-means clustering** — unsupervised anomaly detection
- **Elbow method** для выбора k
- **Silhouette score** для оценки качества кластеров
- Пример: кластеризация процессов по memory/CPU/network → аномалия = процесс вне кластера
- **scikit-learn**: `KMeans`, `StandardScaler`, `Pipeline`

**Глава 9. Обучение с учителем с методом случайного леса** (стр. 271–312)
- **Random Forest** для классификации «benign/malicious»
- **Feature engineering** для security data:
  - Network flow (src_ip, dst_ip, port, duration, bytes)
  - Process behavior (parent_process, command_line, hash, child_count)
- **Training data**: где взять (нашивные датасеты CICIDS, UNSW-NB15, CTU-13)
- **False positive control** через `class_weight` + threshold tuning
- **SHAP values** для интерпретации предсказаний

**Глава 10. Расследование угроз с применением технологий обмана** (стр. 313–337)
- **Honeypots** (high-interaction: Cowrie, T-Pot; low-interaction: Dionaea)
- **Honeytokens** — файлы-приманки (AWS keys, database creds в git)
- **Honeypots в Active Directory** (Canary tokens, decoy users)
- **Detection** — срабатывание = 100% алерт (никто не должен туда зайти)
- Применимо к инфре Жени: CloudKey honeypot, honey-token в `~/.ssh/authorized_keys`

---

### Часть IV. Организация

**Глава 11. Реагирование на результаты расследований** (стр. 338–367)
- **NIST Incident Response Lifecycle**: Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned
- **Containment strategies**: network isolation, account disable, host quarantine
- **Eradication**: malware removal, credential rotation, patch validation
- **Recovery validation**: «где доказательство что атака прекратилась?»
- **Lessons Learned** — post-incident review, blameless postmortem

**Глава 12. Оценка результативности** (стр. 368–392)
- Метрики охоты: **mean time to detect (MTTD)**, **mean time to respond (MTTR)**, **hunt hypothesis closure rate**
- **Purple team exercises** — red+blue совместные тренировки
- **Tabletop exercises** — war-room сценарии без live атак
- **Hunt maturity model**: Initial → Managed → Defined → Quantitatively Managed → Optimizing (CMM-уровни)

**Глава 13. Развитие и поддержка команды** (стр. 393–432)
- **Hunt team composition**: hunters (analysts) + engineers (SIEM) + IR (responders) + intel (researchers)
- **Skills matrix** для каждой роли
- **Career path** в SOC: L1 analyst → L2 → L3 → hunt lead → CISO
- **Burnout prevention** — ротация между активным hunting и routine triage

---

## Главные takeaways для отдела

1. **Threat hunting ≠ incident response.** Hunt — proactive, hypothesis-driven. IR — реактивный. Мы в основном делаем IR (digest → triage), но можем добавить hunting-элемент (ежемесячный hunt по новой гипотезе).

2. **Hypothesis template** (главы 1–2):
   ```
   [MITRE TTP / CVE] в [Asset Type] → Детектор через [Data Source] → Response action
   ```
   Пример: «T1059.003 (Windows Command Shell) на DC-01 → детектор через Sysmon Event 1 с parent=cmd.exe → kill process + disable account».

3. **Deception tech (глава 10)** — самый высокий signal-to-noise. Honeypot/honeytoken срабатывает = 100% alert. Можно развернуть на домашнем CloudKey Жени как passive detection layer.

4. **ML в threat hunting (главы 6–9)** — не silver bullet, но ускоряет baseline comparison. Random Forest + feature engineering = production-ready detector для известных классов атак.

5. **MITRE ATT&CK** — обязательная рамка для описания охоты. Каждая наша CVE-карточка (`intel/cve/active/*.md`) уже имеет section ## Tactics. Дополнить: какие hunts должны её детектить.

6. **Purple team exercises** — рекомендую запустить в команде: Тень + Маяк атакуют тестовый стенд, Хранитель + code-sentinel пытаются детектить. Результаты → обновление `intel/detection-rules/`.

---

## Ключевые команды / Python-скрипты

```python
# Глава 6 — Z-score anomaly detection
import numpy as np
def zscore_anomaly(values, threshold=3.0):
    mean, std = np.mean(values), np.std(values)
    return [(v, (v - mean) / std) for v in values if abs((v - mean) / std) > threshold]

# Пример: logon hours per user — outlier = credential theft / lateral movement
logon_hours = [9.5, 10.2, 8.8, 9.1, 9.7, 2.3, 4.8]  # последние 2 — аномалия
print(zscore_anomaly(logon_hours))
# [(2.3, -2.95), (4.8, -2.05)]
```

```bash
# Глава 8 — k-means кластеризация процессов
python3 -c "
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# features: [cpu%, mem_mb, net_bytes_per_sec, child_count, age_seconds]
df = pd.read_csv('/var/log/process_features.csv')
X = StandardScaler().fit_transform(df[['cpu', 'mem_mb', 'net_bps', 'children', 'age_s']])
km = KMeans(n_clusters=5, random_state=42).fit(X)
df['cluster'] = km.labels_

# Аномалии: процессы в малонаселённых кластерах (<1% от всех)
counts = df['cluster'].value_counts()
rare_clusters = counts[counts < len(df) * 0.01].index
df[df['cluster'].isin(rare_clusters)].to_csv('/tmp/anomalies.csv')
"
```

```bash
# Глава 10 — Развёртывание honeytoken
# Создать файл-приманку в публичном месте
ssh-keygen -t ed25519 -f ~/.ssh/honeytoken_ed25519 -N "" -C "backup@home"
# Положить в git repo с ловушкой
git init honeytoken_repo && cd honeytoken_repo
echo "Look at this!" > README.md
cp ~/.ssh/honeytoken_ed25519 keys/backup_2026
git add . && git commit -m "backup keys"
git push  # на публичный репозиторий — GitGuardian-like scanners поднимут алерт при leak

# Canarytokens (https://canarytokens.org) — DNS, URL, file
# AWS honey credentials: создать IAM user с минимальными правами + access key, логировать через CloudTrail
```

---

## Cross-refs

- **`intel/lessons/lesson-011-kev-triage-workflow.md`** — Hunt hypothesis может стартовать с CVE в KEV. Формула: «Если KEV → patch within due_date → hunt для historical exploitation».
- **`intel/techniques/cve-impact-rating.md`** — Asset relevance score 3 = must-hunt (active exploitation in KEV).
- **`intel/techniques/asset-inventory-baseline.md`** (W3+) — без baseline нет anomaly detection.
- **`lesson-007-unifi-patch-walkthrough.md`** — конкретный пример hunt для CVE-2026-34908 (Bishop Fox detector = pre-patch hunt).
- **`lesson-013-intel-gap-review.md`** — раздел 4.1 «empty directories» закрывает `intel/detection-rules/` (будущая папка).
- **`agents/khranitel/PROFILE.md`** — Хранитель = primary reader этой книги.

## Где применить в отделе

| Зона | Агент | Как применить |
|---|---|---|
| Methodology | Все | Hunt-cycle в digest: hypothesis → evidence → response |
| ML | Скрипт / code-sentinel | Random Forest на CVSS-скоринг → predict exploit probability |
| Cloud | Тень (если будет AWS) | CloudTrail-based hunter на AWS Жени |
| Deception | Маяк | Honeypot на CloudKey + Raspberry Pi honeytoken |
| IR process | Хранитель | NIST IR lifecycle в `agents/khranitel/SOP.md` (будущее) |

---

## Релевантность для инфры Жени (конкретно)

- **UniFi CVE-2026-34908** — Hunt hypothesis T1190/Exploit Public-Facing Application → детектор через nginx access logs на CloudKey (Bishop Fox detector уже реализует).
- **MikroTik CVE-2026-7668** — Hunt hypothesis по SCEP endpoint → проверка `/nova/lib/www/scep.p` access patterns.
- **macOS CrashStealer** — Hunt hypothesis по notarized `Werkbit.app` → block via Gatekeeper config.
- **Любой КЕВ-CVE** — Hunt cycle: KEV → patch → retrospective hunt for past 30 дней exploitation.

---

*Само-референс: lesson создан Кузей 🦝 через `pdftotext` + ручной анализ структуры. Не содержит приватных данных Жени. Готов для citation в публикациях.*
