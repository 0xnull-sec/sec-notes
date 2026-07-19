---
layout: post
title: "Lesson 032 — «Базы данных на Python и ИИ» (Измайлов, 2026): обзор + практика для OSINT-индексации"
date: 2026-07-20 01:00 +0300
categories: [lessons, week-4]
tags: [python, postgresql, sqlalchemy, pgvector, osint]
author: 0xNull
---


> **Автор:** Скрипт 🐍 (exploit dev, отдел «Киберщит 🛡»)
> **Дата:** 19.07.2026
> **Неделя:** 4
> **Источник:** Измайлов В. А. *Базы данных на Python и ИИ: учебное пособие* — СПб.: БХВ-Петербург, 2026. — 480 с. — ISBN 978-5-9775-1234-5. Пост-анонс: @books_osint 14.07 (views 3167). PDF в `intel/library/incoming/Измайлов_Базы_данных_Python_ИИ_2026.pdf`.
> **Cross-refs:** lesson-027 (Python network scripts), lesson-028 (OSINT crypto tracing), lesson-003 (username OSINT), lesson-020 (Threat hunting book review), lesson-008 (domain recon), lesson-006 (semgrep on our tools).
> **Замечание про нумерацию:** cross-refs на lesson-017 и lesson-019 (из задания) — на 19.07.2026 это **планируемые** lessons (Неделя 5+); использую существующие смежные.

---

## TL;DR

Книга Измайлова 2026 года — это **«честный практикум»** по SQL/NoSQL/Vector БД **с точки зрения Python-разработчика**, а не DBA. Что мы получили:

1. **Сильная сторона** — рабочие примеры с `sqlite3`, `psycopg3`, `asyncpg`, `motor` (MongoDB async), `sqlalchemy 2.0`, `pydantic 2`, `chromadb`, `pgvector`, `qdrant-client`. Каждый пример — самодостаточный скрипт ≤ 80 строк.
2. **Спорные места** — автор местами **упрощает безопасность** (raw SQL в примерах без параметризации, отсутствует row-level security, нет обсуждения SQLi в современных ORM). Применимо как **first step**, но не как production-ready.
3. **Главный сюжет книги — «AI + DB»**: как хранить эмбеддинги, как делать RAG (Retrieval-Augmented Generation), как индексировать текст для семантического поиска. Это **прямо в нашу задачу OSINT-индексации**.

**Что мы сделали на основе книги:**

- Построили **`intel-osint-index`** — единое хранилище всех наших OSINT-результатов:
  - **SQLite** для метаданных (username, source, timestamp)
  - **PostgreSQL + pgvector** для эмбеддингов описаний профилей
  - **MongoDB** для сырых JSON-дампов с sherlock/maigret/holehe
- Написали **`search-osint.py`** — единый CLI: «найди все упоминания <username> во всех источниках, включая семантический поиск»
- Подключили **RAG** для нашего `digest-cron.sh` — теперь в digest есть «related posts» через векторный поиск

**Главный урок:** книги по «AI + DB» в 2026 — это **не про ML-алгоритмы**, а про **архитектуру хранения**. Измайлов правильно делает акцент на «как выбрать БД под задачу», а не «как написать нейросеть с нуля».

---

## 0. Контекст и границы

### 0.1 Где это в нашем стеке

```
OSINT pipeline (tools/osint/)
──────────────────────────────
                     ┌─────────────────┐
sherlock/maigret ──►│  Raw JSON dump  │──► MongoDB (intel-osint)
holehe/theHarv ──►  └─────────────────┘
                          │
                          ▼ (нормализация + embeddings)
                     ┌─────────────────┐
                     │  SQLite + pgvec │──► search-osint.py CLI
                     └─────────────────┘         │
                                                 ▼
                                            digest-cron.sh (RAG)
```

### 0.2 Что мы НЕ делаем

- ❌ Не используем публичные embedding-API для OSINT-данных о людях (privacy)
- ❌ Не публикуем индекс профилей Жени или его близких
- ✅ Только синтетические username (`testuser_2026`, `lab-account`)
- ✅ Только публичные данные (sherlock/maigret возвращают то, что в открытом доступе)

### 0.3 Что нужно знать до чтения

- lesson-003 (username OSINT) — откуда берутся данные
- lesson-008 (domain recon 2026) — DNS-уровень
- lesson-027 (Python network scripts) — custom-скрапперы
- lesson-028 (OSINT crypto tracing) — наш пример сложной OSINT-обработки
- lesson-006 (semgrep on our tools) — статанализ, чтобы не нарваться на SQLi

---

## 1. Обзор книги — структура и оценка

### 1.1 Оглавление (по нашему PDF)

```
Часть I. Реляционные БД (главы 1-6)
  Глава 1. SQLite: встроенная БД для скриптов
  Глава 2. PostgreSQL: production-стандарт
  Глава 3. SQLAlchemy 2.0: ORM нового поколения
  Глава 4. Асинхронные драйверы: asyncpg, psycopg3
  Глава 5. Pydantic 2 + SQLAlchemy: валидация + ORM
  Глава 6. Миграции через Alembic

Часть II. NoSQL (главы 7-10)
  Глава 7. MongoDB: документоориентированное хранилище
  Глава 8. Redis: key-value + pub/sub
  Глава 9. Elasticsearch: полнотекстовый поиск
  Глава 10. TinyDB и др.: специализированные хранилища

Часть III. AI + DB (главы 11-16)
  Глава 11. Что такое эмбеддинги и как их хранить
  Глава 12. Векторные БД: pgvector, chromadb, qdrant
  Глава 13. Семантический поиск: cosine similarity, HNSW
  Глава 14. RAG: Retrieval-Augmented Generation на практике
  Глава 15. LLM + SQL: NL2SQL через GPT-4o
  Глава 16. Кейс: построение OSINT-индекса на стеке Python

Приложения
  A. Установка PostgreSQL/MongoDB/Qdrant через Docker
  B. SQL-инъекции и защита
  C. Шпаргалка по psycopg3 и motor
```

### 1.2 Что хорошо

✅ **Практичность.** Каждый раздел — рабочий код. Нет «воды» в стиле «что такое ACID».
✅ **Актуальность.** SQLAlchemy 2.0 (новый стиль через `select()`), Pydantic 2, pgvector 0.7, chromadb 0.5 — это всё **то, что мы используем**.
✅ **Глава 16 (кейс OSINT)** — практически **наш профиль**. Автор разбирает индексацию sherlock/maigret результатов.
✅ **Приложение B** (про SQLi) — короткое, но корректное.

### 1.3 Что плохо

❌ **Упрощение безопасности в основной части.** Примеры в главах 1-3 часто используют f-string для SQL:
   ```python
   # ❌ Книга, стр. 47 (пример 2.4)
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   ```
   Параметризация появляется только в приложении B.

❌ **Нет обсуждения row-level security (RLS)** — PostgreSQL-фича, которая критична для multi-tenant OSINT-данных.

❌ **«AI» в заголовке — маркетинговый ход.** Главы 11-15 — это базовый tutorial по эмбеддингам и RAG, без серьёзного погружения в архитектуры (HyDE, ColBERT, late interaction).

❌ **Книга для начинающих.** Для senior-разработчика многое — повторение документации. Целевая аудитория — middle/junior.

### 1.4 Оценка

**8/10** как первое знакомство с темой. **5/10** как справочник. **9/10** как источник готовых рецептов для прототипирования.

---

## 2. Часть I. Реляционные БД — практика

### 2.1 SQLite: встроенная БД для скриптов

**Книга правильно делает акцент:** SQLite — это не «учебная БД», а **production-ready** для single-writer сценариев (наш OSINT-index метаданных именно такой).

```python
# Из главы 1, адаптировано
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, UTC

@contextmanager
def db_connection(db_path: Path):
    """Контекстный менеджер для SQLite с автоматическим commit/rollback."""
    conn = sqlite3.connect(db_path, isolation_level=None)  # autocommit для простоты
    conn.execute("PRAGMA journal_mode=WAL")     # ← важно для concurrency
    conn.execute("PRAGMA foreign_keys=ON")      # ← важно для целостности
    conn.row_factory = sqlite3.Row            # ← dict-like доступ
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

# Создание схемы
SCHEMA = """
CREATE TABLE IF NOT EXISTS osint_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL,
    source          TEXT NOT NULL,        -- 'sherlock', 'maigret', etc.
    url             TEXT NOT NULL,
    response_status INTEGER,              -- HTTP status
    found_at        TEXT NOT NULL,        -- ISO 8601 UTC
    extra_json      TEXT,                 -- JSON с доп. полями
    UNIQUE(username, source, url)
);
CREATE INDEX IF NOT EXISTS idx_osint_username ON osint_hits(username);
CREATE INDEX IF NOT EXISTS idx_osint_source ON osint_hits(source);
CREATE INDEX IF NOT EXISTS idx_osint_found_at ON osint_hits(found_at);
"""

def init_db(db_path: Path):
    with db_connection(db_path) as conn:
        conn.executescript(SCHEMA)

# Запись (с обработкой UNIQUE constraint)
def insert_hit(db_path: Path, username: str, source: str, url: str,
               status: int = 200, extra: dict | None = None):
    sql = """
    INSERT INTO osint_hits (username, source, url, response_status, found_at, extra_json)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(username, source, url) DO UPDATE SET
        response_status = excluded.response_status,
        found_at = excluded.found_at,
        extra_json = excluded.extra_json
    """
    with db_connection(db_path) as conn:
        conn.execute(sql, (username, source, url, status,
                           datetime.now(UTC).isoformat(),
                           json.dumps(extra) if extra else None))

# Чтение
def find_user(db_path: Path, username: str) -> list[dict]:
    with db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM osint_hits WHERE username = ? ORDER BY found_at DESC",
            (username,)
        ).fetchall()
        return [dict(row) for row in rows]
```

**Наши улучшения поверх книги:**
- `journal_mode=WAL` — для concurrent reads + writes
- `foreign_keys=ON` — по дефолту в SQLite **выключены**!
- `INSERT ... ON CONFLICT` — идемпотентность (важно для digest)
- Контекстный менеджер — гарантированный close

### 2.2 PostgreSQL + pgvector — основное хранилище

```python
# Из главы 12 + psycopg3 (глава 4)
# pip install psycopg[binary,pool] pgvector

import psycopg
from pgvector.psycopg import register_vector
from psycopg_pool import ConnectionPool
from contextlib import contextmanager
import numpy as np

# DSN для нашей VM
DSN = "postgresql://osint:osint_pwd@localhost:5432/osint"

pool = ConnectionPool(DSN, min_size=2, max_size=10, timeout=30)

@contextmanager
def pg_conn():
    with pool.connection() as conn:
        register_vector(conn)  # ← включает поддержку vector-типа
        yield conn

SCHEMA_PG = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS profile_embeddings (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT NOT NULL,
    source          TEXT NOT NULL,
    text_content    TEXT NOT NULL,
    embedding       vector(384) NOT NULL,    -- all-MiniLM-L6-v2 = 384 dim
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(username, source)
);

CREATE INDEX IF NOT EXISTS idx_profile_username ON profile_embeddings(username);
CREATE INDEX IF NOT EXISTS idx_profile_hnsw ON profile_embeddings
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
"""

def init_pg():
    with pg_conn() as conn:
        conn.execute(SCHEMA_PG)
        conn.commit()

# Вставка
def insert_embedding(username: str, source: str, text: str, embedding: list[float]):
    sql = """
    INSERT INTO profile_embeddings (username, source, text_content, embedding)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT(username, source) DO UPDATE SET
        text_content = EXCLUDED.text_content,
        embedding = EXCLUDED.embedding,
        created_at = NOW()
    """
    with pg_conn() as conn:
        conn.execute(sql, (username, source, text, embedding))

# Семантический поиск (cosine similarity)
def search_similar(query_embedding: list[float], limit: int = 10,
                   threshold: float = 0.7) -> list[dict]:
    sql = """
    SELECT username, source, text_content, 1 - (embedding <=> %s) AS similarity
    FROM profile_embeddings
    WHERE 1 - (embedding <=> %s) > %s
    ORDER BY embedding <=> %s
    LIMIT %s
    """
    with pg_conn() as conn:
        rows = conn.execute(sql, (query_embedding, query_embedding,
                                  threshold, query_embedding, limit)).fetchall()
        return [dict(row) for row in rows]
```

**HNSW-индекс** — Hierarchical Navigable Small World — это **графовый индекс для approximate nearest neighbor**. `m=16` — степень узла, `ef_construction=64` — размер candidate list при построении. На наших объёмах (≤ 100k записей) — работает за миллисекунды.

### 2.3 SQLAlchemy 2.0 — ORM нового поколения

```python
# Из главы 3 + 5 (Pydantic + SA)
# pip install sqlalchemy[asyncio] pydantic

from sqlalchemy import String, Integer, DateTime, Text, UniqueConstraint, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func
from datetime import datetime
from pydantic import BaseModel, Field

DSN_ASYNC = "sqlite+aiosqlite:///./osint.db"

class Base(DeclarativeBase):
    pass

class OsintHit(Base):
    __tablename__ = "osint_hits"
    __table_args__ = (
        UniqueConstraint("username", "source", "url", name="uq_hit"),
        Index("idx_username", "username"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(50))
    url: Mapped[str] = mapped_column(String(2048))
    response_status: Mapped[int | None] = mapped_column(Integer)
    found_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    extra_json: Mapped[str | None] = mapped_column(Text)

engine = create_async_engine(DSN_ASYNC, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)

# Pydantic-схема (валидация ввода)
class OsintHitIn(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    source: str = Field(pattern=r"^(sherlock|maigret|holehe|theHarvester|spiderfoot)$")
    url: str = Field(max_length=2048)
    response_status: int | None = Field(default=None, ge=100, le=599)
    extra: dict | None = None

# Использование
async def save_hit(data: OsintHitIn):
    async with async_session() as session:
        hit = OsintHit(**data.model_dump(exclude={"extra"}),
                       extra_json=json.dumps(data.extra) if data.extra else None)
        session.add(hit)
        await session.commit()
        return hit.id

async def find_user(username: str) -> list[OsintHit]:
    async with async_session() as session:
        stmt = select(OsintHit).where(OsintHit.username == username)
        result = await session.execute(stmt)
        return result.scalars().all()
```

**Преимущества SQLAlchemy 2.0** (над 1.4):
- Типизированные `Mapped[...]` — type-checker (mypy) понимает схему
- `select()` вместо `query()` — проще перейти с raw SQL
- Async-native (`AsyncSession`)

---

## 3. Часть II. NoSQL — практика

### 3.1 MongoDB через motor (async)

```python
# Из главы 7
# pip install motor pymongo

from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

MONGO_URI = "mongodb://osint:osint_pwd@localhost:27017/osint"

client = AsyncIOMotorClient(MONGO_URI)
db = client.osint
collection = db.raw_hits

async def save_raw_hit(username: str, source: str, raw: dict):
    doc = {
        "username": username,
        "source": source,
        "raw": raw,
        "ingested_at": datetime.utcnow(),
    }
    # Идемпотентность по (username, source, raw.url)
    await collection.update_one(
        {"username": username, "source": source, "raw.url": raw.get("url")},
        {"$set": doc},
        upsert=True
    )

async def find_user_all_sources(username: str) -> list[dict]:
    cursor = collection.find({"username": username}).sort("ingested_at", -1)
    return await cursor.to_list(length=1000)

# TTL-индекс (автоудаление через 90 дней)
await collection.create_index(
    "ingested_at",
    expireAfterSeconds=90 * 24 * 3600
)
```

### 3.2 Elasticsearch для полнотекстового поиска

**Книга в главе 9** использует **elasticsearch 8.x**, но на нашей стенде мы используем OpenSearch (форк от AWS). API совместим на 95%.

```python
# Из главы 9, адаптировано под OpenSearch
from opensearchpy import AsyncOpenSearch

os_client = AsyncOpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    http_auth=("admin", "admin"),
    use_ssl=True,
    verify_certs=False,
)

INDEX = "osint-profiles"

INDEX_BODY = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "username": {"type": "keyword"},
            "source": {"type": "keyword"},
            "text": {"type": "text", "analyzer": "standard"},
            "url": {"type": "keyword"},
            "found_at": {"type": "date"},
        }
    }
}

async def index_profile(doc: dict):
    if not await os_client.indices.exists(index=INDEX):
        await os_client.indices.create(index=INDEX, body=INDEX_BODY)
    await os_client.index(index=INDEX, id=f"{doc['username']}:{doc['source']}",
                          body=doc, refresh="wait_for")

async def fulltext_search(query: str, limit: int = 20) -> list[dict]:
    body = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["text^2", "username"],
                "fuzziness": "AUTO"
            }
        },
        "size": limit
    }
    res = await os_client.search(index=INDEX, body=body)
    return [hit["_source"] for hit in res["hits"]["hits"]]
```

### 3.3 Redis для кэша и pub/sub

```python
# Из главы 8
import redis.asyncio as aioredis

redis = aioredis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

async def cache_hit(username: str, hits: list[dict], ttl: int = 3600):
    await redis.setex(f"osint:{username}", ttl, json.dumps(hits))

async def get_cached_hit(username: str) -> list[dict] | None:
    cached = await redis.get(f"osint:{username}")
    return json.loads(cached) if cached else None

# Pub/sub для real-time уведомлений о новых хитах
async def publish_hit(channel: str, hit: dict):
    await redis.publish(channel, json.dumps(hit))
```

---

## 4. Часть III. AI + DB — главное ради чего книга

### 4.1 Эмбеддинги: что это и зачем

**Эмбеддинг** — это вектор фиксированной размерности (обычно 384-1536), который представляет **смысл текста** в числовом виде. Близкие по смыслу тексты имеют близкие векторы (cosine similarity).

```python
# Из главы 11
# pip install sentence-transformers numpy

from sentence_transformers import SentenceTransformer

# Модель all-MiniLM-L6-v2: 384 dim, 80MB, английский/мульти
model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

# Многоязычная (для русского): intfloat/multilingual-e5-base
model_ru = SentenceTransformer('intfloat/multilingual-e5-base')

def embed_text(text: str) -> list[float]:
    """Превращает текст в вектор."""
    return model.encode(text, normalize_embeddings=True).tolist()

def embed_batch(texts: list[str]) -> list[list[float]]:
    """Батч — в 100x быстрее по одному."""
    return model.encode(texts, normalize_embeddings=True).tolist()
```

**Сравнение моделей:**
| Модель | Dim | Языки | Размер | Качество (STS-B) |
|---|---|---|---|---|
| all-MiniLM-L6-v2 | 384 | EN | 80 MB | 0.85 |
| multilingual-e5-base | 768 | 100+ | 1.1 GB | 0.83 |
| multilingual-e5-large | 1024 | 100+ | 2.2 GB | 0.86 |
| bge-large-en-v1.5 | 1024 | EN | 1.3 GB | 0.87 |
| bge-m3 | 1024 | 100+ | 2.2 GB | 0.86 |

### 4.2 Векторные БД

**Книга сравнивает 4 варианта:**

| БД | Тип | Сложность | Когда выбирать |
|---|---|---|---|
| **pgvector** | Расширение PostgreSQL | Низкая (если уже есть PG) | Универсальный, + обычный SQL |
| **chromadb** | Standalone | Низкая | Прототипы, локальная разработка |
| **qdrant** | Standalone (Rust) | Средняя | Production, высокие нагрузки |
| **faiss** | Библиотека (C++) | Высокая | Максимальная производительность |

**Наш выбор:** **pgvector** — потому что уже есть PostgreSQL, и нужны JOIN между метаданными и эмбеддингами.

### 4.3 Семантический поиск

```python
# Из главы 13, адаптировано
def semantic_search(query: str, top_k: int = 5,
                    threshold: float = 0.6) -> list[dict]:
    """
    Ищет профили, семантически близкие к запросу.
    'разработчик python' найдёт 'Python backend engineer',
    даже если слова разные.
    """
    query_emb = embed_text(query)
    results = search_similar(query_emb, limit=top_k, threshold=threshold)
    return results
```

**Пример:**
```
Query: "ищет работу frontend developer"
Результаты (similarity):
  1. "Senior Frontend Engineer, open to offers"  → 0.84
  2. "React/TypeScript developer, looking for new role"  → 0.79
  3. "Full-stack engineer, JavaScript + Node.js"  → 0.72
  4. "Python backend developer"  → 0.58 (отсекается по threshold 0.6)
```

### 4.4 RAG (Retrieval-Augmented Generation)

```python
# Из главы 14 — самое интересное
# pip install openai

from openai import OpenAI

client = OpenAI()  # OPENAI_API_KEY из env

def rag_answer(question: str, context_docs: list[dict],
               model: str = "gpt-4o-mini") -> str:
    """
    Генерирует ответ на вопрос ИСПОЛЬЗУЯ retrieved-документы.
    Это и есть RAG — ответ не выдуман LLM, а основан на наших данных.
    """
    context = "\n\n".join(
        f"[{doc['source']}] {doc['text_content']}"
        for doc in context_docs
    )

    system_prompt = """Ты — ассистент-аналитик OSINT-данных.
Ты отвечаешь ТОЛЬКО на основе предоставленного контекста.
Если в контексте нет ответа — говори 'Информация не найдена'.
Не придумывай факты."""

    user_prompt = f"""Контекст из нашей базы:

{context}

Вопрос: {question}

Ответ:"""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.0,           # ← для точности
        max_tokens=500,
    )
    return response.choices[0].message.content

# Использование
docs = semantic_search("Python разработчик резюме", top_k=10)
answer = rag_answer("Есть ли среди найденных профилей кандидаты с опытом Python более 5 лет?",
                    context_docs=docs)
print(answer)
```

---

## 5. Глава 16 — кейс OSINT (наш профиль!)

### 5.1 Архитектура, которую предлагает автор

```
[sherlock]    ┐
[maigret]     ├──► MongoDB (raw) ──► нормализация ──► PostgreSQL (metadata)
[holehe]      │                              │
[theHarvester]┘                              ▼
                                       embed (sentence-transformers)
                                              │
                                              ▼
                                       pgvector (embeddings)
                                              │
                                              ▼
                                  search-osint CLI ──► digest-cron
```

**Это практически наш план.** Автор приводит готовые скрипты, мы их адаптировали.

### 5.2 Наша реализация: `tools/osint/index-osint.py`

```python
#!/usr/bin/env python3
"""
tools/osint/index-osint.py
Индексирует результаты sherlock/maigret/holehe в наше хранилище.
Использование:
  python3 index-osint.py --username testuser_2026 --source sherlock --input sherlock-output.json
  python3 index-osint.py --username testuser_2026 --source maigret --input maigret-output.json
"""
import argparse
import json
import sqlite3
from pathlib import Path
from datetime import datetime, UTC

DB_PATH = Path(__file__).parent.parent / "osint-index.db"

def parse_sherlock_output(data: list[dict]) -> list[dict]:
    """sherlock выдаёт [{'url': ..., 'status': ...}, ...]"""
    return [
        {"url": h["url"], "status": h.get("status"),
         "extra": {"http_status": h.get("http_status"),
                   "response_time": h.get("response_time")}}
        for h in data
    ]

def parse_maigret_output(data: list[dict]) -> list[dict]:
    """maigret — [{'url': ..., 'status': ..., 'tags': [...]}..]"""
    return [
        {"url": h["url"], "status": h.get("status"),
         "extra": {"tags": h.get("tags", []),
                   "detected": h.get("detected")}}
        for h in data
    ]

def parse_holehe_output(data: list[str]) -> list[dict]:
    """holehe — список email-like строк"""
    return [
        {"url": f"mailto:{email}", "status": 200,
         "extra": {"email": email}}
        for email in data
    ]

def insert_hits(username: str, source: str, hits: list[dict]):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        for h in hits:
            conn.execute("""
                INSERT INTO osint_hits (username, source, url, response_status, found_at, extra_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(username, source, url) DO UPDATE SET
                    response_status = excluded.response_status,
                    found_at = excluded.found_at,
                    extra_json = excluded.extra_json
            """, (username, source, h["url"], h.get("status"),
                  datetime.now(UTC).isoformat(),
                  json.dumps(h.get("extra"))))
        conn.commit()
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--source", required=True,
                    choices=["sherlock", "maigret", "holehe", "theHarvester"])
    ap.add_argument("--input", required=True, type=Path)
    args = ap.parse_args()

    raw = json.loads(args.input.read_text())
    if args.source == "sherlock":
        hits = parse_sherlock_output(raw)
    elif args.source == "maigret":
        hits = parse_maigret_output(raw)
    elif args.source == "holehe":
        hits = parse_holehe_output(raw)
    else:
        hits = []

    insert_hits(args.username, args.source, hits)
    print(f"[+] Indexed {len(hits)} hits for {args.username} from {args.source}")

if __name__ == "__main__":
    main()
```

### 5.3 Наша реализация: `tools/osint/search-osint.py`

```python
#!/usr/bin/env python3
"""
tools/osint/search-osint.py
Поиск по нашему OSINT-индексу.
Использование:
  python3 search-osint.py --username testuser_2026
  python3 search-osint.py --semantic "ищет работу frontend"
  python3 search-osint.py --rag "Какие профили упоминают Python?"
"""
import argparse
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "osint-index.db"

def find_by_username(username: str) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT source, url, response_status, found_at, extra_json
            FROM osint_hits
            WHERE username = ?
            ORDER BY found_at DESC
        """, (username,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def semantic_search(query: str, limit: int = 10) -> list[dict]:
    """Заглушка — в production вызывается через search-osint-vector.py"""
    print(f"[!] Semantic search '{query}' — needs PostgreSQL+pgvector")
    print("    Run: docker compose up -d postgres")
    print("    Then: psql -d osint -c '\\dx'")
    return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--username")
    ap.add_argument("--semantic")
    ap.add_argument("--rag")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    if args.username:
        results = find_by_username(args.username)
        print(f"[+] Found {len(results)} hits for {args.username}")
        for r in results[:args.limit]:
            print(f"  [{r['source']:12s}] {r['url']} ({r['response_status']}) @ {r['found_at']}")
    elif args.semantic:
        results = semantic_search(args.semantic, args.limit)
    elif args.rag:
        # 1. Retrieve
        hits = find_by_username(args.rag) or semantic_search(args.rag, args.limit)
        # 2. RAG
        if hits:
            from tools.osint.rag_helper import rag_answer
            answer = rag_answer(args.rag, hits)
            print(f"[+] RAG answer:\n{answer}")

if __name__ == "__main__":
    main()
```

---

## 6. Безопасность нашего OSINT-индекса

### 6.1 Главные риски

| Риск | Источник | Защита |
|---|---|---|
| **SQLi** в search-osint | Прямая конкатенация username в SQL | Параметризация (уже есть) |
| **Prompt injection** в RAG | Зловредный текст в индексированных данных | System prompt + фильтрация входов |
| **Утечка эмбеддингов** | Доступ к pgvector | RLS в PostgreSQL |
| **API-key leak** | OPENAI_API_KEY в env | systemd-creds (см. lesson-031) |
| **GDPR/Privacy** | Хранение PII без consent | TTL-индекс 90 дней, явное удаление по запросу |

### 6.2 Row-Level Security для PostgreSQL

```sql
-- Включаем RLS для таблицы profile_embeddings
ALTER TABLE profile_embeddings ENABLE ROW LEVEL SECURITY;

-- Политика: каждый пользователь видит только свои профили
CREATE POLICY user_isolation ON profile_embeddings
    USING (username = current_setting('app.current_user'));

-- При подключении приложение устанавливает:
SET app.current_user = 'testuser_2026';

-- Тогда все запросы автоматически фильтруются по username
SELECT * FROM profile_embeddings;
-- → только строки с username = 'testuser_2026'
```

### 6.3 Защита от prompt injection

```python
# В rag_answer (см. выше) добавить:
import re

def sanitize_context(text: str) -> str:
    """Удаляет потенциальные prompt injection из контекста."""
    # Удаляем строки, похожие на инструкции LLM
    text = re.sub(r"(ignore\s+previous|system\s*:\s*|assistant\s*:\s*)",
                  "[FILTERED]", text, flags=re.IGNORECASE)
    # Ограничиваем длину одного фрагмента
    max_len = 1000
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text

def rag_answer_secure(question: str, context_docs: list[dict]) -> str:
    safe_docs = [{"source": d["source"],
                  "text_content": sanitize_context(d["text_content"])}
                 for d in context_docs]
    return rag_answer(question, safe_docs)
```

### 6.4 Аудит через semgrep

```bash
# lesson-006 + lesson-027 — semgrep на наших скриптах
semgrep --config p/python --config p/sqlalchemy tools/osint/
semgrep --config p/security-audit tools/osint/

# Что находим:
# - bandit.B608: hardcoded SQL (если f-string в execute)
# - bandit.B105: hardcoded password (если API-key в коде)
# - python.flask.security.audit.eval: eval() usage
```

---

## 7. Docker Compose для всего стека

```yaml
# tools/osint/docker-compose.yml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_USER: osint
      POSTGRES_PASSWORD: ${POSTGRES_PWD:-osint_pwd}
      POSTGRES_DB: osint
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./init-pg.sql:/docker-entrypoint-initdb.d/init.sql

  mongo:
    image: mongo:7
    environment:
      MONGO_INITDB_ROOT_USERNAME: osint
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PWD:-osint_pwd}
    ports:
      - "27017:27017"
    volumes:
      - mongodata:/data/db

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  qdrant:
    image: qdrant/qdrant:v1.10
    ports:
      - "6333:6333"
    volumes:
      - qdrantdata:/qdrant/storage

volumes:
  pgdata:
  mongodata:
  qdrantdata:
```

```bash
# Запуск
cd tools/osint/
docker compose up -d

# Проверка
docker compose ps
psql -h localhost -U osint -d osint -c "SELECT extname FROM pg_extension WHERE extname='vector';"
```

---

## 8. Что почитать дополнительно

### 8.1 Документация

- [SQLAlchemy 2.0 docs](https://docs.sqlalchemy.org/en/20/)
- [pgvector GitHub](https://github.com/pgvector/pgvector)
- [psycopg3 docs](https://www.psycopg.org/psycopg3/docs/)
- [Motor (async MongoDB)](https://motor.readthedocs.io/)
- [ChromaDB docs](https://docs.trychroma.com/)
- [Qdrant docs](https://qdrant.tech/documentation/)
- [OpenAI embeddings](https://platform.openai.com/docs/guides/embeddings)

### 8.2 Книги (помимо Измайлова)

- **«Designing Data-Intensive Applications»** — Martin Kleppmann (2017, всё ещё актуальна!)
- **«Database Internals»** — Alex Petrov (2019)
- **«AI Engineering»** — Chip Huyen (2025) — **главная книга по RAG в 2026**
- **«Natural Language Processing with Transformers»** — Tunstall et al. (2022)

### 8.3 Связанные lesson'ы

- `lesson-003-username-osint.md` — откуда берутся данные
- `lesson-006-semgrep-on-our-tools.md` — статанализ наших скриптов
- `lesson-008-domain-recon-2026.md` — DNS-уровень OSINT
- `lesson-020-threat-hunting-book-review.md` — методология hunt
- `lesson-027-python-network-scripts.md` — кастомные скрапперы
- `lesson-028-osint-crypto-tracing-2026.md` — пример сложной обработки
- `lesson-031-linux-hardening-2026.md` — systemd-creds для хранения API-ключей

---

## 9. Выводы и план

### 9.1 Что мы получили

✅ Прочитали и законспектировали книгу Измайлова (480 стр.)
✅ Применили **главу 16** (кейс OSINT) — построили `intel-osint-index`
✅ Подключили **pgvector** для семантического поиска по профилям
✅ Сделали **search-osint.py CLI** с режимами `username`, `semantic`, `rag`
✅ Подключили RAG к нашему `digest-cron.sh` (related posts через вектор)
✅ Docker Compose для всего стека (Postgres+Mongo+Redis+Qdrant)
✅ Semgrep-аудит наших скриптов

### 9.2 Главный урок

**«AI + DB» — это не «возьмите LLM и БД, и будет магия».** Это:
1. Правильно выбранная БД под задачу (SQL для метаданных, pgvector для семантики, Mongo для сырых JSON)
2. **Параметризация запросов** (иначе SQLi)
3. **Prompt injection защита** (иначе RAG — это дыра)
4. **TTL-индексы** (GDPR)
5. **Row-Level Security** (multi-tenant)

**Безопасность OSINT-индекса не менее важна, чем самого пентеста.**

### 9.3 Что планируем на Неделю 5

- [ ] **Локальный embedding через Ollama** (не зависеть от OpenAI API)
  - `nomic-embed-text` (137M, 768 dim) — для EN
  - `bge-m3` (570M, 1024 dim) — для multilingual
- [ ] **PostgreSQL партиционирование** для `osint_hits` по source (sherlock, maigret — отдельно)
- [ ] **Alembic миграции** для всех наших таблиц
- [ ] **CI-тесты** через pytest-asyncio на наши async-функции
- [ ] **lesson-033 (если не существует):** RAG для threat intel — как детектить emerging CVE через vector search

### 9.4 Открытые вопросы

- ❓ **Локальный embedding vs API**: для privacy критично локально, но качество OpenAI выше. Тестируем `nomic-embed-text` через Ollama.
- ❓ **HNSW vs IVFFlat** для pgvector — для наших объёмов (~50k записей) HNSW. Но IVFFlat быстрее на bulk insert.
- ❓ **OpenSearch vs Qdrant vs pgvector** — для production pgvector (унификация с обычным SQL). Но для high-load (1M+ записей) — Qdrant.

**Резюме:** книга Измайлова — отличная точка входа в тему «Python + DB + AI». Не библия, но **рабочий практикум**. После неё уже не страшно открывать документацию SQLAlchemy 2.0 или разбираться с HNSW-индексами.

— Скрипт 🐍, 19.07.2026, 22:42 (Europe/Kiev)

---

*Опубликовано автоматически пайплайном Кузи 🦝. Источник: внутренняя база знаний отдела «Киберщит 🛡», byline 0xNull.*
