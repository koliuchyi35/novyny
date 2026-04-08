# OSINT Pipeline

Source-oriented OSINT framework для автоматизованого збору даних з різних джерел через єдиний інтерфейс.

## Структура проєкту

```text
osint-pipeline/
│
├── .env
├── .gitignore
├── config.py
├── pipeline.py
│
├── models/
│   ├── __init__.py
│   ├── target.py
│   ├── result.py
│   └── enums.py
│
├── sources/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   │
│   ├── recon_ng/
│   │   ├── __init__.py
│   │   ├── source.py
│   │   ├── runner.py
│   │   ├── plans.py
│   │   └── parser.py
│   │
│   ├── shodan/
│   │   ├── __init__.py
│   │   ├── source.py
│   │   └── client.py
│   │
│   └── theharvester/
│       ├── __init__.py
│       ├── source.py
│       └── runner.py
│
├── storage/
│   ├── __init__.py
│   ├── db.py
│   └── schemas.py
│
└── reports/
    ├── <target>_<date>.json
    └── <target>_<date>.txt
```

## Архітектурна модель

У системі є 4 базові сутності:

- `Target` — ціль аналізу
- `Source` — джерело збору інформації
- `Pipeline` — оркестратор виконання
- `Storage / Reports` — збереження та експорт результатів

Потік роботи:

```text
Input target
   ↓
Target(...)
   ↓
pipeline.py
   ↓
sources registry
   ↓
supports(target)
   ↓
collect(target)
   ↓
SourceResult
   ↓
storage/db.py
   ↓
reports/*.json + reports/*.txt
```

## Models

### `models/target.py`

Описує ціль для аналізу.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Target:
    value: str
    type: str  # domain | email | phone | ip
```

Приклади:
- `example.com`
- `john@example.com`
- `+380991234567`
- `8.8.8.8`

### `models/result.py`

Нормалізований результат роботи одного source.

```python
from dataclasses import dataclass, field
from typing import Any

@dataclass
class SourceResult:
    source: str
    target: str
    target_type: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
```

### `models/enums.py`

Містить константи та типи:
- `TargetType`
- статуси виконання
- типи артефактів
- інші enum/constant значення

## Sources

Уся логіка збору живе в `sources/`.

### `sources/base.py`

Базовий контракт для всіх джерел.

```python
from abc import ABC, abstractmethod

class BaseSource(ABC):
    name: str

    @abstractmethod
    def supports(self, target) -> bool:
        pass

    @abstractmethod
    def collect(self, target):
        pass
```

Кожен source:
- сам визначає, чи підтримує target
- сам виконує збір даних
- сам повертає `SourceResult`

### `sources/registry.py`

Центральний реєстр доступних sources.

```python
from sources.recon_ng.source import ReconNGSource
from sources.shodan.source import ShodanSource


def get_sources():
    return [
        ReconNGSource(),
        ShodanSource(),
    ]
```

### `sources/recon_ng/`

Recon-ng оформлюється як окремий source.

#### `source.py`

Містить `ReconNGSource`, який реалізує:
- `supports(target)`
- `collect(target)`

#### `runner.py`

Відповідає за запуск `recon-ng` через subprocess:
- формує команду
- виконує запуск
- читає stdout / stderr
- повертає сирий результат

#### `plans.py`

Містить мапу:
- `domain` → список recon-ng модулів
- `email` → список recon-ng модулів
- `phone` → список recon-ng модулів
- `ip` → список recon-ng модулів

```python
RECON_PLANS = {
    "domain": [
        "recon/domains-hosts/certificate_transparency",
        "recon/domains-hosts/brute_hosts",
        "recon/domains-contacts/whois_pocs",
    ],
    "email": [
        "recon/contacts-credentials/hibp",
        "recon/domains-contacts/pgp_search",
    ],
    "ip": [
        "recon/hosts-hosts/reverse_resolve",
    ],
    "phone": [],
}
```

#### `parser.py`

Відповідає за:
- парсинг output від recon-ng
- нормалізацію результатів
- приведення даних до єдиного формату `SourceResult`

### `sources/shodan/`

#### `source.py`

Містить `ShodanSource`, який працює через API і повертає `SourceResult`.

#### `client.py`

Інкапсулює роботу з Shodan API:
- host lookup
- сервіси
- банери
- відкриті порти
- додаткові host metadata

### `sources/theharvester/`

#### `source.py`

Містить `TheHarvesterSource`.

#### `runner.py`

Відповідає за виклик CLI, збір stdout/stderr і підготовку результату.

## Pipeline

### `pipeline.py`

Головний оркестратор системи.

Його задача:
1. завантажити конфігурацію
2. отримати target
3. створити `Target`
4. взяти список sources із `registry.py`
5. для кожного source викликати:
   - `supports(target)`
   - `collect(target)`
6. зберегти результат
7. сформувати звіти

Мінімальна логіка:

```python
from sources.registry import get_sources


def run_pipeline(target):
    results = []

    for source in get_sources():
        if source.supports(target):
            result = source.collect(target)
            results.append(result)

    return results
```

## Config

### `config.py`

Відповідає за:
- зчитування `.env`
- шляхи до інструментів
- API ключі
- базові налаштування pipeline
- output paths

### `.env`

```env
# Targets
TARGETS=example.com,john@example.com,+380991234567,8.8.8.8

# Sources
ENABLED_SOURCES=recon_ng,shodan,theharvester

# Output
OUTPUT_DIR=./reports
DB_PATH=./storage/osint.db

# Recon-ng
RECON_NG_PATH=/usr/local/bin/recon-ng
RECON_WORKSPACE=osint_workspace

# API keys
SHODAN_API_KEY=
HIBP_API_KEY=
HUNTER_API_KEY=
```

## Storage

### `storage/db.py`

Відповідає за запис результатів у БД.

Мінімально варто мати таблиці:
- `targets`
- `runs`
- `source_results`

Опційно:
- `artifacts`
- `errors`

### `storage/schemas.py`

Містить SQL schema / init logic для БД.

## Reports

Усі результати зберігаються в `reports/`.

Формати:
- `JSON` — повний машинозчитуваний результат
- `TXT` — короткий readable summary

Приклад:

```text
reports/
├── example.com_2026-04-08.json
└── example.com_2026-04-08.txt
```

## Запуск

```bash
pip install -r requirements.txt
python pipeline.py
```

Опційно:

```bash
python pipeline.py --target example.com
python pipeline.py --target 8.8.8.8
python pipeline.py --target john@example.com
```

## Принципи проєкту

- один source = одна інтеграція
- pipeline не знає внутрішньої логіки source
- кожен source повертає нормалізований результат
- target-specific логіка живе всередині source
- нові джерела додаються без переписування ядра

## Поточна база для реалізації

Перші файли, які треба зафіксувати:

1. `models/target.py`
2. `models/result.py`
3. `models/enums.py`
4. `sources/base.py`
5. `sources/registry.py`
6. `sources/recon_ng/source.py`
7. `sources/recon_ng/runner.py`
8. `sources/recon_ng/plans.py`
9. `sources/recon_ng/parser.py`
10. `storage/db.py`
11. `pipeline.py`

## Резюме

`OSINT Pipeline` будується як source-oriented framework.

Центральна ідея:
- є ціль
- є набір джерел збору
- pipeline проганяє target через compatible sources
- усі результати зводяться в єдиний формат
- збереження і звіти відокремлені від логіки збору

Це дає чисту базу для росту від одного `ReconNGSource` до повноцінного набору OSINT integrations.
