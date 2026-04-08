
```
osint-pipeline/
│
├── .env                        # Твої реальні дані (не комітити!)
├── .env.example                # Шаблон конфігурації
├── config.py                   # Завантаження .env, парсинг, валідація таргетів
├── pipeline.py                 # 🚀 Точка входу — оркеструє весь pipeline
│
├── modules/
│   ├── __init__.py
│   ├── base.py                 # Абстрактний базовий клас для всіх модулів
│   ├── domains.py              # Домени → субдомени, DNS, cert transparency
│   ├── emails.py               # Emails → harvesting, HIBP
│   ├── phones.py               # Телефони → lookup
│   └── ips.py                  # IP → Shodan, геолокація, reverse DNS
│
├── runners/
│   ├── __init__.py
│   └── recon_ng.py             # Subprocess runner для recon-ng
│
├── storage/
│   ├── __init__.py
│   └── db.py                   # SQLite — зберігає всі результати
│
└── reports/                    # Авто-генерується після запуску
    ├── <target>_<date>.json
    └── <target>_<date>.txt
```

Зроблено поки що:
- ✅ `.env.example`
- ✅ `config.py`

Наступний крок — `modules/base.py`?


# 🔍 OSINT Pipeline — Recon-ng Automation Layer

Автоматизований OSINT pipeline поверх [Recon-ng](https://github.com/lanmaster53/recon-ng).
Читає таргети з `.env`, визначає їх тип, і послідовно запускає відповідні модулі Recon-ng через subprocess.

---

## 📁 Структура проєкту

```
osint-pipeline/
│
├── .env                        # Таргети + API ключі (не комітити!)
├── .env.example                # Шаблон для .env
│
├── pipeline.py                 # 🚀 Точка входу. Оркеструє весь pipeline
├── config.py                   # Завантажує .env, визначає типи таргетів
│
├── modules/                    # Логіка по типу таргету
│   ├── __init__.py
│   ├── base.py                 # Абстрактний базовий клас модуля
│   ├── domains.py              # Домени → субдомени, DNS, cert transparency
│   ├── emails.py               # Emails → harvesting, HIBP
│   ├── phones.py               # Телефони → lookup, геолокація
│   └── ips.py                  # IP → Shodan, геолокація, reverse DNS
│
├── runners/
│   └── recon_ng.py             # Subprocess runner: запускає recon-ng команди
│
├── storage/
│   └── db.py                   # SQLite: зберігає всі результати (як сам recon-ng)
│
├── reports/                    # Авто-генеровані результати
│   ├── <target>_<date>.json    # JSON звіт по таргету
│   └── <target>_<date>.txt     # Текстовий summary
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Як це працює

```
.env (таргети)
     │
     ▼
config.py — парсить таргети, визначає тип кожного
     │
     ▼
pipeline.py — для кожного таргету підбирає потрібні модулі
     │
     ├──► modules/domains.py   (якщо таргет — домен)
     ├──► modules/emails.py    (якщо таргет — email)
     ├──► modules/phones.py    (якщо таргет — телефон)
     └──► modules/ips.py       (якщо таргет — IP)
               │
               ▼
         runners/recon_ng.py — формує і виконує recon-ng команди
               │
               ▼
         storage/db.py — зберігає результати в SQLite
               │
               ▼
         reports/ — експортує JSON + текстовий звіт
```

---

## 🗂️ Файли — детально

### `.env`
```env
# --- Таргети ---
TARGETS=example.com, john@example.com, +380991234567, 8.8.8.8

# --- API ключі ---
SHODAN_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
HUNTER_API_KEY=your_key_here

# --- Налаштування ---
RECON_NG_PATH=/usr/local/bin/recon-ng
WORKSPACE=osint_workspace
OUTPUT_DIR=./reports
```

---

### `config.py`
Відповідає за:
- завантаження `.env` через `python-dotenv`
- парсинг таргетів
- автоматичне визначення типу таргету (домен / email / телефон / IP) через regex

---

### `modules/base.py`
Абстрактний клас `BaseModule` з інтерфейсом:
```python
class BaseModule(ABC):
    def run(self, target: str) -> dict: ...     # запускає розвідку
    def validate(self, target: str) -> bool: ... # перевіряє тип таргету
```
Усі модулі успадковують від нього.

---

### `modules/domains.py`
Recon-ng модулі які запускаються для доменів:

| Модуль Recon-ng | Що збирає |
|---|---|
| `recon/domains-hosts/certificate_transparency` | Субдомени з CT логів |
| `recon/domains-hosts/brute_hosts` | Brute force субдоменів |
| `recon/domains-hosts/google_site_web` | Субдомени через Google |
| `recon/domains-contacts/whois_pocs` | Контакти з WHOIS |
| `recon/hosts-hosts/resolve` | DNS резолвінг |

---

### `modules/emails.py`
| Модуль Recon-ng | Що збирає |
|---|---|
| `recon/domains-contacts/hunter_io` | Email harvesting (Hunter.io) |
| `recon/contacts-credentials/hibp` | Перевірка в HaveIBeenPwned |
| `recon/domains-contacts/pgp_search` | Email з PGP keyservers |

---

### `modules/phones.py`
| Модуль Recon-ng | Що збирає |
|---|---|
| `recon/profiles-contacts/phonebook` | Пошук по номеру |

> 📌 Телефонний OSINT частково виходить за межі Recon-ng — окремі прямі API виклики.

---

### `modules/ips.py`
| Модуль Recon-ng | Що збирає |
|---|---|
| `recon/hosts-hosts/shodan_ip` | Shodan: порти, сервіси, банери |
| `recon/hosts-hosts/freegeoip` | Геолокація IP |
| `recon/hosts-hosts/reverse_resolve` | Reverse DNS |
| `recon/hosts-ports/shodan_hostname` | Shodan по хосту |

---

### `runners/recon_ng.py`
Запускає `recon-ng` як subprocess, передає команди через stdin:
```
recon-ng -w <workspace> -r <commands_file>
```
Парсить stdout, витягує результати в структурований dict.

---

### `storage/db.py`
SQLite база з таблицями:
- `targets` — всі таргети з типом і статусом
- `results` — результати кожного модуля
- `runs` — лог запусків pipeline

---

### `reports/`
Авто-генерується після кожного запуску:
- **JSON** — повні структуровані дані для подальшої обробки
- **TXT** — читабельний summary для людини

---

## 🚀 Запуск

```bash
# Встановити залежності
pip install -r requirements.txt

# Налаштувати таргети
cp .env.example .env
# → відредагувати .env

# Запустити pipeline
python pipeline.py

# Або для конкретного таргету
python pipeline.py --target example.com

# Тільки певні модулі
python pipeline.py --target example.com --modules domains,emails
```

---

## 📦 Залежності

```
python-dotenv      # .env завантаження
requests           # прямі API виклики
sqlite3            # вбудований в Python
shodan             # Shodan Python SDK
```

---

## ⚠️ Важливо

- Використовуй тільки для **легальних цілей** і таргетів де маєш дозвіл
- Ніколи не комітити `.env` з реальними ключами
- Recon-ng має бути встановлений окремо: `pip install recon-ng`

---

## 🗺️ Roadmap

- [ ] Фундамент: `.env`, `config.py`, `base.py`, `recon_ng.py`
- [ ] Модуль `domains.py`
- [ ] Модуль `emails.py`
- [ ] Модуль `ips.py`
- [ ] Модуль `phones.py`
- [ ] `storage/db.py`
- [ ] `pipeline.py` — оркестратор
- [ ] Звіти (JSON + TXT)
- [ ] CLI аргументи (`--target`, `--modules`)

