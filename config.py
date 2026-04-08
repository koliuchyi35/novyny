# osint-pipeline/config.py

"""
config.py — Завантаження конфігурації та валідація таргетів

Відповідає за:
- Завантаження .env
- Парсинг таргетів (списки через кому)
- Валідацію кожного таргету по типу
- Завантаження API ключів та налаштувань
"""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

# ── Завантаження .env ────────────────────────────────────────────
load_dotenv()

logger = logging.getLogger(__name__)


# ╔══════════════════════════════════════════════════════════════╗
# ║                     REGEX ПАТЕРНИ                           ║
# ╚══════════════════════════════════════════════════════════════╝

PATTERNS = {
    "domain": re.compile(
        r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)"
        r"(\.[A-Za-z0-9\-]{1,63})*"
        r"\.[A-Za-z]{2,}$"
    ),
    "email": re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    ),
    "ipv4": re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    ),
    "ipv6": re.compile(
        r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    ),
    "phone": re.compile(
        r"^\+[1-9]\d{6,14}$"
    ),
}


# ╔══════════════════════════════════════════════════════════════╗
# ║                     ДАТАКЛАСИ                               ║
# ╚══════════════════════════════════════════════════════════════╝

@dataclass
class Targets:
    """Розпарсені та валідовані таргети по типах."""
    domains: list[str] = field(default_factory=list)
    emails:  list[str] = field(default_factory=list)
    ips:     list[str] = field(default_factory=list)
    phones:  list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([self.domains, self.emails, self.ips, self.phones])

    def summary(self) -> str:
        lines = []
        if self.domains: lines.append(f"  Domains  ({len(self.domains)}): {', '.join(self.domains)}")
        if self.emails:  lines.append(f"  Emails   ({len(self.emails)}):  {', '.join(self.emails)}")
        if self.ips:     lines.append(f"  IPs      ({len(self.ips)}):     {', '.join(self.ips)}")
        if self.phones:  lines.append(f"  Phones   ({len(self.phones)}):  {', '.join(self.phones)}")
        return "\n".join(lines) if lines else "  (порожньо)"


@dataclass
class ApiKeys:
    """API ключі для зовнішніх сервісів."""
    shodan:      Optional[str] = None
    hibp:        Optional[str] = None
    hunter:      Optional[str] = None
    virustotal:  Optional[str] = None

    def available(self) -> list[str]:
        """Повертає список сервісів де є ключ."""
        result = []
        if self.shodan:     result.append("Shodan")
        if self.hibp:       result.append("HIBP")
        if self.hunter:     result.append("Hunter.io")
        if self.virustotal: result.append("VirusTotal")
        return result


@dataclass
class Settings:
    """Загальні налаштування pipeline."""
    recon_ng_path:  str = "/usr/local/bin/recon-ng"
    workspace:      str = "osint_workspace"
    output_dir:     str = "./reports"
    log_level:      str = "INFO"
    module_timeout: int = 60


@dataclass
class Config:
    """Головний конфіг — агрегує всі секції."""
    targets:  Targets
    api_keys: ApiKeys
    settings: Settings


# ╔══════════════════════════════════════════════════════════════╗
# ║                     ВАЛІДАТОРИ                              ║
# ╚══════════════════════════════════════════════════════════════╝

def _is_valid_ipv4(ip: str) -> bool:
    """Перевіряє IPv4 включно з діапазоном октетів (0-255)."""
    if not PATTERNS["ipv4"].match(ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def _is_valid_ipv6(ip: str) -> bool:
    return bool(PATTERNS["ipv6"].match(ip))


def _validate_domain(value: str) -> bool:
    return bool(PATTERNS["domain"].match(value))


def _validate_email(value: str) -> bool:
    return bool(PATTERNS["email"].match(value))


def _validate_ip(value: str) -> bool:
    return _is_valid_ipv4(value) or _is_valid_ipv6(value)


def _validate_phone(value: str) -> bool:
    """Телефон має бути в міжнародному форматі: +380991234567."""
    return bool(PATTERNS["phone"].match(value))


# ╔══════════════════════════════════════════════════════════════╗
# ║                     ПАРСЕРИ                                 ║
# ╚══════════════════════════════════════════════════════════════╝

def _parse_list(env_key: str) -> list[str]:
    """
    Зчитує рядок з .env і повертає список очищених непорожніх значень.

    TARGET_DOMAINS=example.com, test.com  →  ['example.com', 'test.com']
    """
    raw = os.getenv(env_key, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_and_validate(
    env_key: str,
    validator: callable,
    label: str,
) -> list[str]:
    """
    Парсить список з .env і валідує кожен елемент.
    Невалідні елементи логуються і пропускаються.
    """
    items = _parse_list(env_key)
    valid = []

    for item in items:
        if validator(item):
            valid.append(item)
        else:
            logger.warning(f"[config] Невалідний {label}: '{item}' — пропущено")

    return valid


# ╔══════════════════════════════════════════════════════════════╗
# ║                    ГОЛОВНА ФУНКЦІЯ                          ║
# ╚══════════════════════════════════════════════════════════════╝

def load_config() -> Config:
    """
    Завантажує, парсить і валідує всю конфігурацію з .env.

    Returns:
        Config — повністю заповнений конфіг-об'єкт

    Raises:
        ValueError — якщо не задано жодного таргету
    """

    # ── Таргети ──────────────────────────────────────────────────
    targets = Targets(
        domains=_parse_and_validate("TARGET_DOMAINS", _validate_domain, "domain"),
        emails= _parse_and_validate("TARGET_EMAILS",  _validate_email,  "email"),
        ips=    _parse_and_validate("TARGET_IPS",     _validate_ip,     "IP"),
        phones= _parse_and_validate("TARGET_PHONES",  _validate_phone,  "phone"),
    )

    if targets.is_empty():
        raise ValueError(
            "Не задано жодного таргету. "
            "Заповни TARGET_DOMAINS / TARGET_EMAILS / TARGET_IPS / TARGET_PHONES у .env"
        )

    # ── API ключі ─────────────────────────────────────────────────
    api_keys = ApiKeys(
        shodan=     os.getenv("SHODAN_API_KEY")     or None,
        hibp=       os.getenv("HIBP_API_KEY")       or None,
        hunter=     os.getenv("HUNTER_API_KEY")     or None,
        virustotal= os.getenv("VIRUSTOTAL_API_KEY") or None,
    )

    # ── Налаштування ──────────────────────────────────────────────
    settings = Settings(
        recon_ng_path=  os.getenv("RECON_NG_PATH",   "/usr/local/bin/recon-ng"),
        workspace=      os.getenv("WORKSPACE",        "osint_workspace"),
        output_dir=     os.getenv("OUTPUT_DIR",       "./reports"),
        log_level=      os.getenv("LOG_LEVEL",        "INFO").upper(),
        module_timeout= int(os.getenv("MODULE_TIMEOUT", "60")),
    )

    config = Config(targets=targets, api_keys=api_keys, settings=settings)

    # ── Лог підсумку ──────────────────────────────────────────────
    logger.info("─" * 50)
    logger.info("✅ Конфіг завантажено")
    logger.info(f"Таргети:\n{targets.summary()}")
    logger.info(f"API доступні: {', '.join(api_keys.available()) or 'жодного'}")
    logger.info(f"Workspace: {settings.workspace}")
    logger.info("─" * 50)

    return config

