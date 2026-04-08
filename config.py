"""Configuration loader for the source-oriented OSINT pipeline.

Responsibilities:
- load .env
- parse and validate targets from a single TARGETS variable
- expose API keys and runtime settings
- keep source toggles in one place
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+?$"
)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass(frozen=True)
class Target:
    value: str
    type: str  # domain | email | phone | ip


@dataclass(frozen=True)
class ApiKeys:
    shodan: str | None = None
    hibp: str | None = None
    hunter: str | None = None
    virustotal: str | None = None

    def available(self) -> list[str]:
        result: list[str] = []
        if self.shodan:
            result.append("shodan")
        if self.hibp:
            result.append("hibp")
        if self.hunter:
            result.append("hunter")
        if self.virustotal:
            result.append("virustotal")
        return result


@dataclass(frozen=True)
class SourceSettings:
    enabled_sources: tuple[str, ...] = ("recon_ng",)
    recon_ng_path: str = "/usr/local/bin/recon-ng"
    recon_workspace: str = "osint_workspace"


@dataclass(frozen=True)
class RuntimeSettings:
    output_dir: Path = Path("./reports")
    db_path: Path = Path("./storage/osint.db")
    log_level: str = "INFO"
    module_timeout: int = 60


@dataclass(frozen=True)
class Config:
    targets: tuple[Target, ...]
    api_keys: ApiKeys
    sources: SourceSettings
    runtime: RuntimeSettings

    def has_source(self, source_name: str) -> bool:
        return source_name in self.sources.enabled_sources


class ConfigError(ValueError):
    """Raised when environment configuration is invalid."""


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.fullmatch(value))


def _is_email(value: str) -> bool:
    return bool(_EMAIL_RE.fullmatch(value))


def _is_phone(value: str) -> bool:
    return bool(_PHONE_RE.fullmatch(value))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def detect_target_type(value: str) -> str:
    if _is_email(value):
        return "email"
    if _is_ip(value):
        return "ip"
    if _is_phone(value):
        return "phone"
    if _is_domain(value):
        return "domain"
    raise ConfigError(f"Unsupported target format: {value}")


def parse_targets(raw_targets: Iterable[str]) -> tuple[Target, ...]:
    parsed: list[Target] = []
    seen: set[tuple[str, str]] = set()

    for raw in raw_targets:
        value = raw.strip()
        if not value:
            continue

        target_type = detect_target_type(value)
        key = (target_type, value)
        if key in seen:
            continue

        seen.add(key)
        parsed.append(Target(value=value, type=target_type))

    if not parsed:
        raise ConfigError("TARGETS is empty. Add at least one domain, email, phone, or IP.")

    return tuple(parsed)


def _get_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _load_api_keys() -> ApiKeys:
    return ApiKeys(
        shodan=_get_env("SHODAN_API_KEY"),
        hibp=_get_env("HIBP_API_KEY"),
        hunter=_get_env("HUNTER_API_KEY"),
        virustotal=_get_env("VIRUSTOTAL_API_KEY"),
    )


def _load_sources() -> SourceSettings:
    enabled = tuple(_split_csv(os.getenv("ENABLED_SOURCES", "recon_ng")))
    if not enabled:
        raise ConfigError("ENABLED_SOURCES is empty. Enable at least one source.")

    return SourceSettings(
        enabled_sources=enabled,
        recon_ng_path=os.getenv("RECON_NG_PATH", "/usr/local/bin/recon-ng").strip(),
        recon_workspace=os.getenv("RECON_WORKSPACE", "osint_workspace").strip(),
    )


def _load_runtime() -> RuntimeSettings:
    log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in _VALID_LOG_LEVELS:
        raise ConfigError(f"Invalid LOG_LEVEL: {log_level}")

    module_timeout_raw = os.getenv("MODULE_TIMEOUT", "60").strip()
    try:
        module_timeout = int(module_timeout_raw)
    except ValueError as exc:
        raise ConfigError("MODULE_TIMEOUT must be an integer") from exc

    if module_timeout <= 0:
        raise ConfigError("MODULE_TIMEOUT must be greater than 0")

    return RuntimeSettings(
        output_dir=Path(os.getenv("OUTPUT_DIR", "./reports")).expanduser(),
        db_path=Path(os.getenv("DB_PATH", "./storage/osint.db")).expanduser(),
        log_level=log_level,
        module_timeout=module_timeout,
    )


def load_config() -> Config:
    targets = parse_targets(_split_csv(os.getenv("TARGETS")))
    api_keys = _load_api_keys()
    sources = _load_sources()
    runtime = _load_runtime()

    config = Config(
        targets=targets,
        api_keys=api_keys,
        sources=sources,
        runtime=runtime,
    )

    logger.info("Config loaded: %d target(s), sources=%s, api_keys=%s",
                len(config.targets),
                ",".join(config.sources.enabled_sources),
                ",".join(config.api_keys.available()) or "none")
    return config


__all__ = [
    "ApiKeys",
    "Config",
    "ConfigError",
    "RuntimeSettings",
    "SourceSettings",
    "Target",
    "detect_target_type",
    "load_config",
    "parse_targets",
]
