"""Проверка найденных версий библиотек по базе уязвимостей OSV.dev."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

OSV_URL = "https://api.osv.dev/v1/query"

# Наши имена технологий → имена пакетов в npm, где OSV даёт хорошее покрытие.
NPM_PACKAGES: dict[str, str] = {
    "jQuery": "jquery",
    "Bootstrap": "bootstrap",
    "Vue.js": "vue",
    "React": "react",
    "Angular": "@angular/core",
    "Swiper": "swiper",
    "Next.js": "next",
    "Nuxt": "nuxt",
    "Express": "express",
    "Gatsby": "gatsby",
}

# Пакеты PHP-экосистемы (Packagist) — там OSV тоже неплохо наполнен.
PACKAGIST_PACKAGES: dict[str, str] = {
    "Laravel": "laravel/framework",
    "Symfony": "symfony/symfony",
    "Drupal": "drupal/core",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


class Vulnerability:
    __slots__ = ("id", "summary", "severity", "aliases", "url")

    def __init__(self, raw: dict[str, Any]) -> None:
        self.id: str = raw.get("id", "")
        self.summary: str = (raw.get("summary") or raw.get("details") or "").strip()
        self.aliases: list[str] = [a for a in raw.get("aliases", []) if a.startswith("CVE-")]
        self.severity: str = _severity_of(raw)
        self.url = f"https://osv.dev/vulnerability/{self.id}"

    @property
    def label(self) -> str:
        """CVE читается людьми лучше, чем внутренний идентификатор GHSA."""
        return self.aliases[0] if self.aliases else self.id


def _severity_of(raw: dict[str, Any]) -> str:
    db = raw.get("database_specific") or {}
    value = db.get("severity")
    if isinstance(value, str) and value.upper() in SEVERITY_ORDER:
        return value.upper()
    for sev in raw.get("severity", []) or []:
        score = str(sev.get("score", ""))
        if score.startswith("CVSS:"):
            return _from_cvss(score)
    return "UNKNOWN"


def _from_cvss(vector: str) -> str:
    """Грубая оценка по вектору CVSS, когда числового балла в ответе нет."""
    if "/C:H" in vector and "/I:H" in vector:
        return "CRITICAL"
    if "/C:H" in vector or "/I:H" in vector:
        return "HIGH"
    return "MEDIUM"


async def lookup(fetcher, name: str, version: str) -> list[Vulnerability] | None:
    """Уязвимости конкретной версии пакета.

    Пустой список означает «проверено, чисто», а None — «проверить не удалось».
    Их нельзя путать: иначе недоступный OSV выглядел бы как отсутствие проблем.
    """
    if name in NPM_PACKAGES:
        package, ecosystem = NPM_PACKAGES[name], "npm"
    elif name in PACKAGIST_PACKAGES:
        package, ecosystem = PACKAGIST_PACKAGES[name], "Packagist"
    else:
        return []

    payload = {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
    data = await fetcher.post_json(OSV_URL, payload)
    if data is None:
        return None
    if not isinstance(data.get("vulns"), list):
        return []

    vulns = [Vulnerability(v) for v in data["vulns"] if isinstance(v, dict)]
    vulns.sort(key=lambda v: -SEVERITY_ORDER.get(v.severity, 0))
    return vulns


@dataclass
class LookupResult:
    """Итог сверки с OSV: что найдено, сколько проверено и сколько сорвалось."""

    found: dict[str, list[Vulnerability]] = field(default_factory=dict)
    checked: int = 0
    failed: int = 0


async def lookup_many(fetcher, techs) -> LookupResult:
    targets = [
        t
        for t in techs
        if t.version and (t.name in NPM_PACKAGES or t.name in PACKAGIST_PACKAGES)
    ]
    if not targets:
        return LookupResult()

    results = await asyncio.gather(
        *[lookup(fetcher, t.name, t.version) for t in targets],
        return_exceptions=True,
    )
    out = LookupResult()
    for tech, res in zip(targets, results):
        if res is None or isinstance(res, BaseException):
            out.failed += 1
            continue
        out.checked += 1
        if res:
            out.found[tech.name] = res
    return out
