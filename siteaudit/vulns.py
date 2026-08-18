"""Проверка найденных версий по базам уязвимостей.

Источников два, потому что ни один не покрывает всё:

* **OSV.dev** — библиотеки из npm и Packagist. Отвечает быстро, знает точные
  диапазоны уязвимых версий.
* **NVD** — серверное ПО (nginx, Apache, PHP) и движки вроде WordPress,
  которых в OSV нет. Сопоставление идёт по CPE-идентификатору версии.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

# Серверное ПО и движки: в OSV их нет, зато NVD сопоставляет по CPE.
# Шаблоны проверены запросами к API — продукт и вендор в них именно такие.
NVD_CPE: dict[str, str] = {
    "nginx": "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
    "Apache": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "PHP": "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
    "WordPress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
    "Drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
    "OpenResty": "cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*",
}

#: NVD без ключа отдаёт пять запросов в тридцать секунд — больше и не нужно.
NVD_MAX_LOOKUPS = 4

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

#: Технологии, для которых вообще есть источник уязвимостей.
CHECKABLE = set(NPM_PACKAGES) | set(PACKAGIST_PACKAGES) | set(NVD_CPE)


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


class NvdVulnerability:
    """Запись NVD, приведённая к тому же виду, что и запись OSV."""

    __slots__ = ("id", "summary", "severity", "aliases", "url")

    def __init__(self, cve: dict[str, Any]) -> None:
        self.id: str = cve.get("id", "")
        self.aliases: list[str] = []
        self.summary = next(
            (
                d.get("value", "").strip()
                for d in cve.get("descriptions", [])
                if d.get("lang") == "en"
            ),
            "",
        )
        self.severity = _nvd_severity(cve)
        self.url = f"https://nvd.nist.gov/vuln/detail/{self.id}"

    @property
    def label(self) -> str:
        return self.id


def _nvd_severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        value = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if isinstance(value, str) and value.upper() in SEVERITY_ORDER:
            return value.upper()
    return "UNKNOWN"


def clean_version(raw: str) -> str:
    """Оставляет числовую часть: заголовки вроде «8.1.2-1ubuntu2.14» CPE не понимает."""
    match = re.match(r"\d+(?:\.\d+)*", (raw or "").strip())
    return match.group(0) if match else ""


async def lookup_nvd(fetcher, name: str, version: str) -> list[NvdVulnerability] | None:
    """Уязвимости серверного ПО по CPE. Пустой список — чисто, None — не проверили."""
    template = NVD_CPE.get(name)
    number = clean_version(version)
    if not template or not number:
        return []

    cpe = quote(template.format(version=number), safe="")
    data = await fetcher.get_json(f"{NVD_URL}?cpeName={cpe}&resultsPerPage=50&noRejected=")
    if data is None:
        return None
    items = data.get("vulnerabilities")
    if not isinstance(items, list):
        return []

    vulns = [
        NvdVulnerability(item["cve"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("cve"), dict)
    ]
    vulns.sort(key=lambda v: -SEVERITY_ORDER.get(v.severity, 0))
    return vulns


@dataclass
class LookupResult:
    """Итог сверки: что найдено, сколько версий проверено и сколько запросов сорвалось."""

    found: dict[str, list[Any]] = field(default_factory=dict)
    checked: int = 0
    failed: int = 0
    sources: set[str] = field(default_factory=set)


async def lookup_many(fetcher, techs) -> LookupResult:
    out = LookupResult()
    versioned = [t for t in techs if t.version]

    osv_targets = [
        t for t in versioned if t.name in NPM_PACKAGES or t.name in PACKAGIST_PACKAGES
    ]
    nvd_targets = [t for t in versioned if t.name in NVD_CPE][:NVD_MAX_LOOKUPS]

    if osv_targets:
        out.sources.add("OSV.dev")
        results = await asyncio.gather(
            *[lookup(fetcher, t.name, t.version) for t in osv_targets],
            return_exceptions=True,
        )
        _collect(out, osv_targets, results)

    # NVD запрашиваем последовательно: без ключа он ограничивает частоту,
    # а параллельная пачка запросов гарантированно упрётся в лимит.
    if nvd_targets:
        out.sources.add("NVD")
        results = []
        for tech in nvd_targets:
            try:
                results.append(await lookup_nvd(fetcher, tech.name, tech.version))
            except Exception as exc:  # noqa: BLE001 — внешний сервис не роняет аудит
                results.append(exc)
        _collect(out, nvd_targets, results)

    return out


def _collect(out: LookupResult, targets, results) -> None:
    for tech, res in zip(targets, results):
        if res is None or isinstance(res, BaseException):
            out.failed += 1
            continue
        out.checked += 1
        if res:
            out.found.setdefault(tech.name, []).extend(res)
