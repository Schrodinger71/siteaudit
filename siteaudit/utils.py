"""Мелкие хелперы, общие для всех модулей."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_url(raw: str) -> str:
    """Приводит пользовательский ввод к полноценному URL."""
    raw = raw.strip()
    if not raw:
        raise ValueError("пустой URL")
    if not _SCHEME_RE.match(raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"не удалось разобрать URL: {raw}")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))


def origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def registrable(hostname: str) -> str:
    """Грубое приведение хоста к «домену второго уровня» без внешних зависимостей."""
    parts = (hostname or "").lower().lstrip(".").split(".")
    if len(parts) < 3:
        return ".".join(parts)
    # com.ru, co.uk, org.ua и подобные составные зоны
    two_level = {"co", "com", "net", "org", "gov", "edu", "ac", "in", "pp"}
    if parts[-2] in two_level and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(a: str, b: str) -> bool:
    return registrable(host_of(a)) == registrable(host_of(b))


def abs_url(base: str, link: str) -> str | None:
    """Абсолютизирует ссылку, отбрасывая нерелевантные схемы."""
    if not link:
        return None
    link = link.strip()
    low = link.lower()
    if low.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "sms:", "whatsapp:")):
        return None
    try:
        joined = urljoin(base, link)
    except ValueError:
        return None
    if not joined.lower().startswith(("http://", "https://")):
        return None
    return joined.split("#", 1)[0]


def human_size(num: float | None) -> str:
    if num is None:
        return "—"
    step = 1024.0
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if abs(num) < step or unit == "ГБ":
            if unit == "Б":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= step
    return f"{num:.1f} ГБ"


def human_ms(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    ms = seconds * 1000
    if ms < 1000:
        return f"{ms:.0f} мс"
    return f"{seconds:.2f} с"


def truncate(text: str, limit: int = 120) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def pct(part: float, whole: float) -> float:
    return 0.0 if not whole else part / whole * 100.0


def similarity(a: str, b: str) -> float:
    """Быстрая мера похожести двух текстов (доля общих 8-символьных шинглов)."""
    if not a or not b:
        return 0.0
    a, b = a[:20000], b[:20000]
    sa = {a[i : i + 8] for i in range(0, len(a) - 8, 4)}
    sb = {b[i : i + 8] for i in range(0, len(b) - 8, 4)}
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)
