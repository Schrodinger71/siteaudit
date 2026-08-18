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


def rel_values(tag) -> list[str]:
    """Значения атрибута rel тега в нижнем регистре.

    Нужна отдельная функция, потому что BeautifulSoup ведёт себя непоследовательно:
    `tag.get("rel")` возвращает список, а в функцию-фильтр `find_all(rel=...)`
    передаёт исходную строку. Из-за этого фильтры вида `rel=lambda v: "icon" in v`
    молча перебирают отдельные символы и не находят ничего.
    """
    rel = tag.get("rel") or []
    if isinstance(rel, str):
        rel = rel.split()
    return [str(value).lower() for value in rel]


def has_rel(tag, value: str) -> bool:
    """Точное совпадение одного из значений rel: canonical, stylesheet и т. п."""
    return value.lower() in rel_values(tag)


def has_icon_rel(tag) -> bool:
    """Любая иконка: icon, shortcut icon, apple-touch-icon, mask-icon."""
    return any("icon" in value for value in rel_values(tag))


def plural(count: int, one: str, few: str, many: str) -> str:
    """Русское склонение существительного при числительном: 1 группа, 2 группы, 5 групп."""
    tail = abs(count) % 100
    if 11 <= tail <= 14:
        return many
    tail %= 10
    if tail == 1:
        return one
    if 2 <= tail <= 4:
        return few
    return many


def counted(count: int, one: str, few: str, many: str) -> str:
    """То же, но сразу с числом: `counted(2, 'слово', 'слова', 'слов')` → «2 слова»."""
    return f"{count} {plural(count, one, few, many)}"


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


#: Ответы, однозначно означающие «страницы нет».
BROKEN_STATUSES = frozenset({404, 410})

#: Ответы защиты от роботов и ограничений доступа. Ссылка при этом рабочая:
#: Яндекс.Карты отдают 403 любому не-браузеру, ВКонтакте — 418 на HEAD,
#: 999 исторически отдаёт LinkedIn. Считать это битой ссылкой нельзя.
GUARDED_STATUSES = frozenset({401, 403, 405, 406, 418, 423, 429, 451, 503, 999})


def classify_link(status: int, error: str | None) -> str:
    """«broken» — страницы нет, «guarded» — проверить не дали, «ok» — жива."""
    if error:
        # Несуществующий домен — это действительно битая ссылка, а таймаут
        # или обрыв соединения могут быть случайными.
        lowered = error.lower()
        if "nameresolution" in lowered or "getaddrinfo" in lowered or "[errno 11001]" in lowered:
            return "broken"
        return "guarded"
    if status in BROKEN_STATUSES:
        return "broken"
    if status in GUARDED_STATUSES or 500 <= status < 600:
        return "guarded"
    if status >= 400:
        return "broken"
    return "ok"
