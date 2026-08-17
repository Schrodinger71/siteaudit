"""Общий контекст аудита: то, что модули используют совместно."""

from __future__ import annotations

import asyncio
import random
import string
from dataclasses import dataclass, field
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .fetcher import Fetched, Fetcher
from .utils import abs_url, host_of, origin, same_site


@dataclass
class Options:
    timeout: float = 20.0
    concurrency: int = 10
    max_assets: int = 40
    max_links: int = 30
    crawl: int = 0
    depth: int = 3
    safe: bool = False
    insecure: bool = False
    check_cve: bool = True
    browser: bool = False
    user_agent: str | None = None


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001 — если lxml недоступен
        return BeautifulSoup(html, "html.parser")


@dataclass
class AuditContext:
    """Всё, что модули аудита читают: страница, robots, sitemap, базовый 404."""

    target: str
    fetcher: Fetcher
    options: Options
    page: Fetched = field(init=False)
    soup: BeautifulSoup = field(init=False)
    robots: Fetched | None = None
    sitemap: Fetched | None = None
    soft404: Fetched | None = None
    http_probe: Fetched | None = None
    notes: list[str] = field(default_factory=list)
    techs: list = field(default_factory=list)  # list[Tech], заполняет TechModule
    screenshot: str | None = None  # data:image/jpeg;base64,… от модуля vitals

    def tech(self, name: str):
        """Возвращает обнаруженную технологию по имени или None."""
        for t in self.techs:
            if t.name.lower() == name.lower():
                return t
        return None

    @property
    def url(self) -> str:
        return self.page.url

    @property
    def origin(self) -> str:
        return origin(self.page.url)

    @property
    def host(self) -> str:
        return host_of(self.page.url)

    @property
    def is_https(self) -> bool:
        return urlparse(self.page.url).scheme == "https"

    @property
    def html(self) -> str:
        return self.page.text

    def links(self) -> list[tuple[str, str, dict]]:
        """(абсолютный url, текст, атрибуты) для всех <a href>."""
        out: list[tuple[str, str, dict]] = []
        for a in self.soup.find_all("a", href=True):
            u = abs_url(self.url, a.get("href", ""))
            if u:
                out.append((u, a.get_text(" ", strip=True), a.attrs))
        return out

    def internal_links(self) -> list[str]:
        seen: list[str] = []
        known: set[str] = set()
        for u, _, _ in self.links():
            if same_site(u, self.url) and u not in known:
                known.add(u)
                seen.append(u)
        return seen

    def external_links(self) -> list[tuple[str, dict]]:
        return [(u, attrs) for u, _, attrs in self.links() if not same_site(u, self.url)]

    def resources(self) -> dict[str, list[str]]:
        """Ссылки на подключаемые ресурсы, сгруппированные по типу."""
        res: dict[str, list[str]] = {"script": [], "style": [], "image": [], "font": [], "other": []}
        for tag in self.soup.find_all("script", src=True):
            u = abs_url(self.url, tag["src"])
            if u:
                res["script"].append(u)
        for tag in self.soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel", [])).lower()
            u = abs_url(self.url, tag["href"])
            if not u:
                continue
            if "stylesheet" in rel:
                res["style"].append(u)
            elif "preload" in rel and tag.get("as") == "font":
                res["font"].append(u)
            elif "icon" in rel:
                res["other"].append(u)
        for tag in self.soup.find_all("img"):
            src = tag.get("src") or tag.get("data-src") or ""
            u = abs_url(self.url, src)
            if u:
                res["image"].append(u)
        for tag in self.soup.find_all("source", srcset=True):
            first = tag["srcset"].split(",")[0].strip().split(" ")[0]
            u = abs_url(self.url, first)
            if u:
                res["image"].append(u)
        for key in res:
            res[key] = list(dict.fromkeys(res[key]))
        return res

    def meta(self, name: str) -> str | None:
        tag = self.soup.find("meta", attrs={"name": lambda v: v and v.lower() == name.lower()})
        if tag and tag.get("content"):
            return tag["content"].strip()
        return None

    def meta_property(self, prop: str) -> str | None:
        tag = self.soup.find(
            "meta", attrs={"property": lambda v: v and v.lower() == prop.lower()}
        )
        if tag and tag.get("content"):
            return tag["content"].strip()
        return None


async def build_context(target: str, fetcher: Fetcher, options: Options) -> AuditContext:
    """Загружает главную страницу и сопутствующие файлы."""
    page = await fetcher.get(target)
    ctx = AuditContext(target=target, fetcher=fetcher, options=options)
    ctx.page = page
    ctx.soup = _soup(page.text if page.ok else "")
    if not page.ok:
        return ctx

    base = ctx.origin
    noise = "".join(random.choices(string.ascii_lowercase, k=14))
    http_url = "http://" + ctx.host + "/"

    robots, sitemap, soft404, http_probe = await asyncio.gather(
        fetcher.get(f"{base}/robots.txt"),
        fetcher.get(f"{base}/sitemap.xml"),
        fetcher.get(f"{base}/{noise}-siteaudit-404"),
        fetcher.get(http_url, follow_redirects=False, cache=False),
    )
    ctx.robots = robots
    ctx.sitemap = sitemap
    ctx.soft404 = soft404
    ctx.http_probe = http_probe
    return ctx
