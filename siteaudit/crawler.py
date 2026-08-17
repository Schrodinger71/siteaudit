"""Обход сайта в ширину: собирает данные по каждой странице для модуля crawl."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from .fetcher import Fetched, Fetcher
from .utils import abs_url, has_rel, same_site

# Расширения, которые незачем скачивать и парсить как страницы
SKIP_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt",
    "zip", "rar", "7z", "tar", "gz", "exe", "msi", "dmg", "apk",
    "mp3", "mp4", "avi", "mov", "webm", "wav", "ogg",
    "css", "js", "json", "xml", "rss", "atom", "txt",
}


@dataclass
class CrawledPage:
    """Всё, что нас интересует в одной странице сайта."""

    url: str
    depth: int
    status: int = 0
    title: str = ""
    description: str = ""
    h1_count: int = 0
    canonical: str | None = None
    noindex: bool = False
    words: int = 0
    size: int = 0
    ttfb: float | None = None
    content_type: str = ""
    redirects: list[tuple[int, str]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    found_on: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type


class Crawler:
    """Обход в ширину с ограничением по числу страниц и глубине."""

    def __init__(
        self,
        fetcher: Fetcher,
        start_url: str,
        max_pages: int = 50,
        max_depth: int = 3,
        robots_txt: str = "",
        user_agent: str = "*",
    ) -> None:
        self.fetcher = fetcher
        self.start_url = start_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.user_agent = user_agent
        self.blocked_by_robots: list[str] = []
        self._robots = _load_robots(robots_txt)

    async def run(self) -> list[CrawledPage]:
        pages: list[CrawledPage] = []
        seen: set[str] = {_key(self.start_url)}
        frontier: list[tuple[str, str]] = [(self.start_url, "")]
        depth = 0

        while frontier and len(pages) < self.max_pages and depth <= self.max_depth:
            batch = frontier[: self.max_pages - len(pages)]
            frontier = frontier[len(batch) :]

            results = await asyncio.gather(
                *[self._visit(url, depth, found_on) for url, found_on in batch]
            )
            pages.extend(results)

            if depth == self.max_depth:
                break

            next_frontier: list[tuple[str, str]] = []
            for page in results:
                for link in page.links:
                    key = _key(link)
                    if key in seen:
                        continue
                    seen.add(key)
                    if not self._allowed(link):
                        self.blocked_by_robots.append(link)
                        continue
                    next_frontier.append((link, page.url))
            frontier.extend(next_frontier)
            depth += 1

        return pages

    def _allowed(self, url: str) -> bool:
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch(self.user_agent, url)
        except Exception:  # noqa: BLE001 — кривой robots.txt не должен рушить обход
            return True

    async def _visit(self, url: str, depth: int, found_on: str) -> CrawledPage:
        page = CrawledPage(url=url, depth=depth, found_on=found_on)
        resp: Fetched = await self.fetcher.get(url)

        page.status = resp.status
        page.error = resp.error
        page.content_type = resp.content_type
        page.size = resp.size
        page.ttfb = resp.ttfb
        page.redirects = resp.redirects

        if not resp.ok or not page.is_html:
            return page

        soup = _parse(resp.text)
        title = soup.find("title")
        page.title = " ".join(title.get_text().split()) if title else ""

        desc = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        page.description = (desc.get("content") or "").strip() if desc else ""

        page.h1_count = len(soup.find_all("h1"))

        canonical = next(
            (t for t in soup.find_all("link", href=True) if has_rel(t, "canonical")), None
        )
        if canonical:
            page.canonical = abs_url(resp.url, canonical["href"])

        robots_meta = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        meta_value = (robots_meta.get("content") or "").lower() if robots_meta else ""
        page.noindex = "noindex" in meta_value or "noindex" in resp.header("x-robots-tag").lower()

        for tag in soup.find_all(["script", "style", "noscript", "template"]):
            tag.decompose()
        page.words = len(re.findall(r"[\w\-]+", soup.get_text(" ", strip=True)))

        page.links = _extract_links(soup, resp.url)
        return page


def _extract_links(soup: BeautifulSoup, base: str) -> list[str]:
    out: list[str] = []
    known: set[str] = set()
    for a in soup.find_all("a", href=True):
        url = abs_url(base, a["href"])
        if not url or not same_site(url, base):
            continue
        if _extension(url) in SKIP_EXTENSIONS:
            continue
        key = _key(url)
        if key not in known:
            known.add(key)
            out.append(url)
    return out


def _extension(url: str) -> str:
    tail = url.split("?", 1)[0].rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[1].lower() if "." in tail else ""


def _key(url: str) -> str:
    """Ключ дедупликации: без якоря и без завершающего слэша."""
    return url.split("#", 1)[0].rstrip("/").lower()


def _parse(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001 — если lxml не установлен
        return BeautifulSoup(html, "html.parser")


def _load_robots(body: str) -> RobotFileParser | None:
    if not body:
        return None
    parser = RobotFileParser()
    try:
        parser.parse(body.splitlines())
    except Exception:  # noqa: BLE001
        return None
    return parser


async def sitemap_urls(fetcher: Fetcher, sitemap: Fetched | None, limit: int = 2000) -> list[str]:
    """Достаёт список URL из sitemap.xml, разворачивая индекс карт на один уровень."""
    if not sitemap or sitemap.status != 200:
        return []

    text = sitemap.text
    if "<sitemapindex" in text[:2000]:
        children = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)[:5]
        if not children:
            return []
        parts = await asyncio.gather(*[fetcher.get(u) for u in children])
        urls: list[str] = []
        for part in parts:
            if part.status == 200:
                urls.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", part.text))
            if len(urls) >= limit:
                break
        return urls[:limit]

    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)[:limit]
