"""HTTP-слой: асинхронные запросы с замером TTFB, кэшем и ограничением параллелизма."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 siteaudit/0.1"
)


@dataclass
class Fetched:
    """Нормализованный результат HTTP-запроса."""

    url: str
    requested_url: str
    method: str = "GET"
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    content: bytes = b""
    text: str = ""
    ttfb: float | None = None
    total: float | None = None
    http_version: str = ""
    redirects: list[tuple[int, str]] = field(default_factory=list)
    transfer_size: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def has(self, name: str) -> bool:
        return name.lower() in self.headers


class Fetcher:
    """Единая точка сетевых запросов: кэширует ответы и держит один клиент."""

    def __init__(
        self,
        timeout: float = 20.0,
        concurrency: int = 10,
        user_agent: str = DEFAULT_UA,
        verify: bool = True,
        max_bytes: int = 5_000_000,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._sem = asyncio.Semaphore(concurrency)
        self._cache: dict[tuple[str, str, bool], Fetched] = {}
        self._lock = asyncio.Lock()
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=verify,
            http2=True,
            limits=limits,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "Fetcher":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def get(
        self,
        url: str,
        method: str = "GET",
        follow_redirects: bool = True,
        cache: bool = True,
        read_body: bool = True,
    ) -> Fetched:
        key = (method, url, follow_redirects)
        if cache and key in self._cache:
            return self._cache[key]

        result = await self._request(url, method, follow_redirects, read_body)
        if cache:
            async with self._lock:
                self._cache[key] = result
        return result

    async def head(self, url: str, cache: bool = True) -> Fetched:
        """HEAD с откатом на GET: часть серверов и CDN отвечают на HEAD отказом."""
        res = await self.get(url, method="HEAD", cache=cache, read_body=False)
        if res.error or res.status in (403, 405, 501):
            return await self.get(url, method="GET", cache=cache)
        return res

    async def post_json(self, url: str, payload: dict) -> dict | None:
        """POST с JSON для внешних API. Возвращает None при любой сетевой ошибке."""
        async with self._sem:
            try:
                resp = await self._client.post(url, json=payload)
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception:  # noqa: BLE001 — внешний сервис не должен ронять аудит
                return None

    async def _request(
        self, url: str, method: str, follow_redirects: bool, read_body: bool
    ) -> Fetched:
        out = Fetched(url=url, requested_url=url, method=method)
        async with self._sem:
            start = time.perf_counter()
            try:
                req = self._client.build_request(method, url)
                resp = await self._client.send(
                    req, stream=True, follow_redirects=follow_redirects
                )
                out.ttfb = time.perf_counter() - start
                try:
                    out.status = resp.status_code
                    out.headers = {k.lower(): v for k, v in resp.headers.items()}
                    out.raw_headers = [(k, v) for k, v in resp.headers.multi_items()]
                    out.http_version = resp.http_version
                    out.url = str(resp.url)
                    out.redirects = [(r.status_code, str(r.url)) for r in resp.history]
                    cl = resp.headers.get("content-length")
                    out.transfer_size = int(cl) if cl and cl.isdigit() else None
                    if read_body and method != "HEAD":
                        chunks: list[bytes] = []
                        got = 0
                        async for chunk in resp.aiter_bytes():
                            chunks.append(chunk)
                            got += len(chunk)
                            if got >= self.max_bytes:
                                break
                        out.content = b"".join(chunks)
                        out.text = _decode(out.content, resp)
                finally:
                    await resp.aclose()
                out.total = time.perf_counter() - start
            except httpx.HTTPError as exc:
                out.error = f"{type(exc).__name__}: {exc}"
                out.total = time.perf_counter() - start
            except Exception as exc:  # noqa: BLE001 — сеть непредсказуема
                out.error = f"{type(exc).__name__}: {exc}"
                out.total = time.perf_counter() - start
        return out

    async def gather(self, urls: list[str], method: str = "GET") -> list[Fetched]:
        tasks = [self.get(u, method=method) for u in urls]
        return list(await asyncio.gather(*tasks))


def _decode(content: bytes, resp: httpx.Response) -> str:
    for enc in (resp.charset_encoding, "utf-8", "cp1251"):
        if not enc:
            continue
        try:
            return content.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return content.decode("utf-8", errors="replace")
