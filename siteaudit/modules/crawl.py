"""Проверки, которые видно только при обходе всего сайта, а не одной страницы."""

from __future__ import annotations

from collections import Counter

from ..context import AuditContext
from ..crawler import Crawler, CrawledPage, sitemap_urls
from ..models import ModuleResult, Severity
from ..utils import counted, human_ms, truncate
from .base import Module

THIN_WORDS = 150
DEEP_LEVEL = 3
SLOW_TTFB = 1.0


class CrawlModule(Module):
    key = "crawl"
    title = "Обход сайта"
    weight = 0.25

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        limit = ctx.options.crawl
        if limit <= 0:
            result.error = "обход не запускался (нужен флаг --crawl N)"
            return

        crawler = Crawler(
            ctx.fetcher,
            ctx.url,
            max_pages=limit,
            max_depth=ctx.options.depth,
            robots_txt=ctx.robots.text if ctx.robots and ctx.robots.status == 200 else "",
        )
        pages = await crawler.run()
        if not pages:
            result.error = "не удалось обойти ни одной страницы"
            return

        self._overview(result, pages, crawler)
        self._broken(result, pages)
        self._redirects(result, pages)
        self._duplicates(result, pages)
        self._meta_gaps(result, pages)
        self._indexing(result, pages)
        self._depth(result, pages)
        self._thin(result, pages)
        self._slow(result, pages)
        self._canonicals(result, pages)
        await self._sitemap(ctx, result, pages)

    # ------------------------------------------------------------- обзор

    def _overview(self, result: ModuleResult, pages: list[CrawledPage], crawler: Crawler) -> None:
        html_pages = [p for p in pages if p.ok and p.is_html]
        statuses = Counter(p.status if not p.error else 0 for p in pages)
        result.fact("Обойдено страниц", len(pages))
        result.fact("Максимальная глубина", max(p.depth for p in pages))
        result.fact(
            "Коды ответов",
            ", ".join(f"{code or 'ошибка'}: {n}" for code, n in sorted(statuses.items())),
        )
        timings = [p.ttfb for p in pages if p.ttfb]
        if timings:
            result.fact("Средний TTFB", human_ms(sum(timings) / len(timings)))
        if html_pages:
            avg_words = sum(p.words for p in html_pages) / len(html_pages)
            result.fact(
                "Средний объём текста",
                counted(round(avg_words), "слово", "слова", "слов"),
            )
        if crawler.blocked_by_robots:
            result.fact("Закрыто в robots.txt", len(crawler.blocked_by_robots))

    # ------------------------------------------------------------ находки

    def _broken(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        broken = [p for p in pages if p.error or p.status >= 400]
        if not broken:
            result.ok("crawl.broken", "Все обойдённые страницы отвечают корректно")
            return
        server_errors = [p for p in broken if p.status >= 500]
        result.add(
            "crawl.broken",
            f"Битые страницы: {len(broken)} из {len(pages)}",
            Severity.CRITICAL if server_errors else Severity.HIGH,
            "Страницы отдают ошибку, но на них есть внутренние ссылки — "
            "робот тратит на них краулинговый бюджет, пользователь упирается в тупик.",
            "Почините страницы или уберите ссылки на них. Если ссылка в шаблоне — "
            "она битая на всём сайте сразу.",
            evidence=[
                f"{p.status or 'ошибка'} — {truncate(p.url, 60)} (ссылка с {truncate(p.found_on, 40)})"
                for p in broken[:8]
            ],
        )

    def _redirects(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        redirected = [p for p in pages if p.redirects]
        chains = [p for p in redirected if len(p.redirects) >= 2]
        if chains:
            result.add(
                "crawl.redirect.chains",
                f"Цепочки редиректов внутри сайта ({len(chains)})",
                Severity.MEDIUM,
                "Внутренние ссылки ведут через несколько промежуточных адресов.",
                "Проставьте во внутренних ссылках сразу финальные URL — это экономит "
                "и время загрузки, и краулинговый бюджет.",
                evidence=[
                    f"{truncate(p.url, 50)} → {len(p.redirects)} шагов" for p in chains[:6]
                ],
            )
        elif redirected:
            result.add(
                "crawl.redirect.internal",
                f"Внутренние ссылки ведут на редиректы ({len(redirected)})",
                Severity.LOW,
                "",
                "Замените адреса в ссылках на конечные — обычно это следствие смены "
                "структуры URL или слэша в конце адреса.",
                evidence=[
                    f"{truncate(p.url, 45)} → {truncate(p.redirects[-1][1], 45)}"
                    for p in redirected[:5]
                ],
            )
        else:
            result.ok("crawl.redirects", "Внутренние ссылки ведут напрямую, без редиректов")

    def _duplicates(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        html = [p for p in pages if p.ok and p.is_html]

        titles: dict[str, list[str]] = {}
        descs: dict[str, list[str]] = {}
        for p in html:
            if p.title:
                titles.setdefault(p.title.lower(), []).append(p.url)
            if p.description:
                descs.setdefault(p.description.lower(), []).append(p.url)

        dup_titles = {t: u for t, u in titles.items() if len(u) > 1}
        dup_descs = {d: u for d, u in descs.items() if len(u) > 1}

        if dup_titles:
            affected = sum(len(u) for u in dup_titles.values())
            result.add(
                "crawl.duplicate.title",
                f"Дубли title: {counted(len(dup_titles), 'группа', 'группы', 'групп')}, "
                f"{counted(affected, 'страница', 'страницы', 'страниц')}",
                Severity.HIGH if affected > len(html) * 0.3 else Severity.MEDIUM,
                "Поисковик не понимает, чем страницы отличаются, и склеивает их между собой.",
                "Сделайте title уникальным: подставляйте в шаблон название товара, "
                "раздела или номер страницы пагинации.",
                evidence=[
                    f"«{truncate(t, 45)}» ×{len(u)} — {truncate(u[0], 40)}"
                    for t, u in list(dup_titles.items())[:5]
                ],
            )
        else:
            result.ok("crawl.duplicate.title", "Дублей title не найдено")

        if dup_descs:
            affected = sum(len(u) for u in dup_descs.values())
            result.add(
                "crawl.duplicate.description",
                f"Дубли description: {counted(len(dup_descs), 'группа', 'группы', 'групп')}, "
                f"{counted(affected, 'страница', 'страницы', 'страниц')}",
                Severity.MEDIUM,
                "Одинаковые сниппеты снижают кликабельность всей группы страниц.",
                "Генерируйте описание из содержимого страницы, а не одним шаблоном на раздел.",
                evidence=[
                    f"«{truncate(d, 45)}» ×{len(u)}" for d, u in list(dup_descs.items())[:5]
                ],
            )

    def _meta_gaps(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        html = [p for p in pages if p.ok and p.is_html]
        if not html:
            return
        no_title = [p for p in html if not p.title]
        no_desc = [p for p in html if not p.description]
        no_h1 = [p for p in html if p.h1_count == 0]
        many_h1 = [p for p in html if p.h1_count > 1]

        for items, key, label, severity, how in (
            (no_title, "title", "без title", Severity.HIGH,
             "Проверьте шаблон — скорее всего, заголовок не подставляется для этого типа страниц."),
            (no_desc, "description", "без meta description", Severity.MEDIUM,
             "Заполните описания или настройте автогенерацию из первого абзаца."),
            (no_h1, "h1", "без H1", Severity.MEDIUM,
             "Добавьте H1 в шаблон страницы."),
            (many_h1, "h1-multiple", "с несколькими H1", Severity.LOW,
             "Оставьте один H1 на страницу, остальные понизьте до H2."),
        ):
            if items:
                result.add(
                    f"crawl.meta.{key}",
                    f"Страницы {label}: {len(items)} из {len(html)}",
                    severity,
                    "",
                    how,
                    evidence=[truncate(p.url, 65) for p in items[:6]],
                )

        if not (no_title or no_desc or no_h1):
            result.ok("crawl.meta", "У всех обойдённых страниц заполнены title, description и H1")

    def _indexing(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        noindex = [p for p in pages if p.ok and p.noindex]
        if noindex:
            result.add(
                "crawl.noindex",
                f"Страницы закрыты от индексации: {len(noindex)}",
                Severity.MEDIUM,
                "На них ведут внутренние ссылки, но в поиск они не попадут.",
                "Проверьте, что это осознанно. Служебные страницы закрывать нормально, "
                "но noindex на карточках товаров или статьях — потерянный трафик.",
                evidence=[truncate(p.url, 65) for p in noindex[:6]],
            )

    def _depth(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        deep = [p for p in pages if p.depth > DEEP_LEVEL and p.ok]
        if deep:
            result.add(
                "crawl.depth",
                f"Страницы глубже {DEEP_LEVEL} кликов от главной: {len(deep)}",
                Severity.LOW,
                "Чем дальше страница от главной, тем реже её обходит робот и тем меньше "
                "веса до неё доходит.",
                "Сократите путь: добавьте разделы в меню, блоки перелинковки, "
                "HTML-карту сайта или фильтры с прямыми ссылками.",
                evidence=[f"глубина {p.depth} — {truncate(p.url, 55)}" for p in deep[:6]],
            )

    def _thin(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        html = [p for p in pages if p.ok and p.is_html]
        thin = [p for p in html if p.words < THIN_WORDS]
        if thin and html:
            share = len(thin) / len(html) * 100
            result.add(
                "crawl.thin",
                f"Страницы с тонким контентом: {len(thin)} из {len(html)} ({share:.0f}%)",
                Severity.MEDIUM if share > 40 else Severity.LOW,
                f"Меньше {THIN_WORDS} слов текста.",
                "Наполните страницы содержанием или закройте от индексации служебные. "
                "Массовые тонкие страницы — риск попасть под фильтр за низкое качество.",
                evidence=[
                    f"{counted(p.words, 'слово', 'слова', 'слов')} — {truncate(p.url, 55)}"
                    for p in thin[:6]
                ],
            )

    def _slow(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        slow = [p for p in pages if p.ttfb and p.ttfb > SLOW_TTFB]
        if slow:
            result.add(
                "crawl.slow",
                f"Медленные страницы: {len(slow)} (TTFB больше {human_ms(SLOW_TTFB)})",
                Severity.MEDIUM,
                "Отдельные разделы отвечают заметно дольше остальных.",
                "Посмотрите, что общего у этих страниц: тяжёлый запрос к базе, "
                "отсутствие кэша, генерация отчёта на лету.",
                evidence=[
                    f"{human_ms(p.ttfb)} — {truncate(p.url, 55)}"
                    for p in sorted(slow, key=lambda x: -(x.ttfb or 0))[:6]
                ],
            )

    def _canonicals(self, result: ModuleResult, pages: list[CrawledPage]) -> None:
        html = [p for p in pages if p.ok and p.is_html]
        mismatched = [
            p
            for p in html
            if p.canonical and p.canonical.rstrip("/").lower() != p.url.rstrip("/").lower()
        ]
        no_canonical = [p for p in html if not p.canonical]

        if no_canonical:
            result.add(
                "crawl.canonical.missing",
                f"Страницы без canonical: {len(no_canonical)} из {len(html)}",
                Severity.LOW,
                "",
                "Добавьте canonical в шаблон — это главная защита от дублей "
                "по UTM-меткам, сортировкам и фильтрам.",
                evidence=[truncate(p.url, 65) for p in no_canonical[:5]],
            )
        if mismatched:
            result.add(
                "crawl.canonical.mismatch",
                f"Canonical указывает на другой адрес: {len(mismatched)} страниц",
                Severity.MEDIUM,
                "Такие страницы сами себя исключают из поиска в пользу указанного URL.",
                "Убедитесь, что склейка осознанная. Частая ошибка — canonical "
                "на главную со всех страниц сразу.",
                evidence=[
                    f"{truncate(p.url, 40)} → {truncate(p.canonical or '', 40)}"
                    for p in mismatched[:6]
                ],
            )

    async def _sitemap(
        self, ctx: AuditContext, result: ModuleResult, pages: list[CrawledPage]
    ) -> None:
        urls = await sitemap_urls(ctx.fetcher, ctx.sitemap)
        if not urls:
            return

        in_sitemap = {u.rstrip("/").lower() for u in urls}
        crawled = {p.url.rstrip("/").lower() for p in pages if p.ok and p.is_html}
        result.fact("URL в sitemap.xml", len(in_sitemap))

        missing = sorted(crawled - in_sitemap)
        if missing:
            result.add(
                "crawl.sitemap.missing",
                f"Страниц нет в sitemap.xml: {len(missing)}",
                Severity.MEDIUM if len(missing) > len(crawled) * 0.3 else Severity.LOW,
                "Страницы доступны по ссылкам, но в карте сайта их нет.",
                "Перегенерируйте sitemap.xml и настройте его автообновление при "
                "публикации нового контента.",
                evidence=[truncate(u, 65) for u in missing[:6]],
            )
        else:
            result.ok("crawl.sitemap", "Все обойдённые страницы присутствуют в sitemap.xml")

        # Страницы-сироты ищем только если обход покрыл заметную часть карты
        if len(crawled) >= len(in_sitemap) * 0.8:
            orphans = sorted(in_sitemap - crawled)
            if orphans:
                result.add(
                    "crawl.sitemap.orphans",
                    f"Страницы-сироты: {len(orphans)}",
                    Severity.LOW,
                    "Есть в sitemap.xml, но при обходе на них не нашлось ни одной "
                    "внутренней ссылки.",
                    "Добавьте ссылки на эти страницы из меню, каталога или блоков "
                    "перелинковки — без ссылок они почти не получают веса.",
                    evidence=[truncate(u, 65) for u in orphans[:6]],
                )
