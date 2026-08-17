"""Аудит производительности: скорость ответа, вес страницы, ресурсы, кэш, картинки."""

from __future__ import annotations

import asyncio
import re

from ..context import AuditContext
from ..fetcher import Fetched
from ..images import PILLOW_AVAILABLE, WEBP_QUALITY, WORTH_IT
from ..images import analyze as analyze_images
from ..models import ModuleResult, Severity
from ..utils import abs_url, counted, has_rel, human_ms, human_size, pct, truncate
from .base import Module

TTFB_GOOD, TTFB_OK = 0.2, 0.6
HTML_GOOD, HTML_WARN = 100_000, 300_000
PAGE_GOOD, PAGE_WARN = 1_500_000, 3_000_000
MODERN_IMAGE = {"webp", "avif", "svg"}
HEAVY_IMAGE = 300_000


class PerformanceModule(Module):
    key = "performance"
    title = "Производительность"
    weight = 0.30

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        page = ctx.page
        if not page.ok:
            result.error = page.error or f"HTTP {page.status}"
            return

        self._timing(ctx, result)
        self._html_size(ctx, result)
        self._compression(ctx, result)
        self._protocol(ctx, result)
        self._redirects(ctx, result)
        self._render_blocking(ctx, result)
        self._inline_weight(ctx, result)
        self._image_markup(ctx, result)
        await self._assets(ctx, result)

    # --------------------------------------------------------------- время

    def _timing(self, ctx: AuditContext, result: ModuleResult) -> None:
        ttfb = ctx.page.ttfb or 0.0
        result.fact("TTFB (время до первого байта)", human_ms(ttfb))
        result.fact("Загрузка HTML", human_ms(ctx.page.total))

        if ttfb > 1.5:
            result.add(
                "perf.ttfb.critical",
                f"Очень медленный ответ сервера — TTFB {human_ms(ttfb)}",
                Severity.CRITICAL,
                "Всё остальное на странице начинает грузиться только после этого времени.",
                "Ищите причину на бэкенде: тяжёлые SQL-запросы без индексов, отсутствие "
                "кэширования, слабый тариф хостинга. Включите полностраничное кэширование "
                "и OPcache/Redis, вынесите тяжёлую логику в фон.",
            )
        elif ttfb > TTFB_OK:
            result.add(
                "perf.ttfb.slow",
                f"Медленный ответ сервера — TTFB {human_ms(ttfb)}",
                Severity.HIGH,
                f"Ориентир: до {human_ms(TTFB_GOOD)} — отлично, до {human_ms(TTFB_OK)} — приемлемо.",
                "Включите кэширование страниц, проверьте время генерации на бэкенде, "
                "поставьте CDN перед сайтом. TTFB напрямую входит в LCP.",
            )
        elif ttfb > TTFB_GOOD:
            result.add(
                "perf.ttfb.medium",
                f"TTFB {human_ms(ttfb)} — есть куда ускоряться",
                Severity.LOW,
                "",
                "Кэширование на стороне сервера и CDN обычно опускают TTFB ниже 200 мс.",
            )
        else:
            result.ok("perf.ttfb", f"Быстрый ответ сервера — TTFB {human_ms(ttfb)}")

    def _html_size(self, ctx: AuditContext, result: ModuleResult) -> None:
        size = ctx.page.size
        transfer = ctx.page.transfer_size
        result.fact("Размер HTML", f"{human_size(size)} (передано {human_size(transfer)})")

        if size > HTML_WARN:
            result.add(
                "perf.html.huge",
                f"Очень тяжёлый HTML — {human_size(size)}",
                Severity.HIGH,
                "Браузер должен скачать и распарсить весь документ до отрисовки.",
                "Уберите инлайн-данные (гигантские JSON в разметке), вынесите стили и скрипты "
                "в файлы, включите пагинацию/ленивую подгрузку длинных списков.",
            )
        elif size > HTML_GOOD:
            result.add(
                "perf.html.big",
                f"Крупный HTML — {human_size(size)}",
                Severity.LOW,
                f"Комфортный ориентир — до {human_size(HTML_GOOD)}.",
                "Проверьте, нет ли в разметке больших инлайн-блоков данных или base64-картинок.",
            )
        else:
            result.ok("perf.html", f"Размер HTML в норме — {human_size(size)}")

    def _compression(self, ctx: AuditContext, result: ModuleResult) -> None:
        enc = ctx.page.header("content-encoding").lower()
        result.fact("Сжатие HTML", enc or "нет")
        if not enc:
            result.add(
                "perf.compression.off",
                "HTML отдаётся без сжатия",
                Severity.HIGH,
                "Нет заголовка Content-Encoding — текст летит в исходном виде.",
                "Включите Brotli (или хотя бы gzip) для text/html, css, js, svg, json. "
                "Обычно это экономит 60–80% трафика и делается одной строкой в конфиге сервера.",
            )
        elif enc == "gzip":
            result.add(
                "perf.compression.gzip",
                "Используется gzip вместо Brotli",
                Severity.LOW,
                "Brotli сжимает текст на 15–20% плотнее при тех же затратах CPU.",
                "Включите brotli в nginx (`brotli on; brotli_types ...`) или на уровне CDN.",
            )
        else:
            result.ok("perf.compression", f"Сжатие включено: {enc}")

    def _protocol(self, ctx: AuditContext, result: ModuleResult) -> None:
        version = ctx.page.http_version or "?"
        result.fact("Версия HTTP", version)
        if version.startswith("HTTP/1"):
            result.add(
                "perf.http1",
                f"Сайт работает по {version}",
                Severity.MEDIUM,
                "Без мультиплексирования каждый ресурс ждёт своей очереди в соединении.",
                "Включите HTTP/2 (в nginx: `listen 443 ssl http2;`), а лучше HTTP/3. "
                "Это бесплатное ускорение для страниц с большим числом файлов.",
            )
        else:
            result.ok("perf.http", f"Современный протокол: {version}")

    def _redirects(self, ctx: AuditContext, result: ModuleResult) -> None:
        chain = ctx.page.redirects
        result.fact("Цепочка редиректов", f"{len(chain)} шагов" if chain else "нет")
        if len(chain) >= 2:
            result.add(
                "perf.redirect.chain",
                f"Цепочка из {len(chain)} редиректов до целевой страницы",
                Severity.MEDIUM,
                " → ".join(f"{code} {truncate(url, 45)}" for code, url in chain[:4]),
                "Каждый редирект — это лишний round-trip (часто +100–300 мс на мобильной сети). "
                "Настройте один прямой 301 на финальный URL.",
            )
        elif chain:
            result.add(
                "perf.redirect.one",
                f"Один редирект перед загрузкой ({chain[0][0]})",
                Severity.LOW,
                f"{truncate(chain[0][1], 70)} → {truncate(ctx.page.url, 70)}",
                "Нормально для http→https и www-склейки. Убедитесь, что во внешних "
                "материалах и рекламе указан уже финальный адрес.",
            )
        else:
            result.ok("perf.redirect", "Прямой ответ без редиректов")

    def _render_blocking(self, ctx: AuditContext, result: ModuleResult) -> None:
        head = ctx.soup.find("head")
        if not head:
            return
        blocking_js = [
            s
            for s in head.find_all("script", src=True)
            if not s.has_attr("async") and not s.has_attr("defer") and s.get("type") != "module"
        ]
        css_links = [t for t in head.find_all("link") if has_rel(t, "stylesheet")]
        result.fact("Блокирующих скриптов в <head>", len(blocking_js))
        result.fact("CSS-файлов в <head>", len(css_links))

        if blocking_js:
            result.add(
                "perf.render.js",
                f"{counted(len(blocking_js), 'блокирующий скрипт', 'блокирующих скрипта', 'блокирующих скриптов')}"
                " в <head>",
                Severity.HIGH if len(blocking_js) > 2 else Severity.MEDIUM,
                "Парсинг HTML останавливается, пока такой скрипт не скачается и не выполнится.",
                "Добавьте defer (или async для независимых счётчиков), либо перенесите "
                "подключение в конец <body>. Счётчики аналитики всегда грузите асинхронно.",
                evidence=[truncate(s["src"], 70) for s in blocking_js[:5]],
            )
        else:
            result.ok("perf.render.js", "Блокирующих скриптов в <head> нет")

        if len(css_links) > 4:
            result.add(
                "perf.render.css",
                f"Много отдельных CSS-файлов ({len(css_links)})",
                Severity.LOW,
                "Каждый файл в <head> блокирует первую отрисовку.",
                "Соберите стили в один-два бандла, вынесите критический CSS инлайном, "
                "остальное подгружайте с media=\"print\" onload или через preload.",
            )

    def _inline_weight(self, ctx: AuditContext, result: ModuleResult) -> None:
        inline_js = sum(len(s.get_text() or "") for s in ctx.soup.find_all("script", src=False))
        inline_css = sum(len(s.get_text() or "") for s in ctx.soup.find_all("style"))
        result.fact("Инлайн JS/CSS", f"{human_size(inline_js)} / {human_size(inline_css)}")

        if inline_js > 60_000:
            result.add(
                "perf.inline.js",
                f"Много инлайн-JS в разметке ({human_size(inline_js)})",
                Severity.MEDIUM,
                "Инлайн-код нельзя закэшировать — он скачивается заново с каждой страницей.",
                "Вынесите скрипты в отдельные .js файлы с длинным Cache-Control. "
                "Инлайном оставьте только то, что нужно до первой отрисовки.",
            )
        if inline_css > 60_000:
            result.add(
                "perf.inline.css",
                f"Много инлайн-CSS ({human_size(inline_css)})",
                Severity.LOW,
                "",
                "Оставьте инлайном только критический CSS «первого экрана», остальное — в файл.",
            )

        base64_imgs = len(re.findall(r'src="data:image/[^"]{5000,}"', ctx.html))
        if base64_imgs:
            result.add(
                "perf.inline.base64",
                f"Крупные изображения в base64 прямо в HTML ({base64_imgs} шт.)",
                Severity.MEDIUM,
                "Base64 раздувает HTML на треть от веса картинки и не кэшируется отдельно.",
                "Замените на обычные <img src> с файлами — они закэшируются и загрузятся параллельно.",
            )

    def _image_markup(self, ctx: AuditContext, result: ModuleResult) -> None:
        imgs = ctx.soup.find_all("img")
        if not imgs:
            return
        no_dims = [i for i in imgs if not (i.get("width") and i.get("height"))]
        no_lazy = [i for i in imgs if (i.get("loading") or "").lower() != "lazy"]

        if len(no_dims) > len(imgs) * 0.3:
            result.add(
                "perf.img.dimensions",
                f"У {len(no_dims)} из {len(imgs)} картинок не заданы width/height",
                Severity.MEDIUM,
                "Браузер не знает размер до загрузки — контент прыгает, растёт CLS.",
                "Проставьте атрибуты width и height (или aspect-ratio в CSS) всем изображениям. "
                "CLS — одна из трёх метрик Core Web Vitals.",
            )
        else:
            result.ok("perf.img.dimensions", "Размеры изображений заданы")

        if len(imgs) > 8 and len(no_lazy) > len(imgs) * 0.5:
            result.add(
                "perf.img.lazy",
                f"Ленивая загрузка не используется ({len(no_lazy)} из {len(imgs)} картинок)",
                Severity.MEDIUM,
                "Все изображения грузятся сразу, включая те, что далеко за экраном.",
                'Добавьте loading="lazy" всем картинкам ниже первого экрана. '
                'Картинке первого экрана, наоборот, поставьте fetchpriority="high".',
            )

        picture = ctx.soup.find_all("picture")
        srcset = [i for i in imgs if i.get("srcset")]
        if not picture and not srcset and len(imgs) > 4:
            result.add(
                "perf.img.responsive",
                "Нет адаптивных изображений (srcset / <picture>)",
                Severity.LOW,
                "Мобильные устройства скачивают десктопные версии картинок целиком.",
                "Отдавайте разные размеры через srcset/sizes и современные форматы "
                "через <picture> с fallback.",
            )

    # ------------------------------------------------------------- ресурсы

    async def _assets(self, ctx: AuditContext, result: ModuleResult) -> None:
        res = ctx.resources()
        all_urls: list[tuple[str, str]] = []
        for kind in ("style", "script", "image", "font", "other"):
            for u in res[kind]:
                all_urls.append((kind, u))

        result.fact(
            "Ресурсов на странице",
            f"всего {len(all_urls)} (JS: {len(res['script'])}, CSS: {len(res['style'])}, "
            f"IMG: {len(res['image'])})",
        )

        if len(all_urls) > 80:
            result.add(
                "perf.requests.many",
                f"Очень много подключаемых файлов ({len(all_urls)})",
                Severity.MEDIUM,
                "Каждый файл — отдельный запрос, соединение и очередь.",
                "Соберите бандлы, объедините иконки в спрайт/шрифт, уберите неиспользуемые "
                "библиотеки и плагины CMS.",
            )

        sample = all_urls[: ctx.options.max_assets]
        if not sample:
            return
        responses: list[Fetched] = await asyncio.gather(
            *[ctx.fetcher.get(u) for _, u in sample]
        )

        total = ctx.page.size
        by_kind: dict[str, int] = {}
        heavy: list[tuple[str, int]] = []
        no_cache: list[str] = []
        uncompressed: list[str] = []
        legacy_images: list[tuple[str, int]] = []
        failed: list[str] = []
        image_payloads: list[tuple[str, bytes, int | None]] = []
        shown_widths = _displayed_widths(ctx)

        for (kind, url), resp in zip(sample, responses):
            if not resp.ok:
                failed.append(f"{resp.status or 'ошибка'} — {truncate(url, 60)}")
                continue
            size = resp.size or (resp.transfer_size or 0)
            total += size
            by_kind[kind] = by_kind.get(kind, 0) + size
            if size > 200_000:
                heavy.append((url, size))

            cache = resp.header("cache-control").lower()
            max_age = re.search(r"max-age=(\d+)", cache)
            long_cache = bool(max_age and int(max_age.group(1)) >= 86400) or "immutable" in cache
            if not long_cache and "no-store" not in cache:
                no_cache.append(truncate(url, 70))

            ctype = resp.content_type
            is_text = ctype.startswith("text/") or any(
                x in ctype for x in ("javascript", "json", "xml", "svg")
            )
            if is_text and not resp.header("content-encoding") and size > 5000:
                uncompressed.append(truncate(url, 70))

            if kind == "image":
                fmt = ctype.split("/")[-1]
                if fmt not in MODERN_IMAGE and size > HEAVY_IMAGE:
                    legacy_images.append((url, size))
                if resp.content:
                    image_payloads.append((url, resp.content, shown_widths.get(url)))

        result.fact("Вес страницы (выборка)", human_size(total))
        for kind, label in (("script", "JS"), ("style", "CSS"), ("image", "Изображения")):
            if by_kind.get(kind):
                result.fact(f"Вес: {label}", human_size(by_kind[kind]))

        if len(sample) < len(all_urls):
            result.add(
                "perf.assets.sampled",
                f"Взвешено {len(sample)} из {len(all_urls)} ресурсов",
                Severity.INFO,
                "Реальный вес страницы больше. Увеличьте лимит флагом --assets.",
            )

        if total > PAGE_WARN:
            result.add(
                "perf.weight.huge",
                f"Страница очень тяжёлая — {human_size(total)}",
                Severity.HIGH,
                "На мобильном интернете такая страница грузится больше 10 секунд.",
                "Сожмите изображения и переведите в WebP/AVIF, выкиньте неиспользуемый JS, "
                "разделите бандл по маршрутам (code splitting).",
            )
        elif total > PAGE_GOOD:
            result.add(
                "perf.weight.big",
                f"Заметный вес страницы — {human_size(total)}",
                Severity.MEDIUM,
                f"Комфортный ориентир — до {human_size(PAGE_GOOD)}.",
                "Начните с изображений: обычно они дают 60–70% веса.",
            )
        else:
            result.ok("perf.weight", f"Вес страницы в норме — {human_size(total)}")

        if heavy:
            result.add(
                "perf.assets.heavy",
                f"Тяжёлые файлы ({len(heavy)} шт. больше 200 КБ)",
                Severity.MEDIUM,
                "Самые крупные ресурсы держат загрузку дольше всего.",
                "Сожмите изображения, минифицируйте и разделите JS-бандлы, "
                "подгружайте тяжёлые виджеты по требованию.",
                evidence=[
                    f"{human_size(s)} — {truncate(u, 60)}"
                    for u, s in sorted(heavy, key=lambda x: -x[1])[:6]
                ],
            )

        measured = await self._image_savings(result, image_payloads)
        if legacy_images and not measured:
            result.add(
                "perf.img.format",
                f"Крупные изображения в устаревших форматах ({len(legacy_images)})",
                Severity.MEDIUM,
                "JPEG/PNG весят в 1,5–3 раза больше WebP при том же качестве.",
                "Переведите картинки в WebP или AVIF, отдавайте через <picture> "
                "с fallback на старый формат.",
                evidence=[
                    f"{human_size(s)} — {truncate(u, 60)}"
                    for u, s in sorted(legacy_images, key=lambda x: -x[1])[:6]
                ],
            )

        if uncompressed:
            result.add(
                "perf.assets.uncompressed",
                f"Текстовые ресурсы без сжатия ({len(uncompressed)})",
                Severity.MEDIUM,
                "JS/CSS отдаются без gzip/brotli.",
                "Добавьте нужные MIME-типы в конфигурацию сжатия на сервере или CDN.",
                evidence=uncompressed[:6],
            )

        if no_cache:
            share = pct(len(no_cache), len(sample))
            result.add(
                "perf.assets.cache",
                f"У {len(no_cache)} ресурсов нет длительного кэширования ({share:.0f}%)",
                Severity.MEDIUM if share > 40 else Severity.LOW,
                "Cache-Control отсутствует или max-age меньше суток — повторные визиты "
                "качают статику заново.",
                "Для статики с версионированными именами ставьте "
                "`Cache-Control: public, max-age=31536000, immutable`.",
                evidence=no_cache[:6],
            )
        else:
            result.ok("perf.assets.cache", "Статика кэшируется надолго")

        if failed:
            result.add(
                "perf.assets.failed",
                f"Ресурсы не загрузились ({len(failed)})",
                Severity.HIGH,
                "Битые CSS/JS/картинки ломают вёрстку и функциональность.",
                "Проверьте пути и наличие файлов на сервере.",
                evidence=failed[:8],
            )

    # ------------------------------------------------------- изображения

    async def _image_savings(
        self, result: ModuleResult, payloads: list[tuple[str, bytes, int | None]]
    ) -> bool:
        """Считает, сколько реально сэкономит пережатие. True — если посчитали."""
        if not payloads:
            return False
        if not PILLOW_AVAILABLE:
            result.add(
                "perf.img.pillow",
                "Точная экономия на картинках не посчитана",
                Severity.INFO,
                "Не установлена библиотека Pillow.",
                "Установите `pip install pillow`, и инструмент покажет, сколько "
                "мегабайт даст пережатие каждой картинки, вместо общего совета.",
            )
            return False

        savings, skipped = await analyze_images(payloads)
        if not savings:
            return False

        # Экономию заявляем только там, где она берётся из смены формата.
        # Пережать WebP в WebP тоже «выгодно», но за счёт потери качества.
        convertible = [s for s in savings if not s.already_modern]
        modern = [s for s in savings if s.already_modern]

        if modern:
            result.fact(
                "Изображения в современных форматах",
                f"{len(modern)} из {len(savings)} ({human_size(sum(s.original for s in modern))})",
            )

        if convertible:
            original = sum(s.original for s in convertible)
            optimized = sum(s.optimized for s in convertible)
            saved = max(0, original - optimized)
            share = pct(saved, original)

            result.fact(
                "JPEG/PNG: сейчас / после конвертации",
                f"{human_size(original)} → {human_size(optimized)} "
                f"(−{human_size(saved)}, {share:.0f}%)",
            )

            worth = [s for s in convertible if s.ratio >= WORTH_IT and s.saved > 20_000]
            if worth and share >= 20:
                result.add(
                    "perf.img.savings",
                    f"Изображения можно облегчить на {human_size(saved)} ({share:.0f}%)",
                    Severity.HIGH if share >= 50 else Severity.MEDIUM,
                    f"Проверено {counted(len(convertible), 'изображение', 'изображения', 'изображений')}"
                    f" в устаревших форматах, общий вес {human_size(original)}. Цифры получены "
                    f"реальным пережатием в WebP с качеством {WEBP_QUALITY}, а не оценкой.",
                    "Переведите картинки в WebP или AVIF при сборке или на стороне CDN. "
                    "Отдавайте через <picture> с fallback на исходный формат.",
                    evidence=[
                        f"−{human_size(s.saved)} ({s.ratio * 100:.0f}%): {s.fmt} "
                        f"{s.width}×{s.height}, {human_size(s.original)} — {truncate(s.url, 45)}"
                        for s in worth[:6]
                    ],
                )
            else:
                result.ok(
                    "perf.img.savings",
                    f"Конвертация в WebP дала бы всего {share:.0f}% — не стоит возни",
                )
        elif modern:
            result.ok(
                "perf.img.format",
                f"Все изображения уже в современных форматах ({len(modern)} шт.)",
            )

        oversized = [s for s in savings if s.oversized]
        if oversized:
            result.add(
                "perf.img.oversized",
                f"Картинки отдаются крупнее, чем показываются ({len(oversized)})",
                Severity.MEDIUM,
                "Браузер скачивает файл в полном разрешении и уменьшает его при отрисовке — "
                "трафик тратится впустую, особенно на мобильных.",
                "Нарежьте изображения под реальные размеры отображения и подключите "
                "через srcset с несколькими вариантами ширины.",
                evidence=[
                    f"{s.width}×{s.height} при показе в "
                    f"{s.displayed_width or '?'}px — {truncate(s.url, 50)}"
                    for s in oversized[:6]
                ],
            )

        if skipped:
            result.add(
                "perf.img.unreadable",
                f"Не удалось разобрать изображений: {skipped}",
                Severity.INFO,
                "Файлы битые либо в формате, который Pillow не открывает (например, AVIF).",
                "",
            )
        return True


def _displayed_widths(ctx: AuditContext) -> dict[str, int]:
    """Ширина отображения из атрибута width — нужна, чтобы поймать избыточные картинки."""
    widths: dict[str, int] = {}
    for img in ctx.soup.find_all("img"):
        raw = str(img.get("width") or "").strip().rstrip("px")
        src = img.get("src") or img.get("data-src") or ""
        url = abs_url(ctx.url, src)
        if url and raw.isdigit():
            widths[url] = int(raw)
    return widths
