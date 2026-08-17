"""SEO-аудит: мета-теги, заголовки, индексация, разметка, ссылки."""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..context import AuditContext
from ..models import ModuleResult, Severity
from ..utils import abs_url, counted, has_icon_rel, has_rel, pct, similarity, truncate
from .base import Module

TITLE_MIN, TITLE_MAX = 30, 65
DESC_MIN, DESC_MAX = 70, 165


def _parse(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001 — если lxml не установлен
        return BeautifulSoup(html, "html.parser")


class SeoModule(Module):
    key = "seo"
    title = "SEO"
    weight = 0.30

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not ctx.page.ok:
            result.error = ctx.page.error or f"HTTP {ctx.page.status}"
            return

        self._title(ctx, result)
        self._description(ctx, result)
        self._headings(ctx, result)
        self._indexing(ctx, result)
        self._canonical(ctx, result)
        self._lang_and_viewport(ctx, result)
        self._images(ctx, result)
        self._social(ctx, result)
        self._structured_data(ctx, result)
        self._content(ctx, result)
        self._url_quality(ctx, result)
        await self._favicon(ctx, result)
        await self._robots_sitemap(ctx, result)
        await self._not_found(ctx, result)
        await self._links(ctx, result)

    # ------------------------------------------------------------ мета-теги

    def _title(self, ctx: AuditContext, result: ModuleResult) -> None:
        tags = ctx.soup.find_all("title")
        title = tags[0].get_text(strip=True) if tags else ""
        result.fact("Title", truncate(title, 90) or "отсутствует")
        result.fact("Длина title", f"{len(title)} симв." if title else "0")

        if not title:
            result.add(
                "seo.title.missing",
                "Отсутствует тег <title>",
                Severity.CRITICAL,
                "У страницы нет заголовка — поисковик подставит случайный текст со страницы.",
                "Добавьте уникальный <title> длиной 30–65 символов с главным запросом "
                "в начале и названием бренда в конце.",
            )
        elif len(title) < TITLE_MIN:
            result.add(
                "seo.title.short",
                f"Слишком короткий title ({len(title)} симв.)",
                Severity.MEDIUM,
                f"«{truncate(title, 80)}»",
                f"Расширьте до {TITLE_MIN}–{TITLE_MAX} символов: добавьте уточняющие "
                "слова, гео или УТП. Короткий title теряет охват по длинным запросам.",
            )
        elif len(title) > TITLE_MAX:
            result.add(
                "seo.title.long",
                f"Слишком длинный title ({len(title)} симв.)",
                Severity.LOW,
                f"«{truncate(title, 100)}»",
                f"Сократите до {TITLE_MAX} символов — в выдаче хвост всё равно обрежется многоточием.",
            )
        else:
            result.ok("seo.title", f"Title корректной длины ({len(title)} симв.)")

        if len(tags) > 1:
            result.add(
                "seo.title.duplicate",
                f"На странице {counted(len(tags), 'тег', 'тега', 'тегов')} <title>",
                Severity.MEDIUM,
                "Дубли <title> сбивают поисковик — он выберет первый или склеит их.",
                "Оставьте ровно один <title> в <head>.",
            )

    def _description(self, ctx: AuditContext, result: ModuleResult) -> None:
        desc = ctx.meta("description") or ""
        result.fact("Description", truncate(desc, 90) or "отсутствует")

        if not desc:
            result.add(
                "seo.description.missing",
                "Отсутствует meta description",
                Severity.HIGH,
                "Сниппет в выдаче будет собран автоматически из случайного текста страницы.",
                "Добавьте <meta name=\"description\"> на 70–165 символов: краткая выгода "
                "плюс призыв к действию. Это напрямую влияет на CTR из поиска.",
            )
        elif len(desc) < DESC_MIN:
            result.add(
                "seo.description.short",
                f"Короткий description ({len(desc)} симв.)",
                Severity.LOW,
                f"«{truncate(desc, 100)}»",
                f"Доведите до {DESC_MIN}–{DESC_MAX} символов, чтобы занять всю площадь сниппета.",
            )
        elif len(desc) > DESC_MAX:
            result.add(
                "seo.description.long",
                f"Длинный description ({len(desc)} симв.)",
                Severity.LOW,
                f"«{truncate(desc, 120)}»",
                f"Сократите до {DESC_MAX} символов — остальное обрежется.",
            )
        else:
            result.ok("seo.description", f"Description корректной длины ({len(desc)} симв.)")

        keywords = ctx.meta("keywords")
        if keywords and len(keywords) > 200:
            result.add(
                "seo.keywords.spam",
                "Переспам в meta keywords",
                Severity.LOW,
                f"{len(keywords)} символов в keywords.",
                "Google игнорирует keywords, Яндекс может счесть переспамом. "
                "Либо удалите тег, либо оставьте 5–7 фраз.",
            )

    def _headings(self, ctx: AuditContext, result: ModuleResult) -> None:
        levels = {f"h{i}": ctx.soup.find_all(f"h{i}") for i in range(1, 7)}
        h1s = levels["h1"]
        result.fact("H1", truncate(h1s[0].get_text(" ", strip=True), 90) if h1s else "отсутствует")
        result.fact(
            "Структура заголовков",
            ", ".join(f"{k}: {len(v)}" for k, v in levels.items() if v) or "заголовков нет",
        )

        if not h1s:
            result.add(
                "seo.h1.missing",
                "Нет заголовка H1",
                Severity.HIGH,
                "Поисковику не за что зацепиться при определении темы страницы.",
                "Добавьте один H1 с основным запросом. Он должен отличаться от title, "
                "но раскрывать ту же тему.",
            )
        elif len(h1s) > 1:
            result.add(
                "seo.h1.multiple",
                f"Несколько H1 на странице ({len(h1s)})",
                Severity.MEDIUM,
                "; ".join(truncate(h.get_text(" ", strip=True), 40) for h in h1s[:4]),
                "Оставьте один H1, остальные понизьте до H2. Часто это следствие того, "
                "что в H1 обёрнут логотип в шапке.",
            )
        else:
            result.ok("seo.h1", "Ровно один H1")

        order = [int(t.name[1]) for t in ctx.soup.find_all(re.compile(r"^h[1-6]$"))]
        skips = [
            (order[i], order[i + 1])
            for i in range(len(order) - 1)
            if order[i + 1] - order[i] > 1
        ]
        if skips:
            result.add(
                "seo.headings.skip",
                f"Нарушена иерархия заголовков ({counted(len(skips), 'разрыв', 'разрыва', 'разрывов')})",
                Severity.LOW,
                "; ".join(f"H{a} → H{b}" for a, b in skips[:5]),
                "Не перепрыгивайте через уровни (H2 → H4). Заголовки — это оглавление "
                "страницы и для поисковика, и для скринридера.",
            )
        elif order:
            result.ok("seo.headings", "Иерархия заголовков без разрывов")

    def _indexing(self, ctx: AuditContext, result: ModuleResult) -> None:
        robots_meta = (ctx.meta("robots") or "").lower()
        x_robots = ctx.page.header("x-robots-tag").lower()
        blockers = []
        if "noindex" in robots_meta:
            blockers.append('meta name="robots"')
        if "noindex" in x_robots:
            blockers.append("заголовок X-Robots-Tag")

        result.fact("meta robots", robots_meta or "не задан (индексация разрешена)")

        if blockers:
            result.add(
                "seo.noindex",
                "Страница закрыта от индексации",
                Severity.CRITICAL,
                f"Запрет найден в: {', '.join(blockers)}.",
                "Если это боевая страница — немедленно уберите noindex, иначе она "
                "не появится в поиске вообще.",
            )
        else:
            result.ok("seo.index", "Индексация не запрещена")

        if "nofollow" in robots_meta:
            result.add(
                "seo.nofollow",
                "Все ссылки страницы закрыты через nofollow",
                Severity.MEDIUM,
                f'meta robots: {robots_meta}',
                "nofollow на уровне страницы обрывает передачу веса по внутренним ссылкам. "
                "Уберите, если это не служебная страница.",
            )

    def _canonical(self, ctx: AuditContext, result: ModuleResult) -> None:
        links = [t for t in ctx.soup.find_all("link", href=True) if has_rel(t, "canonical")]
        hrefs = [abs_url(ctx.url, t.get("href", "")) for t in links]
        hrefs = [h for h in hrefs if h]
        result.fact("Canonical", truncate(hrefs[0], 80) if hrefs else "не задан")

        if not hrefs:
            result.add(
                "seo.canonical.missing",
                "Не указан rel=canonical",
                Severity.MEDIUM,
                "Без canonical страница легко склеивается с дублями по UTM-меткам, "
                "сортировкам и пагинации.",
                'Добавьте <link rel="canonical" href="..."> с абсолютным URL '
                "предпочтительной версии страницы.",
            )
        elif len(hrefs) > 1:
            result.add(
                "seo.canonical.multiple",
                f"Несколько canonical ({len(hrefs)})",
                Severity.MEDIUM,
                "; ".join(truncate(h, 60) for h in hrefs[:3]),
                "Поисковик проигнорирует все конфликтующие canonical. Оставьте один.",
            )
        else:
            canon = hrefs[0]
            if canon.rstrip("/") != ctx.url.rstrip("/"):
                result.add(
                    "seo.canonical.mismatch",
                    "Canonical указывает на другой URL",
                    Severity.LOW,
                    f"страница: {truncate(ctx.url, 60)} → canonical: {truncate(canon, 60)}",
                    "Убедитесь, что это осознанная склейка. Если нет — canonical должен "
                    "совпадать с URL самой страницы.",
                )
            else:
                result.ok("seo.canonical", "Canonical корректен")

        hreflangs = ctx.soup.find_all("link", hreflang=True)
        if hreflangs:
            has_x_default = any(t.get("hreflang", "").lower() == "x-default" for t in hreflangs)
            if not has_x_default:
                result.add(
                    "seo.hreflang.x-default",
                    "В hreflang нет x-default",
                    Severity.LOW,
                    f"Найдено {len(hreflangs)} альтернативных языковых версий.",
                    'Добавьте <link rel="alternate" hreflang="x-default"> — это версия '
                    "для пользователей, чей язык не совпал ни с одной локалью.",
                )
            else:
                result.ok("seo.hreflang", f"hreflang настроен ({len(hreflangs)} версий)")

    def _lang_and_viewport(self, ctx: AuditContext, result: ModuleResult) -> None:
        html_tag = ctx.soup.find("html")
        lang = (html_tag.get("lang") if html_tag else "") or ""
        result.fact("Язык страницы", lang or "не указан")
        if not lang:
            result.add(
                "seo.lang.missing",
                "Не указан атрибут lang у <html>",
                Severity.LOW,
                "Поисковик и скринридеры определяют язык эвристикой.",
                'Добавьте <html lang="ru"> (или нужную локаль).',
            )
        else:
            result.ok("seo.lang", f"Язык указан: {lang}")

        viewport = ctx.meta("viewport")
        if not viewport:
            result.add(
                "seo.viewport.missing",
                "Нет meta viewport — сайт не адаптирован под мобильные",
                Severity.HIGH,
                "Мобильный трафик обычно больше половины; Google использует mobile-first индексацию.",
                'Добавьте <meta name="viewport" content="width=device-width, initial-scale=1">.',
            )
        elif "user-scalable=no" in viewport.replace(" ", "") or "maximum-scale=1" in viewport.replace(" ", ""):
            result.add(
                "seo.viewport.zoom",
                "Запрещено масштабирование на мобильных",
                Severity.LOW,
                f"viewport: {viewport}",
                "Уберите user-scalable=no и maximum-scale — это нарушает доступность "
                "и штрафуется аудитами.",
            )
        else:
            result.ok("seo.viewport", "Viewport настроен")

        charset = ctx.soup.find("meta", charset=True)
        if not charset and "charset" not in ctx.page.header("content-type").lower():
            result.add(
                "seo.charset.missing",
                "Не объявлена кодировка страницы",
                Severity.LOW,
                "Ни <meta charset>, ни charset в Content-Type.",
                'Добавьте <meta charset="utf-8"> первой строкой в <head>.',
            )


    def _images(self, ctx: AuditContext, result: ModuleResult) -> None:
        imgs = ctx.soup.find_all("img")
        if not imgs:
            return
        no_alt = [i for i in imgs if not (i.get("alt") or "").strip()]
        result.fact("Изображений на странице", len(imgs))

        if no_alt:
            share = pct(len(no_alt), len(imgs))
            severity = Severity.MEDIUM if share > 30 else Severity.LOW
            samples = [truncate(i.get("src", "") or i.get("data-src", ""), 70) for i in no_alt[:5]]
            result.add(
                "seo.img.alt",
                f"У {len(no_alt)} из {len(imgs)} изображений нет alt ({share:.0f}%)",
                severity,
                "Пустой alt — потерянный трафик из поиска по картинкам и проблема доступности.",
                "Пропишите осмысленный alt, описывающий изображение. "
                "Декоративным картинкам оставьте alt=\"\" явно.",
                evidence=samples,
            )
        else:
            result.ok("seo.img.alt", "У всех изображений заполнен alt")

    def _social(self, ctx: AuditContext, result: ModuleResult) -> None:
        og = {
            key: ctx.meta_property(f"og:{key}")
            for key in ("title", "description", "image", "url", "type")
        }
        missing = [k for k in ("title", "description", "image") if not og.get(k)]
        result.fact("Open Graph", "настроен" if not missing else f"нет: {', '.join(missing)}")

        if len(missing) == 3:
            result.add(
                "seo.og.missing",
                "Нет разметки Open Graph",
                Severity.MEDIUM,
                "При репосте в мессенджеры и соцсети превью соберётся как попало.",
                "Добавьте og:title, og:description, og:image (1200×630), og:url, og:type. "
                "Это заметно повышает кликабельность ссылок в чатах.",
            )
        elif missing:
            result.add(
                "seo.og.partial",
                f"Open Graph заполнен не полностью: нет {', '.join(missing)}",
                Severity.LOW,
                "",
                "Дозаполните недостающие og-теги, особенно og:image.",
            )
        else:
            result.ok("seo.og", "Open Graph заполнен")

        if not ctx.meta("twitter:card"):
            result.add(
                "seo.twitter.missing",
                "Нет Twitter Card",
                Severity.LOW,
                "",
                'Добавьте <meta name="twitter:card" content="summary_large_image">.',
            )

    def _structured_data(self, ctx: AuditContext, result: ModuleResult) -> None:
        blocks = ctx.soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)})
        types: list[str] = []
        broken = 0
        for b in blocks:
            try:
                data = json.loads(b.string or b.get_text() or "{}")
            except (json.JSONDecodeError, TypeError):
                broken += 1
                continue
            types.extend(_extract_types(data))

        microdata = bool(ctx.soup.find(attrs={"itemtype": True}))
        result.fact(
            "Микроразметка",
            ", ".join(sorted(set(types))[:8]) if types else ("Microdata" if microdata else "нет"),
        )

        if not blocks and not microdata:
            result.add(
                "seo.schema.missing",
                "Нет структурированных данных (Schema.org)",
                Severity.MEDIUM,
                "Без разметки не будет расширенных сниппетов: рейтинги, цены, хлебные крошки, FAQ.",
                "Добавьте JSON-LD: Organization + WebSite на всех страницах, "
                "BreadcrumbList в каталоге, Product/Article на карточках. "
                "Проверьте результат в Rich Results Test и Яндекс.Вебмастере.",
            )
        else:
            result.ok("seo.schema", f"Микроразметка найдена: {', '.join(sorted(set(types))[:5]) or 'Microdata'}")

        if broken:
            result.add(
                "seo.schema.invalid",
                f"Битый JSON-LD ({broken} блоков)",
                Severity.MEDIUM,
                "Блоки не парсятся как JSON — поисковик их проигнорирует.",
                "Проверьте синтаксис (лишние запятые, неэкранированные кавычки) "
                "в валидаторе структурированных данных.",
            )

        if not ctx.soup.find(attrs={"itemtype": re.compile("BreadcrumbList", re.I)}) and "BreadcrumbList" not in types:
            result.add(
                "seo.breadcrumbs.missing",
                "Нет разметки хлебных крошек",
                Severity.LOW,
                "",
                "Разметьте навигационную цепочку как BreadcrumbList — в выдаче вместо "
                "длинного URL появится читаемый путь.",
            )

    def _content(self, ctx: AuditContext, result: ModuleResult) -> None:
        # отдельная копия дерева: ctx.soup нужен другим модулям целым
        copy = _parse(ctx.html)
        for tag in copy.find_all(["script", "style", "noscript", "template"]):
            tag.decompose()
        text = copy.get_text(" ", strip=True)
        words = len(re.findall(r"[\w\-]+", text))
        ratio = pct(len(text.encode("utf-8")), max(1, len(ctx.page.content)))
        result.fact("Объём текста", counted(words, "слово", "слова", "слов"))
        result.fact("Доля текста в HTML", f"{ratio:.1f}%")

        if words < 150:
            result.add(
                "seo.content.thin",
                f"Мало текстового контента ({counted(words, 'слово', 'слова', 'слов')})",
                Severity.MEDIUM if words < 60 else Severity.LOW,
                "Страницы с тонким контентом плохо ранжируются и могут попасть под фильтр.",
                "Доведите основной текст минимум до 300–500 слов осмысленного содержания. "
                "Если контент рендерится через JS — убедитесь, что он есть в HTML для робота "
                "(SSR или предрендер).",
            )
        else:
            result.ok(
                "seo.content",
                f"Объём контента достаточный ({counted(words, 'слово', 'слова', 'слов')})",
            )

        if ratio < 5 and words > 0:
            result.add(
                "seo.content.ratio",
                f"Низкая доля текста в коде ({ratio:.1f}%)",
                Severity.LOW,
                "HTML раздут разметкой и инлайн-скриптами относительно полезного текста.",
                "Вынесите инлайн-стили и скрипты во внешние файлы, уберите неиспользуемую разметку.",
            )

    def _url_quality(self, ctx: AuditContext, result: ModuleResult) -> None:
        parsed = urlparse(ctx.url)
        path = parsed.path
        problems = []
        if len(ctx.url) > 115:
            problems.append(f"длина {len(ctx.url)} символов")
        if "_" in path:
            problems.append("подчёркивания вместо дефисов")
        if re.search(r"[A-ZА-Я]", path):
            problems.append("заглавные буквы")
        if re.search(r"[а-яё]", path, re.I):
            problems.append("кириллица в пути (превратится в punycode/%-escape)")
        if path.count("/") > 6:
            problems.append(f"глубина вложенности {path.count('/')}")
        if re.search(r"\.(php|aspx?|jsp|html?)$", path, re.I) and path != "/":
            problems.append("расширение файла в URL")

        if problems:
            result.add(
                "seo.url.quality",
                "URL можно улучшить",
                Severity.LOW,
                "; ".join(problems),
                "Короткие ЧПУ-адреса из строчных латинских букв и дефисов лучше "
                "читаются и в выдаче, и в ссылках. Меняя URL, всегда ставьте 301-редирект со старого.",
            )
        else:
            result.ok("seo.url", "Структура URL в порядке")

    # -------------------------------------------------------- сеть/файлы

    async def _favicon(self, ctx: AuditContext, result: ModuleResult) -> None:
        """Иконка объявляется тегом link либо просто лежит в /favicon.ico."""
        declared = [t for t in ctx.soup.find_all("link") if has_icon_rel(t)]
        if declared:
            result.fact("Favicon", f"объявлен в разметке ({len(declared)} шт.)")
            result.ok("seo.favicon", "Favicon объявлен")
            return

        probe = await ctx.fetcher.get(f"{ctx.origin}/favicon.ico")
        if probe.status == 200 and probe.size > 0 and "html" not in probe.content_type:
            result.fact("Favicon", "нет тега link, но /favicon.ico отдаётся")
            result.add(
                "seo.favicon.undeclared",
                "Favicon не объявлен в разметке",
                Severity.LOW,
                "Файл /favicon.ico доступен, браузеры его найдут, но тега <link> нет.",
                'Пропишите <link rel="icon"> явно и добавьте apple-touch-icon 180×180 — '
                "иначе на мобильных при добавлении на домашний экран возьмётся скриншот.",
            )
            return

        result.fact("Favicon", "не найден")
        result.add(
            "seo.favicon.missing",
            "Не найден favicon",
            Severity.LOW,
            "Ни тега <link rel=\"icon\">, ни файла /favicon.ico.",
            'Добавьте <link rel="icon"> и apple-touch-icon.',
        )

    async def _robots_sitemap(self, ctx: AuditContext, result: ModuleResult) -> None:
        robots = ctx.robots
        sitemap_urls: list[str] = []

        if robots and robots.status == 200 and "text" in robots.content_type:
            body = robots.text
            result.fact("robots.txt", f"есть, {len(body)} байт")
            sitemap_urls = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)

            disallow_all = re.search(r"(?ims)^user-agent:\s*\*\s*(?:\n(?!user-agent).*)*?^disallow:\s*/\s*$", body)
            if disallow_all:
                result.add(
                    "seo.robots.disallow-all",
                    "robots.txt запрещает обход всего сайта",
                    Severity.CRITICAL,
                    "Найдена директива Disallow: / для User-agent: *",
                    "Если сайт боевой — уберите этот запрет немедленно. Часто он остаётся "
                    "с этапа разработки и полностью выключает сайт из поиска.",
                )
            else:
                result.ok("seo.robots", "robots.txt есть и не блокирует сайт целиком")

            if not sitemap_urls:
                result.add(
                    "seo.robots.no-sitemap",
                    "В robots.txt не указан Sitemap",
                    Severity.LOW,
                    "",
                    "Добавьте строку `Sitemap: https://домен/sitemap.xml` — это самый простой "
                    "способ сообщить роботам о карте сайта.",
                )
        else:
            result.fact("robots.txt", "отсутствует")
            result.add(
                "seo.robots.missing",
                "Нет robots.txt",
                Severity.MEDIUM,
                f"Ответ: {robots.status if robots else '—'}",
                "Создайте robots.txt: закройте служебные разделы, укажите Sitemap. "
                "Отсутствие файла не критично, но лишает вас контроля над обходом.",
            )

        sitemap = ctx.sitemap
        good_sitemap = bool(
            sitemap
            and sitemap.status == 200
            and any(marker in sitemap.text[:2000] for marker in ("<urlset", "<sitemapindex"))
        )
        if good_sitemap:
            count = sitemap.text.count("<loc>")
            result.fact("sitemap.xml", f"есть, {count} записей")
            result.ok("seo.sitemap", f"Карта сайта доступна ({count} URL)")
        elif sitemap_urls:
            probe = await ctx.fetcher.get(sitemap_urls[0])
            if probe.status == 200:
                result.fact("sitemap.xml", f"по адресу из robots.txt: {truncate(sitemap_urls[0], 60)}")
                result.ok("seo.sitemap", "Карта сайта доступна по адресу из robots.txt")
            else:
                result.add(
                    "seo.sitemap.broken",
                    "Sitemap из robots.txt недоступен",
                    Severity.MEDIUM,
                    f"{sitemap_urls[0]} → HTTP {probe.status}",
                    "Исправьте адрес карты сайта или сгенерируйте её заново.",
                )
        else:
            result.fact("sitemap.xml", "отсутствует")
            result.add(
                "seo.sitemap.missing",
                "Нет карты сайта sitemap.xml",
                Severity.MEDIUM,
                f"Ответ /sitemap.xml: {sitemap.status if sitemap else '—'}",
                "Сгенерируйте sitemap.xml (плагином CMS или скриптом), укажите его в robots.txt "
                "и добавьте в Google Search Console и Яндекс.Вебмастер. Без карты новые страницы "
                "индексируются заметно дольше.",
            )

    async def _not_found(self, ctx: AuditContext, result: ModuleResult) -> None:
        probe = ctx.soft404
        if not probe or probe.error:
            return
        result.fact("Ответ на несуществующий URL", f"HTTP {probe.status}")
        if probe.status == 200:
            same = similarity(probe.text, ctx.html)
            result.add(
                "seo.404.soft",
                "Несуществующая страница отдаёт 200 OK (soft-404)",
                Severity.HIGH,
                f"Похожесть на главную: {same * 100:.0f}%.",
                "Сервер должен отдавать 404 (или 410) для несуществующих адресов. "
                "Иначе поисковик индексирует бесконечное множество мусорных URL "
                "и размывает краулинговый бюджет.",
            )
        elif probe.status in (301, 302, 307, 308):
            result.add(
                "seo.404.redirect",
                f"Несуществующий URL редиректит ({probe.status}) вместо 404",
                Severity.MEDIUM,
                f"→ {truncate(probe.url, 70)}",
                "Массовый редирект битых адресов на главную считается soft-404. "
                "Отдавайте честный 404 с полезной страницей-заглушкой.",
            )
        elif probe.status == 404:
            result.ok("seo.404", "Несуществующие URL корректно отдают 404")

    async def _links(self, ctx: AuditContext, result: ModuleResult) -> None:
        internal = ctx.internal_links()
        external = ctx.external_links()
        result.fact("Внутренних ссылок", len(internal))
        result.fact("Внешних ссылок", len(external))

        if len(internal) < 3:
            result.add(
                "seo.links.few-internal",
                f"Почти нет внутренних ссылок ({len(internal)})",
                Severity.MEDIUM,
                "Страница-«тупик»: вес не передаётся дальше, робот не находит новые URL.",
                "Добавьте перелинковку: меню, хлебные крошки, блоки «похожие» и «читайте также».",
            )

        unsafe_blank = [
            u
            for u, attrs in external
            if attrs.get("target") == "_blank"
            and "noopener" not in " ".join(attrs.get("rel", [])).lower()
        ]
        if unsafe_blank:
            result.add(
                "seo.links.noopener",
                f"Внешние ссылки target=_blank без rel=noopener ({len(unsafe_blank)})",
                Severity.LOW,
                "; ".join(truncate(u, 60) for u in unsafe_blank[:4]),
                'Добавьте rel="noopener noreferrer" — иначе открытая страница получает '
                "доступ к window.opener и может подменить вашу вкладку.",
            )

        # Проверяем доступность выборки ссылок
        sample = (internal + [u for u, _ in external])[: ctx.options.max_links]
        if not sample:
            return
        responses = await asyncio.gather(*[ctx.fetcher.head(u) for u in sample])
        broken = [(u, r) for u, r in zip(sample, responses) if r.error or r.status >= 400]
        if broken:
            result.add(
                "seo.links.broken",
                f"Битые ссылки: {len(broken)} из {len(sample)} проверенных",
                Severity.HIGH if len(broken) > 2 else Severity.MEDIUM,
                "Битые ссылки тратят краулинговый бюджет и раздражают пользователей.",
                "Исправьте адреса или уберите ссылки. Проверьте, нет ли битых ссылок "
                "в шаблоне — тогда они на каждой странице сайта.",
                evidence=[
                    f"{r.status if not r.error else 'ошибка'} — {truncate(u, 70)}"
                    for u, r in broken[:8]
                ],
            )
        else:
            result.ok(
                "seo.links",
                f"Проверено {counted(len(sample), 'ссылка', 'ссылки', 'ссылок')} — битых нет",
            )


def _extract_types(data) -> list[str]:
    out: list[str] = []
    if isinstance(data, dict):
        t = data.get("@type")
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, list):
            out.extend(str(x) for x in t)
        for value in data.values():
            out.extend(_extract_types(value))
    elif isinstance(data, list):
        for item in data:
            out.extend(_extract_types(item))
    return out
