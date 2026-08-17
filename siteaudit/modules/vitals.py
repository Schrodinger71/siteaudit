"""Измерение Core Web Vitals в настоящем браузере через Playwright.

Модуль включается флагом --browser. Без него остальной аудит работает как раньше,
без тяжёлой зависимости.
"""

from __future__ import annotations

import base64

from ..context import AuditContext
from ..fetcher import MOBILE_UA
from ..models import ModuleResult, Severity
from ..utils import human_ms, human_size, truncate
from .base import Module

# Пороги Google: (хорошо, требует улучшения) — всё, что выше, считается плохим
LCP_GOOD, LCP_POOR = 2.5, 4.0
CLS_GOOD, CLS_POOR = 0.1, 0.25
TBT_GOOD, TBT_POOR = 200.0, 600.0
FCP_GOOD, FCP_POOR = 1.8, 3.0

INSTALL_HINT = (
    "Установите браузерный движок: `pip install playwright` "
    "и затем `playwright install chromium`."
)

#: Профили устройств для замера. Мобильный — Pixel 7 в портретной ориентации.
DESKTOP = {
    "key": "desktop",
    "name": "десктоп",
    "viewport": {"width": 1366, "height": 768},
    "scale": 1.0,
    "touch": False,
    "user_agent": None,
}
MOBILE = {
    "key": "mobile",
    "name": "мобильный",
    "viewport": {"width": 393, "height": 852},
    "scale": 3.0,
    "touch": True,
    "user_agent": MOBILE_UA,
}

#: Во сколько раз мобильный LCP должен превысить десктопный, чтобы это считалось находкой
MOBILE_GAP = 1.8

# Наблюдатели ставятся до навигации, иначе ранние события будут потеряны
INIT_SCRIPT = """
window.__siteaudit = { lcp: 0, cls: 0, tbt: 0 };
try {
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) window.__siteaudit.lcp = e.startTime;
  }).observe({ type: 'largest-contentful-paint', buffered: true });
} catch (e) {}
try {
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) {
      if (!e.hadRecentInput) window.__siteaudit.cls += e.value;
    }
  }).observe({ type: 'layout-shift', buffered: true });
} catch (e) {}
try {
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) {
      window.__siteaudit.tbt += Math.max(0, e.duration - 50);
    }
  }).observe({ type: 'longtask', buffered: true });
} catch (e) {}
"""

COLLECT_SCRIPT = """
() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const paint = performance.getEntriesByType('paint');
  const fcpEntry = paint.find((p) => p.name === 'first-contentful-paint');
  const res = performance.getEntriesByType('resource');
  const store = window.__siteaudit || {};
  return {
    lcp: store.lcp || null,
    cls: store.cls || 0,
    tbt: store.tbt || 0,
    fcp: fcpEntry ? fcpEntry.startTime : null,
    ttfb: nav.responseStart || null,
    domContentLoaded: nav.domContentLoadedEventEnd || null,
    load: nav.loadEventEnd || null,
    domNodes: document.getElementsByTagName('*').length,
    maxDepth: (() => {
      let max = 0;
      const walk = (node, d) => {
        if (d > max) max = d;
        for (const child of node.children) walk(child, d + 1);
      };
      if (document.body) walk(document.body, 0);
      return max;
    })(),
    text: document.body ? document.body.innerText.length : 0,
    resources: res.length,
    transfer: res.reduce((sum, r) => sum + (r.transferSize || 0), 0)
  };
}
"""


class VitalsModule(Module):
    key = "vitals"
    title = "Core Web Vitals"
    weight = 0.30

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.error = f"Playwright не установлен. {INSTALL_HINT}"
            return

        # При --mobile меряем оба устройства: мобильные числа считаем основными,
        # десктопные нужны для сравнения. Без флага хватает одного прогона.
        profiles = [MOBILE, DESKTOP] if ctx.options.mobile else [DESKTOP]
        try:
            passes = await self._measure(ctx, async_playwright, profiles)
        except Exception as exc:  # noqa: BLE001 — браузер падает по многим причинам
            message = str(exc)
            if "Executable doesn't exist" in message or "playwright install" in message:
                result.error = f"Не установлен браузер Chromium. {INSTALL_HINT}"
            else:
                result.error = f"{type(exc).__name__}: {truncate(message, 200)}"
            return

        primary_profile = profiles[0]
        primary = passes[primary_profile["key"]]
        metrics = primary["metrics"]

        result.fact("Устройство замера", primary_profile["name"])
        if len(profiles) > 1:
            self._comparison(result, passes)

        self._vitals(result, metrics)
        self._loading(result, metrics)
        self._dom(result, metrics)
        self._rendering(ctx, result, metrics)
        self._console(result, primary["console_errors"], primary["page_errors"])

    async def _measure(self, ctx: AuditContext, async_playwright, profiles: list[dict]) -> dict:
        passes: dict[str, dict] = {}
        timeout_ms = int(max(ctx.options.timeout, 30) * 1000)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                for profile in profiles:
                    passes[profile["key"]] = await self._one_pass(
                        browser, ctx, profile, timeout_ms, screenshot=profile is profiles[0]
                    )
            finally:
                await browser.close()
        return passes

    async def _one_pass(
        self, browser, ctx: AuditContext, profile: dict, timeout_ms: int, screenshot: bool
    ) -> dict:
        console_errors: list[str] = []
        page_errors: list[str] = []

        context = await browser.new_context(
            viewport=profile["viewport"],
            device_scale_factor=profile["scale"],
            is_mobile=profile["touch"],
            has_touch=profile["touch"],
            user_agent=profile["user_agent"],
            ignore_https_errors=ctx.options.insecure,
        )
        await context.add_init_script(INIT_SCRIPT)
        page = await context.new_page()

        page.on(
            "console",
            lambda msg: console_errors.append(truncate(msg.text, 120))
            if msg.type == "error"
            else None,
        )
        page.on("pageerror", lambda exc: page_errors.append(truncate(str(exc), 120)))

        await page.goto(ctx.url, wait_until="load", timeout=timeout_ms)
        # Замер строго на load + пауза. Ждать networkidle нельзя: поздние баннеры
        # и виджеты перебивают кандидата LCP, и метрика раздувается в разы.
        await page.wait_for_timeout(1500)
        metrics = await page.evaluate(COLLECT_SCRIPT)

        if screenshot:
            try:
                shot = await page.screenshot(type="jpeg", quality=55, full_page=False)
                ctx.screenshot = "data:image/jpeg;base64," + base64.b64encode(shot).decode()
            except Exception:  # noqa: BLE001 — скриншот не обязателен
                pass

        await context.close()
        return {
            "metrics": metrics,
            "console_errors": console_errors,
            "page_errors": page_errors,
        }

    def _comparison(self, result: ModuleResult, passes: dict) -> None:
        """Сравнение мобильного прогона с десктопным."""
        mobile = passes["mobile"]["metrics"]
        desktop = passes["desktop"]["metrics"]

        for label, key, fmt in (
            ("LCP", "lcp", lambda v: human_ms(v / 1000)),
            ("CLS", "cls", lambda v: f"{v:.3f}"),
            ("TBT", "tbt", lambda v: f"{v:.0f} мс"),
            ("Передано по сети", "transfer", human_size),
        ):
            m, d = mobile.get(key) or 0, desktop.get(key) or 0
            result.fact(f"{label}: моб. / десктоп", f"{fmt(m)} / {fmt(d)}")

        m_lcp = (mobile.get("lcp") or 0) / 1000
        d_lcp = (desktop.get("lcp") or 0) / 1000
        if d_lcp and m_lcp > d_lcp * MOBILE_GAP and m_lcp > LCP_GOOD:
            result.add(
                "vitals.mobile.slower",
                f"Мобильная версия грузится в {m_lcp / d_lcp:.1f} раза дольше десктопной",
                Severity.HIGH,
                f"LCP: {human_ms(m_lcp)} против {human_ms(d_lcp)}. "
                "Google оценивает сайт по мобильной версии.",
                "Проверьте, не отдаются ли мобильным те же тяжёлые изображения и скрипты, "
                "что и десктопу. Настройте srcset под мобильные разрешения и уберите "
                "с мобильной версии то, что там не показывается.",
            )

        m_bytes = mobile.get("transfer") or 0
        d_bytes = desktop.get("transfer") or 0
        if d_bytes and m_bytes >= d_bytes * 0.95:
            result.add(
                "vitals.mobile.sameweight",
                "Мобильным отдаётся столько же данных, сколько десктопу",
                Severity.MEDIUM,
                f"{human_size(m_bytes)} против {human_size(d_bytes)} — экономии нет.",
                "Адаптивные изображения через srcset/sizes и отказ от загрузки "
                "десктопных виджетов на мобильных обычно срезают вес на треть и больше.",
            )
        elif d_bytes:
            result.ok(
                "vitals.mobile.weight",
                f"Мобильным отдаётся меньше данных ({human_size(m_bytes)} против {human_size(d_bytes)})",
            )

    # ------------------------------------------------------------- метрики

    def _vitals(self, result: ModuleResult, m: dict) -> None:
        lcp = (m.get("lcp") or 0) / 1000
        cls = m.get("cls") or 0.0
        tbt = m.get("tbt") or 0.0

        result.fact("LCP (отрисовка главного элемента)", human_ms(lcp) if lcp else "—")
        result.fact("CLS (сдвиг вёрстки)", f"{cls:.3f}")
        result.fact("TBT (блокировка потока)", f"{tbt:.0f} мс")

        if lcp:
            if lcp > LCP_POOR:
                result.add(
                    "vitals.lcp.poor",
                    f"LCP {human_ms(lcp)} — плохо (порог {LCP_GOOD} с)",
                    Severity.HIGH,
                    "Главный элемент экрана появляется слишком поздно. "
                    "Это одна из трёх метрик, по которым Google оценивает страницу.",
                    "Разберите LCP по частям: TTFB сервера, загрузка ресурса, отрисовка. "
                    "Чаще всего виновата тяжёлая картинка первого экрана — сожмите её, "
                    'отдайте в WebP и добавьте fetchpriority="high" с preload.',
                )
            elif lcp > LCP_GOOD:
                result.add(
                    "vitals.lcp.medium",
                    f"LCP {human_ms(lcp)} — требует улучшения (порог {LCP_GOOD} с)",
                    Severity.MEDIUM,
                    "",
                    "Ускорьте загрузку главного изображения или заголовка первого экрана: "
                    "preload, современный формат, отсутствие блокирующего CSS перед ним.",
                )
            else:
                result.ok("vitals.lcp", f"LCP {human_ms(lcp)} — хорошо")

        if cls > CLS_POOR:
            result.add(
                "vitals.cls.poor",
                f"CLS {cls:.3f} — плохо (порог {CLS_GOOD})",
                Severity.HIGH,
                "Вёрстка ощутимо прыгает при загрузке: пользователь промахивается по кнопкам.",
                "Задайте width/height или aspect-ratio всем картинкам и рекламным блокам, "
                "резервируйте место под баннеры и подгружаемые виджеты, "
                "используйте font-display: optional вместо swap для крупных шрифтов.",
            )
        elif cls > CLS_GOOD:
            result.add(
                "vitals.cls.medium",
                f"CLS {cls:.3f} — требует улучшения (порог {CLS_GOOD})",
                Severity.MEDIUM,
                "",
                "Найдите прыгающие блоки: чаще всего это картинки без размеров, "
                "поздно подключаемые шрифты и вставки, появляющиеся после загрузки.",
            )
        else:
            result.ok("vitals.cls", f"CLS {cls:.3f} — хорошо")

        if tbt > TBT_POOR:
            result.add(
                "vitals.tbt.poor",
                f"TBT {tbt:.0f} мс — плохо (порог {TBT_GOOD:.0f} мс)",
                Severity.HIGH,
                "Главный поток надолго заблокирован скриптами — страница выглядит "
                "загруженной, но не реагирует на клики. Это прямой предиктор плохого INP.",
                "Разбейте длинные задачи, уберите неиспользуемый JS, перенесите тяжёлые "
                "вычисления в Web Worker, подгружайте виджеты чата и аналитики "
                "после взаимодействия пользователя.",
            )
        elif tbt > TBT_GOOD:
            result.add(
                "vitals.tbt.medium",
                f"TBT {tbt:.0f} мс — требует улучшения (порог {TBT_GOOD:.0f} мс)",
                Severity.MEDIUM,
                "",
                "Посмотрите, какие скрипты выполняются дольше 50 мс, и отложите их запуск.",
            )
        else:
            result.ok("vitals.tbt", f"TBT {tbt:.0f} мс — хорошо")

    def _loading(self, result: ModuleResult, m: dict) -> None:
        fcp = (m.get("fcp") or 0) / 1000
        load = (m.get("load") or 0) / 1000
        result.fact("FCP (первая отрисовка)", human_ms(fcp) if fcp else "—")
        result.fact("Полная загрузка", human_ms(load) if load else "—")
        result.fact("Запросов в браузере", m.get("resources") or 0)
        result.fact("Передано по сети", human_size(m.get("transfer") or 0))

        if fcp > FCP_POOR:
            result.add(
                "vitals.fcp",
                f"FCP {human_ms(fcp)} — долгий белый экран",
                Severity.MEDIUM,
                f"Порог для оценки «хорошо» — {FCP_GOOD} с.",
                "Уберите блокирующие рендеринг CSS и JS из <head>, "
                "вынесите критический CSS инлайном.",
            )
        elif fcp:
            result.ok("vitals.fcp", f"FCP {human_ms(fcp)}")

    def _dom(self, result: ModuleResult, m: dict) -> None:
        nodes = m.get("domNodes") or 0
        depth = m.get("maxDepth") or 0
        result.fact("Узлов в DOM", nodes)
        result.fact("Глубина вложенности DOM", depth)

        if nodes > 1500:
            result.add(
                "vitals.dom.size",
                f"Слишком большой DOM ({nodes} узлов)",
                Severity.MEDIUM if nodes > 3000 else Severity.LOW,
                "Каждый пересчёт стилей и перерисовка обходятся тем дороже, чем больше дерево.",
                "Сократите разметку: виртуализируйте длинные списки, уберите лишние "
                "обёртки-контейнеры, выносите скрытые блоки из DOM вместо display:none.",
            )
        if depth > 32:
            result.add(
                "vitals.dom.depth",
                f"Глубокая вложенность DOM ({depth} уровней)",
                Severity.LOW,
                "",
                "Упростите структуру шаблона — глубокие деревья замедляют "
                "расчёт стилей и усложняют поддержку.",
            )

    def _rendering(self, ctx: AuditContext, result: ModuleResult, m: dict) -> None:
        """Сравнение сырого HTML и результата рендеринга — диагностика SPA без SSR."""
        rendered = m.get("text") or 0
        raw = len(ctx.soup.get_text(" ", strip=True))
        result.fact("Текст в сыром HTML", f"{raw} симв.")
        result.fact("Текст после рендеринга", f"{rendered} симв.")

        if rendered > 400 and raw < rendered * 0.25:
            result.add(
                "vitals.spa",
                "Контент появляется только после выполнения JavaScript",
                Severity.HIGH,
                f"В исходном HTML {raw} символов текста, после рендеринга — {rendered}. "
                "Робот, не выполняющий JS, увидит почти пустую страницу.",
                "Включите серверный рендеринг (SSR) или предрендер для поисковых роботов. "
                "Google выполняет JS, но с задержкой и не всегда полностью; "
                "Яндекс и соцсети — заметно хуже.",
            )
        elif raw > 200:
            result.ok("vitals.ssr", "Основной контент присутствует в исходном HTML")

    def _console(self, result: ModuleResult, console_errors: list[str], page_errors: list[str]) -> None:
        total = len(console_errors) + len(page_errors)
        result.fact("Ошибок в консоли", total)

        if page_errors:
            result.add(
                "vitals.js.errors",
                f"Необработанные ошибки JavaScript ({len(page_errors)})",
                Severity.HIGH,
                "Упавший скрипт может ломать формы, корзину и другую функциональность.",
                "Откройте консоль браузера и почините ошибки — начните с первой, "
                "остальные часто её следствие.",
                evidence=page_errors[:5],
            )
        if console_errors:
            result.add(
                "vitals.console.errors",
                f"Ошибки в консоли браузера ({len(console_errors)})",
                Severity.LOW if not page_errors else Severity.MEDIUM,
                "Чаще всего это не загрузившиеся ресурсы или ошибки сторонних скриптов.",
                "Разберите список: битые ресурсы стоит починить, лишние сторонние "
                "скрипты — убрать.",
                evidence=console_errors[:5],
            )
        if not total:
            result.ok("vitals.console", "Ошибок в консоли нет")
