"""Аудит доступности: то, что мешает пользоваться сайтом с клавиатуры и скринридером.

Статические проверки идут по разметке всегда. Контраст, размеры кликабельных зон
и видимость фокуса требуют вычисленных стилей и включаются вместе с --browser.
"""

from __future__ import annotations

import re
from collections import Counter

from ..context import AuditContext
from ..models import ModuleResult, Severity
from ..utils import counted, pct, truncate
from .base import Module

#: Порог контраста для обычного текста по WCAG 2.1 уровня AA
CONTRAST_AA = 4.5
#: Для крупного текста (от 24px или от 18.66px полужирного) требования мягче
CONTRAST_AA_LARGE = 3.0
#: Минимальный комфортный размер кликабельной зоны, пикселей
TAP_TARGET = 24

INPUT_TYPES_WITHOUT_LABEL = {"hidden", "submit", "button", "reset", "image"}

CONTRAST_SCRIPT = """
() => {
  const luminance = (rgb) => {
    const [r, g, b] = rgb.map((v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };

  // [r, g, b, a] или null. Альфа важна: полупрозрачную плёнку нельзя считать
  // сплошным фоном, иначе rgba(255,255,255,0.03) поверх чёрного превращается
  // в белый фон, и белый текст выглядит нечитаемым.
  const rgba = (value) => {
    const m = (value || '').match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    const p = m[1].split(',').map((x) => parseFloat(x.trim()));
    if (p.length < 3 || p.some(isNaN)) return null;
    return [p[0], p[1], p[2], p.length >= 4 ? p[3] : 1];
  };

  // Накладываем слои от дальнего к ближнему по формуле source-over.
  const flatten = (layers) => {
    let base = layers[layers.length - 1].slice(0, 3);
    for (let i = layers.length - 2; i >= 0; i--) {
      const [r, g, b, a] = layers[i];
      base = [r * a + base[0] * (1 - a), g * a + base[1] * (1 - a), b * a + base[2] * (1 - a)];
    }
    return base;
  };

  const OPAQUE = 0.995;

  // Собираем фон под элементом. Градиент или картинка по пути — измерять нельзя.
  const backdrop = (el) => {
    const layers = [];
    let node = el;
    while (node && node !== document.documentElement) {
      const cs = getComputedStyle(node);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') return { unknown: true };
      const c = rgba(cs.backgroundColor);
      if (c && c[3] > 0) {
        layers.push(c);
        if (c[3] >= OPAQUE) return { color: flatten(layers) };
      }
      node = node.parentElement;
    }
    const root = getComputedStyle(document.documentElement);
    if (root.backgroundImage && root.backgroundImage !== 'none') return { unknown: true };
    const rootColor = rgba(root.backgroundColor);
    layers.push(rootColor && rootColor[3] >= OPAQUE ? rootColor : [255, 255, 255, 1]);
    return { color: flatten(layers) };
  };

  // Невидимый предок делает невидимым и текст: мерить такое бессмысленно.
  const hidden = (el) => {
    let node = el;
    while (node && node !== document.documentElement) {
      const cs = getComputedStyle(node);
      if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) {
        return true;
      }
      node = node.parentElement;
    }
    return false;
  };

  const out = { checked: 0, unmeasured: 0, low: [], tiny: [], noFocus: 0 };
  const nodes = document.querySelectorAll('p,span,a,li,h1,h2,h3,h4,h5,h6,td,th,label,button,div');

  for (const el of nodes) {
    const text = (el.innerText || '').trim();
    if (!text || el.children.length > 0) continue;
    if (hidden(el)) continue;

    const style = getComputedStyle(el);
    const fgRaw = rgba(style.color);
    if (!fgRaw || fgRaw[3] === 0) continue;

    const behind = backdrop(el);
    if (behind.unknown) { out.unmeasured += 1; continue; }
    const bg = behind.color;
    // Полупрозрачный текст тоже смешиваем с фоном, иначе контраст завышается.
    const fg = fgRaw[3] >= OPAQUE ? fgRaw.slice(0, 3) : flatten([fgRaw, [bg[0], bg[1], bg[2], 1]]);

    const l1 = luminance(fg), l2 = luminance(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

    const size = parseFloat(style.fontSize) || 16;
    const bold = (parseInt(style.fontWeight, 10) || 400) >= 700;
    const large = size >= 24 || (size >= 18.66 && bold);
    const need = large ? 3.0 : 4.5;

    out.checked += 1;
    if (ratio < need) {
      out.low.push({
        ratio: Math.round(ratio * 100) / 100,
        need: need,
        size: Math.round(size),
        text: text.slice(0, 60)
      });
    }
  }

  for (const el of document.querySelectorAll('a[href],button,input,select,textarea')) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) continue;
    if (rect.width < 24 || rect.height < 24) {
      out.tiny.push({
        tag: el.tagName.toLowerCase(),
        w: Math.round(rect.width),
        h: Math.round(rect.height),
        text: (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 40)
      });
    }
  }

  for (const sheet of Array.from(document.styleSheets)) {
    let rules = [];
    try { rules = Array.from(sheet.cssRules || []); } catch (e) { continue; }
    for (const rule of rules) {
      if (rule.selectorText && /:focus(?!-visible)/.test(rule.selectorText)) {
        const s = rule.style || {};
        if (s.outline === 'none' || s.outline === '0' || s.outlineWidth === '0px') out.noFocus += 1;
      }
    }
  }
  return out;
}
"""


class A11yModule(Module):
    key = "a11y"
    title = "Доступность"
    weight = 0.20

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not ctx.page.ok:
            result.error = ctx.page.error or f"HTTP {ctx.page.status}"
            return

        self._landmarks(ctx, result)
        self._forms(ctx, result)
        self._names(ctx, result)
        self._frames_and_tables(ctx, result)
        self._duplicate_ids(ctx, result)
        self._tabindex(ctx, result)
        self._placeholder_links(ctx, result)

        if ctx.options.browser:
            await self._computed(ctx, result)
        else:
            result.add(
                "a11y.contrast.skipped",
                "Контраст и размеры элементов не проверялись",
                Severity.INFO,
                "Эти проверки требуют вычисленных стилей.",
                "Запустите с флагом --browser, чтобы измерить контраст текста, "
                "размеры кликабельных зон и видимость фокуса.",
            )

    # ------------------------------------------------------ структура

    def _landmarks(self, ctx: AuditContext, result: ModuleResult) -> None:
        soup = ctx.soup
        has_main = bool(soup.find("main") or soup.find(attrs={"role": "main"}))
        has_nav = bool(soup.find("nav") or soup.find(attrs={"role": "navigation"}))
        result.fact(
            "Ориентиры страницы",
            ", ".join(
                name
                for name, present in (("main", has_main), ("nav", has_nav), ("header", bool(soup.find("header"))))
                if present
            )
            or "не размечены",
        )

        if not has_main:
            result.add(
                "a11y.landmark.main",
                "Нет области <main>",
                Severity.MEDIUM,
                "Пользователи скринридеров переходят к основному содержимому одной командой — "
                "без <main> им приходится прослушивать меню на каждой странице.",
                "Оберните основное содержимое в <main> (ровно один на страницу).",
            )
        else:
            result.ok("a11y.landmark.main", "Основное содержимое размечено как <main>")

        skip_link = soup.find(
            "a", href=lambda v: v and v.startswith("#"), string=re.compile(r"пропустить|содерж|skip", re.I)
        )
        if not skip_link and has_nav:
            result.add(
                "a11y.skiplink",
                "Нет ссылки «пропустить навигацию»",
                Severity.LOW,
                "При работе с клавиатуры меню приходится проходить табом на каждой странице.",
                "Добавьте первой в <body> ссылку на якорь основного содержимого, "
                "видимую только при фокусе.",
            )

    def _forms(self, ctx: AuditContext, result: ModuleResult) -> None:
        soup = ctx.soup
        fields = [
            f
            for f in soup.find_all(["input", "select", "textarea"])
            if (f.get("type") or "text").lower() not in INPUT_TYPES_WITHOUT_LABEL
        ]
        if not fields:
            return

        labels_for = {
            label.get("for") for label in soup.find_all("label", attrs={"for": True})
        }
        unlabeled = []
        for field in fields:
            if field.get("aria-label") or field.get("aria-labelledby") or field.get("title"):
                continue
            if field.get("id") and field.get("id") in labels_for:
                continue
            if field.find_parent("label"):
                continue
            unlabeled.append(field)

        result.fact("Полей формы", f"{len(fields)}, без подписи: {len(unlabeled)}")

        if unlabeled:
            only_placeholder = [f for f in unlabeled if f.get("placeholder")]
            detail = "Скринридер прочитает такое поле как «поле ввода» без пояснения."
            if only_placeholder:
                detail += (
                    f" У {len(only_placeholder)} из них есть только placeholder, "
                    "а он исчезает при вводе и не заменяет подпись."
                )
            result.add(
                "a11y.form.label",
                f"Поля формы без подписи: {len(unlabeled)} из {len(fields)}",
                Severity.HIGH if len(unlabeled) > len(fields) / 2 else Severity.MEDIUM,
                detail,
                "Свяжите каждое поле с <label for>, либо оберните поле в <label>, "
                "либо задайте aria-label. Placeholder подписью не считается.",
                evidence=[
                    truncate(str(f)[:90], 90) for f in unlabeled[:5]
                ],
            )
        else:
            result.ok("a11y.form.label", "У всех полей формы есть подпись")

    def _names(self, ctx: AuditContext, result: ModuleResult) -> None:
        """Ссылки и кнопки, которые скринридер прочитает как пустоту."""
        nameless_links, nameless_buttons = [], []

        for link in ctx.soup.find_all("a", href=True):
            if _accessible_name(link):
                continue
            nameless_links.append(truncate(str(link)[:80], 80))

        for button in ctx.soup.find_all(["button"]) + ctx.soup.find_all(
            "input", attrs={"type": re.compile(r"^(submit|button|reset)$", re.I)}
        ):
            if button.name == "input":
                if button.get("value") or button.get("aria-label"):
                    continue
            elif _accessible_name(button):
                continue
            nameless_buttons.append(truncate(str(button)[:80], 80))

        if nameless_links:
            result.add(
                "a11y.link.name",
                f"Ссылки без текста: {len(nameless_links)}",
                Severity.HIGH,
                "Обычно это иконки без подписи. Скринридер прочитает такую ссылку "
                "как «ссылка» и назовёт адрес — пользователь не поймёт, куда она ведёт.",
                "Добавьте текст внутрь ссылки, alt у картинки-иконки или aria-label.",
                evidence=nameless_links[:5],
            )
        if nameless_buttons:
            result.add(
                "a11y.button.name",
                f"Кнопки без доступного имени: {len(nameless_buttons)}",
                Severity.HIGH,
                "Кнопку без текста и aria-label невозможно опознать на слух.",
                "Задайте кнопке текст или aria-label, описывающий действие.",
                evidence=nameless_buttons[:5],
            )
        if not nameless_links and not nameless_buttons:
            result.ok("a11y.names", "У всех ссылок и кнопок есть доступное имя")

    def _frames_and_tables(self, ctx: AuditContext, result: ModuleResult) -> None:
        frames = [f for f in ctx.soup.find_all("iframe") if not f.get("title")]
        if frames:
            result.add(
                "a11y.iframe.title",
                f"Фреймы без атрибута title: {len(frames)}",
                Severity.MEDIUM,
                "В списке областей страницы такой фрейм будет назван просто «фрейм».",
                'Добавьте title, описывающий содержимое: <iframe title="Карта проезда">. '
                "Особенно важно для встроенных карт, видео и виджетов.",
                evidence=[truncate(f.get("src", ""), 70) for f in frames[:4]],
            )

        tables = ctx.soup.find_all("table")
        bad_tables = [t for t in tables if not t.find("th")]
        if bad_tables:
            result.add(
                "a11y.table.headers",
                f"Таблицы без заголовков столбцов: {len(bad_tables)} из {len(tables)}",
                Severity.LOW,
                "Без <th> скринридер не может связать ячейку с её столбцом.",
                "Разметьте шапку через <th scope=\"col\">, а для сложных таблиц "
                "добавьте <caption> с описанием.",
            )

    def _duplicate_ids(self, ctx: AuditContext, result: ModuleResult) -> None:
        ids = [t["id"] for t in ctx.soup.find_all(attrs={"id": True}) if t["id"].strip()]
        duplicates = [value for value, count in Counter(ids).items() if count > 1]
        if duplicates:
            result.add(
                "a11y.id.duplicate",
                f"Повторяющиеся id в разметке: {len(duplicates)}",
                Severity.MEDIUM,
                "Связки label→поле и aria-labelledby работают по id: при дублях "
                "браузер возьмёт первый попавшийся элемент.",
                "Сделайте идентификаторы уникальными. Чаще всего дубли появляются "
                "при выводе одного шаблона в цикле.",
                evidence=duplicates[:6],
            )
        else:
            result.ok("a11y.id", "Идентификаторы уникальны")

    def _tabindex(self, ctx: AuditContext, result: ModuleResult) -> None:
        positive = [
            t
            for t in ctx.soup.find_all(attrs={"tabindex": True})
            if str(t.get("tabindex", "0")).strip().lstrip("+").isdigit()
            and int(t["tabindex"]) > 0
        ]
        if positive:
            result.add(
                "a11y.tabindex",
                f"Положительный tabindex: {len(positive)} элементов",
                Severity.MEDIUM,
                "Такие элементы вырываются вперёд в порядке обхода клавиатурой, "
                "и последовательность перестаёт совпадать с визуальной.",
                "Используйте только tabindex=\"0\" и tabindex=\"-1\", а порядок задавайте "
                "самой структурой документа.",
            )

    def _placeholder_links(self, ctx: AuditContext, result: ModuleResult) -> None:
        empty = [
            a
            for a in ctx.soup.find_all("a", href=True)
            if a["href"].strip() in ("#", "javascript:void(0)", "javascript:;")
        ]
        if empty:
            result.add(
                "a11y.link.placeholder",
                f"Ссылки-заглушки без адреса: {len(empty)}",
                Severity.LOW,
                "Элемент выглядит как ссылка, но никуда не ведёт.",
                "Если это кнопка — используйте <button>. Так она получит правильную "
                "роль, будет работать по Enter и Space и попадёт в обход клавиатурой.",
                evidence=[truncate(a.get_text(" ", strip=True) or str(a)[:60], 60) for a in empty[:5]],
            )

    # -------------------------------------------------- вычисленные стили

    async def _computed(self, ctx: AuditContext, result: ModuleResult) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.add(
                "a11y.browser.missing",
                "Playwright не установлен — контраст не проверен",
                Severity.INFO,
                "",
                "Установите: pip install playwright и playwright install chromium.",
            )
            return

        try:
            data = await self._collect(ctx, async_playwright)
        except Exception as exc:  # noqa: BLE001 — браузер падает по многим причинам
            result.add(
                "a11y.browser.failed",
                "Не удалось измерить контраст",
                Severity.INFO,
                truncate(str(exc), 150),
                "Проверьте, что браузер установлен: playwright install chromium.",
            )
            return

        self._contrast(result, data)
        self._tap_targets(result, data)
        self._focus(result, data)

    async def _collect(self, ctx: AuditContext, async_playwright) -> dict:
        timeout_ms = int(max(ctx.options.timeout, 30) * 1000)
        viewport = {"width": 393, "height": 852} if ctx.options.mobile else {"width": 1366, "height": 768}
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    viewport=viewport, ignore_https_errors=ctx.options.insecure
                )
                page = await context.new_page()
                await page.goto(ctx.url, wait_until="load", timeout=timeout_ms)
                await page.wait_for_timeout(800)
                return await page.evaluate(CONTRAST_SCRIPT)
            finally:
                await browser.close()

    def _contrast(self, result: ModuleResult, data: dict) -> None:
        checked = data.get("checked") or 0
        unmeasured = data.get("unmeasured") or 0
        low = data.get("low") or []

        measured = f"{counted(checked, 'элемент', 'элемента', 'элементов')}"
        if unmeasured:
            measured += f", не измерено {unmeasured} (текст поверх картинок и градиентов)"
        result.fact("Проверено на контраст", measured)

        if unmeasured and unmeasured > checked:
            result.add(
                "a11y.contrast.unmeasured",
                f"Контраст не удалось измерить у {counted(unmeasured, 'элемента', 'элементов', 'элементов')}",
                Severity.INFO,
                "Текст лежит на фоновых изображениях или градиентах — вычислить "
                "соотношение автоматически нельзя.",
                "Проверьте такие блоки глазами: белый текст на светлой части фотографии "
                "читается плохо. Помогает полупрозрачная подложка под текстом.",
            )

        if not checked:
            return
        if not low:
            result.ok("a11y.contrast", f"Контраст текста соответствует WCAG AA ({checked} элементов)")
            return

        share = pct(len(low), checked)
        worst = sorted(low, key=lambda x: x["ratio"])[:6]
        result.add(
            "a11y.contrast",
            f"Недостаточный контраст текста: {len(low)} из {checked} ({share:.0f}%)",
            Severity.HIGH if share > 20 else Severity.MEDIUM,
            f"Требуется {CONTRAST_AA}:1 для обычного текста и {CONTRAST_AA_LARGE}:1 "
            "для крупного. Светло-серый текст на белом — самая частая причина.",
            "Затемните цвет текста или осветлите фон до нужного соотношения. "
            "Это заметно не только людям с нарушениями зрения, но и всем на солнце.",
            evidence=[
                f"{item['ratio']}:1 при норме {item['need']}:1 "
                f"({item['size']}px) — «{truncate(item['text'], 40)}»"
                for item in worst
            ],
        )

    def _tap_targets(self, result: ModuleResult, data: dict) -> None:
        tiny = data.get("tiny") or []
        if not tiny:
            result.ok("a11y.tap", "Кликабельные элементы достаточного размера")
            return
        result.add(
            "a11y.tap",
            f"Мелкие кликабельные элементы: {len(tiny)}",
            Severity.MEDIUM,
            f"Меньше {TAP_TARGET}×{TAP_TARGET} пикселей — по таким тяжело попасть пальцем "
            "и невозможно при треморе.",
            "Увеличьте область нажатия до 24 пикселей минимум, а лучше до 44. "
            "Размер можно нарастить отступами, не меняя внешний вид.",
            evidence=[
                f"<{t['tag']}> {t['w']}×{t['h']}px — «{truncate(t['text'], 30)}»" for t in tiny[:6]
            ],
        )

    def _focus(self, result: ModuleResult, data: dict) -> None:
        removed = data.get("noFocus") or 0
        if removed:
            result.add(
                "a11y.focus",
                f"Обводка фокуса убрана в стилях ({counted(removed, 'правило', 'правила', 'правил')})",
                Severity.HIGH,
                "Найдены правила :focus с outline: none. Без видимого фокуса "
                "работа с клавиатуры превращается в угадывание.",
                "Не убирайте обводку, а замените на свою заметную. Если она мешает "
                "при клике мышью — используйте :focus-visible вместо :focus.",
            )
        else:
            result.ok("a11y.focus", "Индикатор фокуса не подавлен")


def _accessible_name(tag) -> str:
    """Текст, который скринридер объявит для элемента."""
    if tag.get("aria-label", "").strip() or tag.get("aria-labelledby", "").strip():
        return tag.get("aria-label", "").strip() or "aria-labelledby"
    if tag.get("title", "").strip():
        return tag["title"].strip()
    text = tag.get_text(" ", strip=True)
    if text:
        return text
    for img in tag.find_all("img"):
        if (img.get("alt") or "").strip():
            return img["alt"].strip()
    for svg in tag.find_all("svg"):
        if svg.find("title"):
            return "svg title"
    return ""
