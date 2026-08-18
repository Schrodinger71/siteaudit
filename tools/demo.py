"""Генератор демонстрации для README: анимированный GIF и статичный SVG.

Скрипт не имитирует работу инструмента, а прогоняет настоящий аудит и
записывает то, что реально напечатал rich. Внешние утилиты (vhs, asciinema,
ffmpeg) не нужны — кадры рисуются через Pillow.

    python tools/demo.py
    python tools/demo.py --target example.com --out docs
"""

from __future__ import annotations

import argparse
import asyncio
import io
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siteaudit.audit import audit_site  # noqa: E402
from siteaudit.context import Options  # noqa: E402
from siteaudit.modules import ALL_MODULES  # noqa: E402
from siteaudit.report import render_console, render_html  # noqa: E402

# ------------------------------------------------------------- внешний вид
COLUMNS = 96
ROWS = 28
FONT_SIZE = 14
#: Сколько символов команды печатается и строк отчёта появляется за один кадр.
#: Крупнее шаг — меньше кадров и легче файл, мельче — плавнее анимация.
TYPING_STEP = 3
OUTPUT_STEP = 4
#: Палитра GIF. 64 цветов хватает: в выводе десяток оттенков плюс антиалиасинг.
GIF_COLORS = 64
PADDING = 18
TITLEBAR = 30
BACKGROUND = (22, 24, 28)
CHROME = (32, 35, 40)
DEFAULT_FG = (208, 214, 222)
PROMPT_FG = (86, 182, 126)
CURSOR = (120, 200, 255)
DOTS = ((255, 95, 86), (255, 189, 46), (39, 201, 63))

FONT_CANDIDATES = [
    "C:/Windows/Fonts/CascadiaMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
BOLD_CANDIDATES = [
    "C:/Windows/Fonts/consolab.ttf",
    "C:/Windows/Fonts/DejaVuSansMono-Bold.ttf",
    "C:/Windows/Fonts/CascadiaMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
]

# --------------------------------------------------------------- разбор ANSI
ANSI = re.compile("\x1b\\[([0-9;]*)m")

# rich отдаёт не только truecolor: чаще всего это классические коды 30-37 и
# яркие 90-97, поэтому без палитры вывод получается полностью серым.
BASE_COLORS = [
    (40, 44, 52), (224, 108, 117), (152, 195, 121), (229, 192, 123),
    (97, 175, 239), (198, 120, 221), (86, 182, 194), (171, 178, 191),
]
BRIGHT_COLORS = [
    (92, 99, 112), (255, 132, 140), (178, 217, 148), (247, 217, 160),
    (140, 199, 245), (219, 160, 236), (128, 209, 218), (223, 228, 235),
]


def xterm_color(index: int) -> tuple[int, int, int]:
    """Цвет из 256-цветной палитры xterm."""
    if index < 8:
        return BASE_COLORS[index]
    if index < 16:
        return BRIGHT_COLORS[index - 8]
    if index < 232:
        index -= 16
        levels = (0, 95, 135, 175, 215, 255)
        return (levels[index // 36], levels[(index // 6) % 6], levels[index % 6])
    grey = 8 + (index - 232) * 10
    return (grey, grey, grey)



@dataclass
class Cell:
    """Кусок строки с одинаковым оформлением."""

    text: str
    fg: tuple[int, int, int]
    bg: tuple[int, int, int] | None
    bold: bool


def parse_ansi(dump: str) -> list[list[Cell]]:
    """Разбирает вывод rich в строки из окрашенных кусков."""
    lines: list[list[Cell]] = []
    fg, bg, bold = DEFAULT_FG, None, False

    for raw in dump.split("\n"):
        cells: list[Cell] = []
        position = 0
        for match in ANSI.finditer(raw):
            chunk = raw[position : match.start()]
            if chunk:
                cells.append(Cell(chunk, fg, bg, bold))
            position = match.end()

            codes = [int(c) for c in match.group(1).split(";") if c.isdigit()] or [0]
            index = 0
            while index < len(codes):
                code = codes[index]
                if code == 0:
                    fg, bg, bold = DEFAULT_FG, None, False
                elif code == 1:
                    bold = True
                elif code == 22:
                    bold = False
                elif code == 39:
                    fg = DEFAULT_FG
                elif code == 49:
                    bg = None
                elif 30 <= code <= 37:
                    fg = BASE_COLORS[code - 30]
                elif 90 <= code <= 97:
                    fg = BRIGHT_COLORS[code - 90]
                elif 40 <= code <= 47:
                    bg = BASE_COLORS[code - 40]
                elif 100 <= code <= 107:
                    bg = BRIGHT_COLORS[code - 100]
                elif code in (38, 48) and index + 1 < len(codes):
                    mode = codes[index + 1]
                    if mode == 2 and index + 4 < len(codes):
                        color = (codes[index + 2], codes[index + 3], codes[index + 4])
                        index += 4
                    elif mode == 5 and index + 2 < len(codes):
                        color = xterm_color(codes[index + 2])
                        index += 2
                    else:
                        index += 1
                        continue
                    if code == 38:
                        fg = color
                    else:
                        bg = color
                index += 1

        tail = raw[position:]
        if tail:
            cells.append(Cell(tail, fg, bg, bold))
        lines.append(cells)
    return lines


# ----------------------------------------------------------------- отрисовка
def load_font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont:
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    raise SystemExit("Не найден моноширинный шрифт — поправьте FONT_CANDIDATES в tools/demo.py")


class Renderer:
    """Рисует кадр окна терминала."""

    def __init__(self) -> None:
        self.font = load_font(FONT_CANDIDATES, FONT_SIZE)
        self.bold = load_font(BOLD_CANDIDATES, FONT_SIZE)
        self.char_w = self.font.getlength("M")
        self.line_h = int(FONT_SIZE * 1.55)
        self.width = int(self.char_w * COLUMNS) + PADDING * 2
        self.height = self.line_h * ROWS + PADDING * 2 + TITLEBAR

    def frame(self, lines: list[list[Cell]], cursor: bool = False) -> Image.Image:
        image = Image.new("RGB", (self.width, self.height), BACKGROUND)
        draw = ImageDraw.Draw(image)

        draw.rectangle([0, 0, self.width, TITLEBAR], fill=CHROME)
        for i, color in enumerate(DOTS):
            x = 16 + i * 18
            draw.ellipse([x, TITLEBAR // 2 - 5, x + 10, TITLEBAR // 2 + 5], fill=color)

        # Показываем хвост вывода — как прокрутка в настоящем терминале
        visible = lines[-ROWS:] if len(lines) > ROWS else lines
        for row, cells in enumerate(visible):
            y = TITLEBAR + PADDING + row * self.line_h
            x = float(PADDING)
            for cell in cells:
                width = self.char_w * len(cell.text)
                if cell.bg:
                    draw.rectangle([x, y, x + width, y + self.line_h], fill=cell.bg)
                draw.text(
                    (x, y), cell.text, font=self.bold if cell.bold else self.font, fill=cell.fg
                )
                x += width
            if cursor and row == len(visible) - 1:
                draw.rectangle([x, y + 2, x + self.char_w, y + self.line_h - 2], fill=CURSOR)
        return image


def build_gif(command: str, output: list[list[Cell]], path: Path) -> None:
    renderer = Renderer()
    frames: list[Image.Image] = []
    durations: list[int] = []

    prompt = Cell("$ ", PROMPT_FG, None, True)

    # набор команды
    for i in range(TYPING_STEP, len(command) + TYPING_STEP, TYPING_STEP):
        typed_part = command[:i]
        frames.append(renderer.frame([[prompt, Cell(typed_part, DEFAULT_FG, None, False)]], True))
        durations.append(110)

    typed = [prompt, Cell(command, DEFAULT_FG, None, False)]
    frames.append(renderer.frame([typed]))
    durations.append(900)

    # вывод отчёта по три строки за кадр
    shown: list[list[Cell]] = [typed, []]
    for i in range(0, len(output), OUTPUT_STEP):
        shown.extend(output[i : i + OUTPUT_STEP])
        frames.append(renderer.frame(shown))
        durations.append(160)

    frames.append(renderer.frame(shown))
    durations.append(5000)

    palette = [
        f.quantize(colors=GIF_COLORS, method=Image.MEDIANCUT, dither=Image.NONE) for f in frames
    ]
    palette[0].save(
        path,
        save_all=True,
        append_images=palette[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"GIF: {path} — кадров {len(frames)}, {path.stat().st_size / 1024:.0f} КБ")


async def shoot_html(html: str, path: Path, height: int = 1500) -> bool:
    """Снимок HTML-отчёта. Нужен браузер, поэтому шаг необязательный."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("Playwright не установлен — снимок HTML-отчёта пропущен")
        return False

    page_file = path.with_suffix(".html")
    page_file.write_text(html, encoding="utf-8")
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1120, "height": height},
                device_scale_factor=2,
                color_scheme="dark",
            )
            page = await context.new_page()
            await page.goto(page_file.resolve().as_uri(), wait_until="load")
            await page.wait_for_timeout(400)
            await page.screenshot(path=str(path))
            await browser.close()
    except Exception as exc:  # noqa: BLE001 — без снимка остальное всё равно собирается
        print(f"Снимок HTML не сделан: {exc}")
        return False
    finally:
        page_file.unlink(missing_ok=True)

    print(f"PNG: {path} — {path.stat().st_size / 1024:.0f} КБ")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Сборка демонстрации для README")
    parser.add_argument("--target", default="example.com", help="какой сайт проверять")
    parser.add_argument("--out", default="docs", help="каталог для demo.gif и demo.svg")
    args = parser.parse_args()

    command = f"siteaudit {args.target} --safe"
    options = Options(safe=True, timeout=20, max_assets=12, max_links=8)
    modules = [m for m in ALL_MODULES if m.key in ("seo", "performance", "security", "tech")]

    report = asyncio.run(audit_site(args.target, options, modules))
    if report.error:
        print(f"Аудит не удался: {report.error}")
        return 1

    console = Console(
        record=True,
        width=COLUMNS,
        file=io.StringIO(),
        color_system="truecolor",
        legacy_windows=False,
    )
    render_console([report], console)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Текст снимаем первым и без очистки: и export_text, и save_svg по
    # умолчанию опустошают буфер записи, и второй вызов получил бы пустоту.
    dump = console.export_text(styles=True, clear=False)

    console.save_svg(str(out / "demo.svg"), title=command)
    print(f"SVG: {out / 'demo.svg'}")

    asyncio.run(shoot_html(render_html([report]), out / "report.png"))

    lines = parse_ansi(dump.rstrip(chr(10)))
    while lines and not lines[-1]:
        lines.pop()
    build_gif(command, lines, out / "demo.gif")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
