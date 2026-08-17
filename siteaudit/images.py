"""Подсчёт реальной экономии на изображениях: пережатие в памяти через Pillow.

Смысл в том, чтобы вместо совета «переведите картинки в WebP» показать
конкретные мегабайты и проценты по каждому файлу.
"""

from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass

try:
    from PIL import Image

    PILLOW_AVAILABLE = True
except ImportError:  # pragma: no cover
    PILLOW_AVAILABLE = False

#: Качество WebP, при котором разница с оригиналом визуально незаметна
WEBP_QUALITY = 82
#: Мельче этого пережимать бессмысленно — накладные расходы съедят выигрыш
MIN_SIZE = 15_000
#: Ширина, больше которой картинку почти наверняка показывают уменьшенной
OVERSIZED_WIDTH = 2000
#: Экономия ниже этой доли не стоит возни
WORTH_IT = 0.15
#: Форматы, которые уже современные. Пережимать их в WebP q82 нельзя выдавать
#: за экономию: выигрыш там берётся из потери качества, а не из смены формата.
MODERN_FORMATS = {"WEBP", "AVIF", "JXL"}


@dataclass
class ImageSaving:
    url: str
    original: int
    optimized: int
    width: int
    height: int
    fmt: str
    displayed_width: int | None = None

    @property
    def saved(self) -> int:
        return max(0, self.original - self.optimized)

    @property
    def ratio(self) -> float:
        return self.saved / self.original if self.original else 0.0

    @property
    def already_modern(self) -> bool:
        """Файл уже в современном формате — экономию от конвертации заявлять нечестно."""
        return self.fmt in MODERN_FORMATS

    @property
    def oversized(self) -> bool:
        """Картинка отдаётся заметно крупнее, чем показывается на странице."""
        if not self.displayed_width or not self.width:
            return self.width > OVERSIZED_WIDTH
        return self.width > self.displayed_width * 2


def _recompress(data: bytes) -> tuple[int, int, int, str] | None:
    """Возвращает (размер после пережатия, ширина, высота, формат) или None."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            fmt = (img.format or "").upper()
            width, height = img.size
            if img.mode in ("P", "LA", "RGBA"):
                img = img.convert("RGBA")
            elif img.mode != "RGB":
                img = img.convert("RGB")

            buffer = io.BytesIO()
            img.save(buffer, format="WEBP", quality=WEBP_QUALITY, method=4)
            return buffer.tell(), width, height, fmt
    except Exception:  # noqa: BLE001 — битые и экзотические файлы просто пропускаем
        return None


async def analyze(
    items: list[tuple[str, bytes, int | None]],
) -> tuple[list[ImageSaving], int]:
    """Считает экономию по списку (url, содержимое, ширина отображения).

    Пережатие упирается в процессор, поэтому идёт в отдельных потоках,
    чтобы не блокировать сетевые запросы остального аудита.
    """
    if not PILLOW_AVAILABLE:
        return [], 0

    candidates = [
        (url, data, shown)
        for url, data, shown in items
        if data and len(data) >= MIN_SIZE
    ]
    if not candidates:
        return [], 0

    loop = asyncio.get_running_loop()
    results = await asyncio.gather(
        *[loop.run_in_executor(None, _recompress, data) for _, data, _ in candidates]
    )

    savings: list[ImageSaving] = []
    skipped = 0
    for (url, data, shown), outcome in zip(candidates, results):
        if outcome is None:
            skipped += 1
            continue
        optimized, width, height, fmt = outcome
        savings.append(
            ImageSaving(
                url=url,
                original=len(data),
                optimized=optimized,
                width=width,
                height=height,
                fmt=fmt,
                displayed_width=shown,
            )
        )

    savings.sort(key=lambda s: -s.saved)
    return savings, skipped
