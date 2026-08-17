"""Тесты подсчёта экономии на изображениях."""

from __future__ import annotations

import asyncio
import io

import pytest

from siteaudit.images import MIN_SIZE, ImageSaving, analyze

Image = pytest.importorskip("PIL.Image", reason="нужен Pillow")


def make_image(fmt: str, size: tuple[int, int] = (900, 700), noisy: bool = True) -> bytes:
    """Картинка с шумом: однотонная сжимается слишком хорошо и ничего не проверяет."""
    import random

    img = Image.new("RGB", size)
    pixels = img.load()
    random.seed(1)
    for x in range(size[0]):
        for y in range(0, size[1], 2):
            value = random.randint(0, 255) if noisy else 128
            pixels[x, y] = (value, (value * 3) % 256, (value * 7) % 256)
    buffer = io.BytesIO()
    img.save(buffer, format=fmt, quality=95) if fmt == "JPEG" else img.save(buffer, format=fmt)
    return buffer.getvalue()


class TestAnalyze:
    def test_computes_savings_for_png(self):
        data = make_image("PNG")
        savings, skipped = asyncio.run(analyze([("http://x/a.png", data, None)]))
        assert skipped == 0
        assert len(savings) == 1
        assert savings[0].fmt == "PNG"
        assert savings[0].optimized > 0

    def test_skips_small_files(self):
        savings, _ = asyncio.run(analyze([("http://x/tiny.png", b"x" * (MIN_SIZE - 1), None)]))
        assert savings == []

    def test_broken_file_is_counted_as_skipped(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * MIN_SIZE
        savings, skipped = asyncio.run(analyze([("http://x/broken.png", data, None)]))
        assert savings == []
        assert skipped == 1

    def test_results_sorted_by_saving(self):
        payloads = [
            ("http://x/small.png", make_image("PNG", (300, 300)), None),
            ("http://x/big.png", make_image("PNG", (900, 700)), None),
        ]
        savings, _ = asyncio.run(analyze(payloads))
        assert [s.saved for s in savings] == sorted((s.saved for s in savings), reverse=True)


class TestModernFormat:
    def test_webp_marked_as_modern(self):
        saving = ImageSaving(
            url="http://x/a.webp", original=100_000, optimized=70_000,
            width=800, height=600, fmt="WEBP",
        )
        assert saving.already_modern

    @pytest.mark.parametrize("fmt", ["JPEG", "PNG", "GIF", "BMP"])
    def test_legacy_formats_are_convertible(self, fmt):
        saving = ImageSaving(
            url="http://x/a", original=100_000, optimized=70_000,
            width=800, height=600, fmt=fmt,
        )
        assert not saving.already_modern

    def test_real_webp_detected_as_modern(self):
        data = make_image("WEBP")
        savings, _ = asyncio.run(analyze([("http://x/a.webp", data, None)]))
        assert savings and savings[0].already_modern


class TestOversized:
    def test_wider_than_double_display_is_oversized(self):
        saving = ImageSaving(
            url="http://x/a.jpg", original=100_000, optimized=50_000,
            width=1600, height=1200, fmt="JPEG", displayed_width=320,
        )
        assert saving.oversized

    def test_matching_display_width_is_fine(self):
        saving = ImageSaving(
            url="http://x/a.jpg", original=100_000, optimized=50_000,
            width=640, height=480, fmt="JPEG", displayed_width=320,
        )
        assert not saving.oversized

    def test_huge_image_without_known_display_width(self):
        saving = ImageSaving(
            url="http://x/a.jpg", original=100_000, optimized=50_000,
            width=2400, height=1800, fmt="JPEG",
        )
        assert saving.oversized


class TestRatios:
    def test_saved_never_negative(self):
        saving = ImageSaving(
            url="http://x/a.webp", original=50_000, optimized=80_000,
            width=100, height=100, fmt="WEBP",
        )
        assert saving.saved == 0
        assert saving.ratio == 0.0

    def test_ratio_matches_sizes(self):
        saving = ImageSaving(
            url="http://x/a.png", original=200_000, optimized=50_000,
            width=100, height=100, fmt="PNG",
        )
        assert saving.saved == 150_000
        assert saving.ratio == pytest.approx(0.75)
