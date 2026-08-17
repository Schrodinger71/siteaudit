"""Юнит-тесты вспомогательных функций."""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from siteaudit.utils import (
    abs_url,
    counted,
    has_icon_rel,
    has_rel,
    normalize_url,
    plural,
    registrable,
    rel_values,
    same_site,
)


def _parse(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "lxml")


class TestRelParsing:
    """Регрессия на баг, из-за которого не находились favicon, canonical и CSS.

    BeautifulSoup отдаёт rel списком через tag.get(), но строкой — в функцию-фильтр
    find_all(). Старый код рассчитывал только на список и молча ничего не находил.
    """

    def test_rel_values_accepts_list(self):
        tag = _parse('<link rel="canonical" href="/x">').find("link")
        assert rel_values(tag) == ["canonical"]

    def test_rel_values_accepts_string(self):
        class FakeTag(dict):
            def get(self, key, default=None):
                return {"rel": "shortcut icon"}.get(key, default)

        assert rel_values(FakeTag()) == ["shortcut", "icon"]

    def test_rel_values_empty_when_absent(self):
        tag = _parse("<link href='/x'>").find("link")
        assert rel_values(tag) == []

    @pytest.mark.parametrize(
        "html",
        [
            '<link rel="canonical" href="/x">',
            '<link rel="CANONICAL" href="/x">',
        ],
    )
    def test_has_rel_finds_canonical(self, html):
        assert has_rel(_parse(html).find("link"), "canonical")

    def test_has_rel_is_exact_not_substring(self):
        tag = _parse('<link rel="canonicalize" href="/x">').find("link")
        assert not has_rel(tag, "canonical")

    @pytest.mark.parametrize(
        "rel",
        ["icon", "shortcut icon", "apple-touch-icon", "mask-icon", "ICON"],
    )
    def test_has_icon_rel_covers_all_icon_forms(self, rel):
        tag = _parse(f'<link rel="{rel}" href="/f.ico">').find("link")
        assert has_icon_rel(tag)

    def test_has_icon_rel_ignores_other_links(self):
        tag = _parse('<link rel="stylesheet" href="/a.css">').find("link")
        assert not has_icon_rel(tag)

    def test_stylesheet_detection(self):
        soup = _parse(
            '<link rel="stylesheet" href="/a.css">'
            '<link rel="preload" as="style" href="/b.css">'
        )
        found = [t for t in soup.find_all("link") if has_rel(t, "stylesheet")]
        assert len(found) == 1


class TestPlural:
    @pytest.mark.parametrize(
        ("count", "expected"),
        [(1, "балл"), (2, "балла"), (4, "балла"), (5, "баллов"), (11, "баллов"),
         (14, "баллов"), (21, "балл"), (22, "балла"), (25, "баллов"), (101, "балл"),
         (0, "баллов"), (-3, "балла")],
    )
    def test_plural_forms(self, count, expected):
        assert plural(count, "балл", "балла", "баллов") == expected

    def test_counted_includes_number(self):
        assert counted(2, "страница", "страницы", "страниц") == "2 страницы"


class TestUrls:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "https://example.com/"),
            ("http://example.com", "http://example.com/"),
            ("https://example.com/path", "https://example.com/path"),
            ("  example.com  ", "https://example.com/"),
            ("https://example.com/p?a=1#frag", "https://example.com/p?a=1"),
        ],
    )
    def test_normalize_url(self, raw, expected):
        assert normalize_url(raw) == expected

    def test_normalize_url_rejects_empty(self):
        with pytest.raises(ValueError):
            normalize_url("   ")

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("shop.example.co.uk", "example.co.uk"),
        ],
    )
    def test_registrable(self, host, expected):
        assert registrable(host) == expected

    def test_same_site_across_subdomains(self):
        assert same_site("https://www.example.com/a", "https://shop.example.com/b")

    def test_same_site_rejects_other_domain(self):
        assert not same_site("https://example.com", "https://example.org")

    @pytest.mark.parametrize(
        "link", ["javascript:void(0)", "mailto:a@b.c", "tel:+700", "#anchor", ""]
    )
    def test_abs_url_skips_non_http(self, link):
        assert abs_url("https://example.com/", link) is None

    def test_abs_url_strips_fragment(self):
        assert abs_url("https://example.com/a/", "b#x") == "https://example.com/a/b"
