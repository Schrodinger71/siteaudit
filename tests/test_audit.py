"""Проверки аудита на локальных стендах.

Главная идея: на эталонном стенде находок быть не должно вообще, а на грязном
должны быть строго определённые. Первое ловит ложные срабатывания, второе —
молча переставшие работать проверки.
"""

from __future__ import annotations

import asyncio

import pytest

from siteaudit.audit import audit_site, choose_user_agent
from siteaudit.context import Options
from siteaudit.models import Severity
from siteaudit.modules.a11y import A11yModule
from siteaudit.modules.crawl import CrawlModule
from siteaudit.modules.performance import PerformanceModule
from siteaudit.modules.security import SecurityModule
from siteaudit.modules.seo import SeoModule
from siteaudit.modules.tech import TechModule


def run(url: str, modules: list, **options):
    """Аудит без обращений к внешним сервисам."""
    opts = Options(check_cve=False, timeout=15, **options)
    return asyncio.run(audit_site(url, opts, modules))


def ids(module) -> set[str]:
    return {f.id for f in module.findings}


def problem_ids(module) -> set[str]:
    return {f.id for f in module.problems}


# --------------------------------------------------------------- эталон


@pytest.fixture(scope="module")
def clean_seo(clean_site):
    report = run(clean_site, [SeoModule])
    assert not report.error, report.error
    return report.modules[0]


class TestCleanStand:
    def test_no_findings_at_all(self, clean_seo):
        """Любая находка на эталонной странице — ложное срабатывание."""
        assert problem_ids(clean_seo) == set(), (
            "На эталонном стенде не должно быть находок, а нашлись: "
            + ", ".join(f"{f.id} ({f.title})" for f in clean_seo.problems)
        )

    def test_perfect_score(self, clean_seo):
        assert clean_seo.score == 100

    @pytest.mark.parametrize(
        "check",
        [
            "seo.title",
            "seo.description",
            "seo.h1",
            "seo.headings",
            "seo.canonical",
            "seo.favicon",
            "seo.og",
            "seo.schema",
            "seo.lang",
            "seo.viewport",
            "seo.index",
            "seo.robots",
            "seo.sitemap",
            "seo.404",
            "seo.links",
            "seo.img.alt",
            "seo.content",
        ],
    )
    def test_check_actually_ran_and_passed(self, clean_seo, check):
        """Проверка должна не просто молчать, а явно отметиться как пройденная."""
        passed = {f.id for f in clean_seo.passed}
        assert check in passed, f"проверка {check} не отметилась пройденной"

    def test_favicon_declared_in_markup(self, clean_seo):
        facts = dict(clean_seo.facts)
        assert "объявлен" in facts["Favicon"]

    def test_canonical_detected(self, clean_seo):
        facts = dict(clean_seo.facts)
        assert facts["Canonical"].startswith("http")


def test_clean_stand_stylesheets_counted(clean_site):
    """Регрессия: подсчёт CSS ломался вместе с разбором rel."""
    report = run(clean_site, [PerformanceModule])
    facts = dict(report.modules[0].facts)
    assert facts["CSS-файлов в <head>"] == "1"


def test_clean_stand_no_blocking_scripts(clean_site):
    report = run(clean_site, [PerformanceModule])
    assert "perf.render.js" not in problem_ids(report.modules[0])


# ---------------------------------------------------------------- грязный


@pytest.fixture(scope="module")
def dirty_seo(dirty_site):
    report = run(dirty_site, [SeoModule])
    assert not report.error, report.error
    return report.modules[0]


@pytest.fixture(scope="module")
def dirty_security(dirty_site):
    report = run(dirty_site, [SecurityModule])
    assert not report.error, report.error
    return report.modules[0]


class TestDirtyStandSeo:
    @pytest.mark.parametrize(
        "finding",
        [
            "seo.img.alt",        # у картинки нет alt
            "seo.links.broken",   # ссылка на /broken-page
            "seo.schema.missing", # нет JSON-LD
        ],
    )
    def test_expected_findings(self, dirty_seo, finding):
        assert finding in problem_ids(dirty_seo)

    def test_score_is_low(self, dirty_seo):
        assert dirty_seo.score < 80


class TestDirtyStandSecurity:
    def test_http_without_tls(self, dirty_security):
        assert "sec.https.missing" in problem_ids(dirty_security)

    def test_form_posts_over_http(self, dirty_security):
        assert "sec.form.http" in problem_ids(dirty_security)

    def test_password_form_on_http(self, dirty_security):
        assert "sec.form.password-http" in problem_ids(dirty_security)

    @pytest.mark.parametrize("leaked", [".env", ".git"])
    def test_exposed_sensitive_files(self, dirty_security, leaked):
        exposed = [i for i in problem_ids(dirty_security) if i.startswith("sec.exposed")]
        assert any(leaked in i for i in exposed), f"не найден открытый {leaked}"

    def test_missing_security_headers(self, dirty_security):
        found = problem_ids(dirty_security)
        assert "sec.header.content-security-policy" in found
        assert "sec.header.x-content-type-options" in found

    def test_secret_in_markup(self, dirty_security):
        assert "sec.leak.keys" in problem_ids(dirty_security)

    def test_findings_carry_recommendations(self, dirty_security):
        """Находка без рекомендации бесполезна пользователю."""
        without = [f.id for f in dirty_security.problems if not f.recommendation]
        assert without == [], f"нет рекомендации у: {without}"


class TestSafeMode:
    def test_safe_mode_skips_active_probes(self, dirty_site):
        report = run(dirty_site, [SecurityModule], safe=True)
        found = problem_ids(report.modules[0])
        assert not [i for i in found if i.startswith("sec.exposed")]
        assert "sec.paths.skipped" in ids(report.modules[0])


# ------------------------------------------------------------------ обход


@pytest.fixture(scope="module")
def dirty_crawl(dirty_site):
    report = run(dirty_site, [CrawlModule], crawl=30, depth=4)
    assert not report.error, report.error
    return report.modules[0]


class TestCrawl:
    def test_finds_broken_page(self, dirty_crawl):
        assert "crawl.broken" in problem_ids(dirty_crawl)

    def test_finds_duplicate_titles(self, dirty_crawl):
        assert "crawl.duplicate.title" in problem_ids(dirty_crawl)

    def test_finds_duplicate_descriptions(self, dirty_crawl):
        assert "crawl.duplicate.description" in problem_ids(dirty_crawl)

    def test_finds_pages_without_title(self, dirty_crawl):
        assert "crawl.meta.title" in problem_ids(dirty_crawl)

    def test_finds_noindex_page(self, dirty_crawl):
        assert "crawl.noindex" in problem_ids(dirty_crawl)

    def test_finds_orphan_in_sitemap(self, dirty_crawl):
        assert "crawl.sitemap.orphans" in problem_ids(dirty_crawl)

    def test_finds_deep_page(self, dirty_crawl):
        assert "crawl.depth" in problem_ids(dirty_crawl)

    def test_respects_robots_disallow(self, dirty_crawl):
        facts = dict(dirty_crawl.facts)
        assert facts.get("Закрыто в robots.txt") == "1"

    def test_clean_stand_has_no_structural_problems(self, clean_site):
        report = run(clean_site, [CrawlModule], crawl=20, depth=3)
        found = problem_ids(report.modules[0])
        # тонкий контент на подстраницах ожидаем, структурных проблем — нет
        assert not {
            "crawl.broken",
            "crawl.duplicate.title",
            "crawl.meta.title",
            "crawl.sitemap.missing",
        } & found


# ------------------------------------------------------------ технологии


class TestTech:
    def test_detects_wordpress_from_generator(self, dirty_site):
        report = run(dirty_site, [TechModule])
        names = {t.name for t in report.techs}
        assert "WordPress" in names

    def test_cve_status_always_reported(self, dirty_site):
        """Молчание нельзя путать с «уязвимостей нет»."""
        report = run(dirty_site, [TechModule])
        facts = dict(report.modules[0].facts)
        assert "Проверка уязвимостей" in facts
        assert facts["Проверка уязвимостей"] == "отключена флагом --no-cve"


# -------------------------------------------------------------- прочее


# ------------------------------------------------------------ доступность


@pytest.fixture(scope="module")
def dirty_a11y(dirty_site):
    report = run(dirty_site, [A11yModule])
    assert not report.error, report.error
    return report.modules[0]


class TestAccessibility:
    @pytest.mark.parametrize(
        "finding",
        [
            "a11y.landmark.main",      # нет <main>
            "a11y.form.label",         # поля только с placeholder
            "a11y.link.name",          # ссылка-иконка без текста
            "a11y.button.name",        # пустая кнопка
            "a11y.iframe.title",       # фрейм без title
            "a11y.id.duplicate",       # два элемента с id="block"
            "a11y.tabindex",           # tabindex="5"
            "a11y.link.placeholder",   # href="#"
            "a11y.table.headers",      # таблица без th
        ],
    )
    def test_dirty_stand_findings(self, dirty_a11y, finding):
        assert finding in problem_ids(dirty_a11y)

    def test_clean_stand_has_no_a11y_problems(self, clean_site):
        report = run(clean_site, [A11yModule])
        assert problem_ids(report.modules[0]) == set(), (
            "на эталонном стенде не должно быть замечаний по доступности: "
            + ", ".join(f.id for f in report.modules[0].problems)
        )

    def test_clean_stand_labels_recognized(self, clean_site):
        report = run(clean_site, [A11yModule])
        passed = {f.id for f in report.modules[0].passed}
        assert {"a11y.form.label", "a11y.landmark.main", "a11y.names"} <= passed

    def test_contrast_skipped_without_browser(self, dirty_a11y):
        """Без --browser модуль обязан сказать, что контраст не измерялся."""
        assert "a11y.contrast.skipped" in ids(dirty_a11y)


class TestUserAgent:
    def test_desktop_by_default(self):
        assert "Mobile" not in choose_user_agent(Options())

    def test_mobile_flag_switches_agent(self):
        agent = choose_user_agent(Options(mobile=True))
        assert "Mobile" in agent and "Android" in agent

    def test_custom_agent_wins_over_mobile_flag(self):
        assert choose_user_agent(Options(mobile=True, user_agent="Мой бот")) == "Мой бот"


def test_unreachable_host_is_reported_not_crashed():
    report = run("http://127.0.0.1:9/", [SeoModule])
    assert report.error
    assert report.score == 0


def test_findings_are_sorted_by_severity(dirty_security):
    ranks = [f.severity.rank for f in dirty_security.problems]
    assert ranks == sorted(ranks)


def test_no_finding_uses_ok_severity_in_problems(dirty_security):
    assert all(f.severity is not Severity.OK for f in dirty_security.problems)
