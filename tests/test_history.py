"""Тесты журнала прогонов и вычисления диффа."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from siteaudit.history import History, _key
from siteaudit.models import ModuleResult, Report, Severity


def make_report(target: str, findings: list[tuple[str, Severity]], module: str = "seo") -> Report:
    result = ModuleResult(key=module, title=module.upper())
    for finding_id, severity in findings:
        result.add(finding_id, f"Заголовок {finding_id}", severity)
    report = Report(target=target, final_url=target)
    report.modules.append(result)
    return report


@pytest.fixture()
def history(tmp_path):
    with History(tmp_path / "history.db") as h:
        yield h


class TestKeyNormalization:
    @pytest.mark.parametrize(
        "target",
        [
            "https://example.com",
            "http://example.com/",
            "https://www.example.com",
            "example.com",
        ],
    )
    def test_same_site_written_differently_shares_key(self, target):
        assert _key(target) == "example.com"

    def test_different_sites_differ(self):
        assert _key("https://example.com") != _key("https://example.org")


class TestSaveAndRead:
    def test_first_run_has_no_diff(self, history):
        report = make_report("https://example.com", [("seo.a", Severity.HIGH)])
        assert history.diff_against_previous(report) is None
        history.save(report)

    def test_run_is_listed(self, history):
        history.save(make_report("https://example.com", [("seo.a", Severity.HIGH)]))
        runs = history.runs("example.com")
        assert len(runs) == 1
        assert runs[0].modules == ["seo"]

    def test_www_and_bare_domain_are_one_site(self, history):
        history.save(make_report("https://www.example.com", [("seo.a", Severity.HIGH)]))
        assert len(history.runs("https://example.com")) == 1


class TestDiff:
    def test_detects_fixed_and_appeared(self, history):
        first = make_report(
            "https://example.com", [("seo.a", Severity.HIGH), ("seo.b", Severity.LOW)]
        )
        history.save(first)

        second = make_report(
            "https://example.com", [("seo.b", Severity.LOW), ("seo.c", Severity.MEDIUM)]
        )
        diff = history.diff_against_previous(second)

        assert {i.key for i in diff.fixed} == {"seo:seo.a"}
        assert {i.key for i in diff.appeared} == {"seo:seo.c"}
        assert diff.still_open == 1

    def test_score_delta_counted(self, history):
        history.save(make_report("https://example.com", [("seo.a", Severity.CRITICAL)]))
        second = make_report("https://example.com", [])
        diff = history.diff_against_previous(second)
        assert diff.score_delta == 25
        assert diff.same_modules

    def test_ok_and_info_findings_are_not_tracked(self, history):
        first = make_report(
            "https://example.com", [("seo.a", Severity.OK), ("seo.b", Severity.INFO)]
        )
        history.save(first)
        second = make_report("https://example.com", [])
        diff = history.diff_against_previous(second)
        assert diff.fixed == []
        assert diff.appeared == []

    def test_different_module_sets_are_not_compared_by_score(self, history):
        """Запуск с --only не должен выглядеть как «всё исправлено»."""
        wide = make_report("https://example.com", [("seo.a", Severity.HIGH)])
        wide.modules.append(ModuleResult(key="security", title="SEC"))
        wide.modules[1].add("sec.x", "Дыра", Severity.CRITICAL)
        history.save(wide)

        narrow = make_report("https://example.com", [("seo.a", Severity.HIGH)])
        diff = history.diff_against_previous(narrow)

        assert not diff.same_modules
        assert diff.fixed == [], "находки отключённого модуля не должны считаться исправленными"

    def test_diff_uses_latest_run(self, history):
        for finding in ("seo.a", "seo.b"):
            history.save(make_report("https://example.com", [(finding, Severity.HIGH)]))
        current = make_report("https://example.com", [("seo.b", Severity.HIGH)])
        diff = history.diff_against_previous(current)
        assert diff.fixed == [] and diff.appeared == []


class TestSchemaMigration:
    def test_old_database_without_modules_column_is_upgraded(self, tmp_path):
        import sqlite3

        path = tmp_path / "old.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,"
            " final_url TEXT, started_at TEXT NOT NULL, duration REAL, score INTEGER NOT NULL,"
            " grade TEXT, payload TEXT);"
            "CREATE TABLE findings (run_id INTEGER, module TEXT, finding_id TEXT,"
            " severity TEXT, title TEXT);"
        )
        conn.execute(
            "INSERT INTO runs (target, started_at, score, grade) VALUES (?, ?, ?, ?)",
            ("example.com", datetime.now().isoformat(timespec="seconds"), 50, "D"),
        )
        conn.commit()
        conn.close()

        with History(path) as history:
            runs = history.runs("example.com")
            assert len(runs) == 1
            assert runs[0].modules == []

    def test_run_without_stored_modules_falls_back_to_comparing(self, tmp_path):
        with History(tmp_path / "h.db") as history:
            history.save(make_report("https://example.com", [("seo.a", Severity.HIGH)]))
            history.conn.execute("UPDATE runs SET modules = NULL")
            history.conn.commit()
            diff = history.diff_against_previous(
                make_report("https://example.com", [("seo.a", Severity.HIGH)])
            )
            assert diff is not None
            assert not diff.same_modules
