"""Тесты ручного задания версий и разбора данных из баз уязвимостей."""

from __future__ import annotations

import pytest

from siteaudit.cli import _parse_versions
from siteaudit.models import Tech
from siteaudit.vulns import CHECKABLE, NVD_CPE, NvdVulnerability, clean_version


class TestParseVersions:
    def test_single_pair(self):
        assert _parse_versions(["React=18.2.0"]) == {"React": "18.2.0"}

    def test_several_pairs(self):
        parsed = _parse_versions(["nginx=1.24.0", "PHP=8.1.2"])
        assert parsed == {"nginx": "1.24.0", "PHP": "8.1.2"}

    def test_spaces_are_trimmed(self):
        assert _parse_versions([" React = 18.2.0 "]) == {"React": "18.2.0"}

    def test_version_may_contain_equals_sign(self):
        assert _parse_versions(["X=1.0=beta"]) == {"X": "1.0=beta"}

    @pytest.mark.parametrize("bad", ["React", "=18.2.0", "React=", "", "  "])
    def test_malformed_pair_rejected(self, bad):
        with pytest.raises(ValueError, match="ИМЯ=ВЕРСИЯ"):
            _parse_versions([bad])

    def test_empty_list(self):
        assert _parse_versions([]) == {}


class TestCleanVersion:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1.24.0", "1.24.0"),
            ("8.1.2-1ubuntu2.14", "8.1.2"),
            ("1.30.4 (Ubuntu)", "1.30.4"),
            ("2.4.58~deb12", "2.4.58"),
            ("6", "6"),
            ("", ""),
            ("неизвестно", ""),
        ],
    )
    def test_numeric_part_extracted(self, raw, expected):
        assert clean_version(raw) == expected


class TestNvdParsing:
    def test_severity_from_cvss31(self):
        v = NvdVulnerability({
            "id": "CVE-2023-1",
            "descriptions": [{"lang": "en", "value": "Пример"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
        })
        assert v.severity == "HIGH"
        assert v.label == "CVE-2023-1"
        assert v.url.endswith("CVE-2023-1")

    def test_falls_back_to_older_metric(self):
        v = NvdVulnerability({
            "id": "CVE-2010-1",
            "descriptions": [{"lang": "en", "value": "Старая"}],
            "metrics": {"cvssMetricV2": [{"baseSeverity": "MEDIUM"}]},
        })
        assert v.severity == "MEDIUM"

    def test_unknown_when_no_metrics(self):
        v = NvdVulnerability({"id": "CVE-X", "descriptions": [], "metrics": {}})
        assert v.severity == "UNKNOWN"
        assert v.summary == ""

    def test_english_description_preferred(self):
        v = NvdVulnerability({
            "id": "CVE-1",
            "descriptions": [
                {"lang": "es", "value": "descripción"},
                {"lang": "en", "value": "description"},
            ],
            "metrics": {},
        })
        assert v.summary == "description"


class TestCheckableCoverage:
    @pytest.mark.parametrize("name", ["nginx", "Apache", "PHP", "WordPress"])
    def test_server_software_has_source(self, name):
        """Серверное ПО должно проверяться, иначе версия nginx собирается зря."""
        assert name in NVD_CPE
        assert name in CHECKABLE

    @pytest.mark.parametrize("name", ["React", "Next.js", "Swiper", "jQuery"])
    def test_frontend_libraries_have_source(self, name):
        assert name in CHECKABLE

    def test_cpe_templates_have_version_placeholder(self):
        for name, template in NVD_CPE.items():
            assert "{version}" in template, f"в шаблоне {name} нет места под версию"
            assert template.startswith("cpe:2.3:")


class TestManualVersionsApplied:
    """Версия из --set-version должна попадать в отчёт и в сверку."""

    def test_overrides_detected_version(self, dirty_site):
        from siteaudit.audit import audit_site
        from siteaudit.context import Options
        from siteaudit.modules.tech import TechModule
        import asyncio

        report = asyncio.run(
            audit_site(
                dirty_site,
                Options(check_cve=False, timeout=15, versions={"WordPress": "6.4.1"}),
                [TechModule],
            )
        )
        wp = next(t for t in report.techs if t.name == "WordPress")
        assert wp.version == "6.4.1"
        assert "вручную" in wp.evidence[0]

    def test_adds_technology_that_was_not_detected(self, dirty_site):
        from siteaudit.audit import audit_site
        from siteaudit.context import Options
        from siteaudit.modules.tech import TechModule
        import asyncio

        report = asyncio.run(
            audit_site(
                dirty_site,
                Options(check_cve=False, timeout=15, versions={"PHP": "8.1.2"}),
                [TechModule],
            )
        )
        php = next((t for t in report.techs if t.name == "PHP"), None)
        assert php is not None and php.version == "8.1.2"

    def test_name_matching_is_case_insensitive(self, dirty_site):
        from siteaudit.audit import audit_site
        from siteaudit.context import Options
        from siteaudit.modules.tech import TechModule
        import asyncio

        report = asyncio.run(
            audit_site(
                dirty_site,
                Options(check_cve=False, timeout=15, versions={"wordpress": "6.5"}),
                [TechModule],
            )
        )
        names = [t.name for t in report.techs]
        assert names.count("WordPress") == 1
        assert next(t for t in report.techs if t.name == "WordPress").version == "6.5"
