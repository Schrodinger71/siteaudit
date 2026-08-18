"""Проверки целостности самих тестовых стендов.

Эти тесты существуют из-за реального случая: файлы-приманки `.env` и `.git/HEAD`
лежали только на машине разработчика. Локально всё было зелёным, а на чистом
клоне в CI тесты безопасности падали, потому что проверять было нечего.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import httpx
import pytest

from conftest import BAIT_FILES

FIXTURES = Path(__file__).parent


def tracked_files(directory: str) -> set[str]:
    out = subprocess.run(
        ["git", "ls-files", directory],
        cwd=FIXTURES.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


class TestStandsAreInRepository:
    """Стенд обязан полностью восстанавливаться из чистого клона."""

    @pytest.mark.parametrize("sample", sorted(BAIT_FILES))
    def test_bait_sample_is_tracked(self, sample):
        tracked = tracked_files("tests/fixture")
        assert f"tests/fixture/{sample}" in tracked, (
            f"файл {sample} не в репозитории — на чистом клоне стенд соберётся неполным"
        )

    @pytest.mark.parametrize("stand", ["tests/fixture", "tests/fixture-clean"])
    def test_every_local_file_is_tracked(self, stand):
        """Ни один файл стенда не должен существовать только локально."""
        tracked = tracked_files(stand)
        on_disk = {
            p.relative_to(FIXTURES.parent).as_posix()
            for p in (FIXTURES.parent / stand).rglob("*")
            if p.is_file()
        }
        untracked = on_disk - tracked
        assert untracked == set(), f"файлы есть только на диске: {sorted(untracked)}"


class TestBaitFilesAreServed:
    """Приманки должны реально отдаваться стендом, иначе проверки безопасности пусты."""

    @pytest.mark.parametrize(("path", "marker"), [("/.env", "DB_PASSWORD"), ("/.git/HEAD", "ref:")])
    def test_served(self, dirty_site, path, marker):
        response = httpx.get(dirty_site + path, timeout=10)
        assert response.status_code == 200, f"{path} не отдаётся стендом"
        assert marker in response.text

    def test_samples_directory_is_not_exposed(self, dirty_site):
        """Служебный каталог с приманками не должен попадать в раздачу."""
        response = httpx.get(dirty_site + "/samples/dotenv", timeout=10)
        assert response.status_code == 404
