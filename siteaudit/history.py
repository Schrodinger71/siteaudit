"""История прогонов в SQLite: хранение отчётов и сравнение с прошлым разом."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import Diff, DiffItem, Report, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT    NOT NULL,
    final_url  TEXT,
    started_at TEXT    NOT NULL,
    duration   REAL,
    score      INTEGER NOT NULL,
    grade      TEXT,
    modules    TEXT,
    payload    TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    run_id     INTEGER NOT NULL,
    module     TEXT    NOT NULL,
    finding_id TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    title      TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""

DEFAULT_PATH = Path.home() / ".siteaudit" / "history.db"


@dataclass
class StoredRun:
    id: int
    target: str
    started_at: datetime
    score: int
    grade: str
    duration: float
    modules: list[str]


class History:
    """Журнал прогонов. Открывается лениво, чтобы не создавать файл без нужды."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_PATH
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------ доступ

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(SCHEMA)
            self._migrate(self._conn)
        return self._conn

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Дотягивает схему баз, созданных прошлыми версиями."""
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
        if "modules" not in columns:
            conn.execute("ALTER TABLE runs ADD COLUMN modules TEXT")
            conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "History":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ запись

    def save(self, report: Report) -> int:
        payload = json.dumps(report.to_dict(), ensure_ascii=False)
        cur = self.conn.execute(
            "INSERT INTO runs"
            " (target, final_url, started_at, duration, score, grade, modules, payload)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _key(report.target),
                report.final_url,
                report.started_at.isoformat(timespec="seconds"),
                round(report.duration, 2),
                report.score,
                report.grade,
                ",".join(sorted(m.key for m in report.modules)),
                payload,
            ),
        )
        run_id = int(cur.lastrowid or 0)
        rows = [
            (run_id, module.key, f.id, f.severity.value, f.title)
            for module in report.modules
            for f in module.findings
            if f.severity not in (Severity.OK, Severity.INFO)
        ]
        if rows:
            self.conn.executemany(
                "INSERT INTO findings (run_id, module, finding_id, severity, title)"
                " VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        self.conn.commit()
        return run_id

    # ------------------------------------------------------------- чтение

    def runs(self, target: str | None = None, limit: int = 20) -> list[StoredRun]:
        columns = "id, target, started_at, score, grade, duration, modules"
        if target:
            cur = self.conn.execute(
                f"SELECT {columns} FROM runs WHERE target = ? ORDER BY id DESC LIMIT ?",
                (_key(target), limit),
            )
        else:
            cur = self.conn.execute(
                f"SELECT {columns} FROM runs ORDER BY id DESC LIMIT ?", (limit,)
            )
        return [
            StoredRun(
                id=row["id"],
                target=row["target"],
                started_at=datetime.fromisoformat(row["started_at"]),
                score=row["score"],
                grade=row["grade"] or "",
                duration=row["duration"] or 0.0,
                modules=[k for k in (row["modules"] or "").split(",") if k],
            )
            for row in cur.fetchall()
        ]

    def last_run(self, target: str) -> StoredRun | None:
        found = self.runs(target, limit=1)
        return found[0] if found else None

    def _findings_of(self, run_id: int) -> dict[str, DiffItem]:
        cur = self.conn.execute(
            "SELECT module, finding_id, severity, title FROM findings WHERE run_id = ?",
            (run_id,),
        )
        out: dict[str, DiffItem] = {}
        for row in cur.fetchall():
            key = f"{row['module']}:{row['finding_id']}"
            out[key] = DiffItem(
                key=key,
                module=row["module"],
                title=row["title"] or row["finding_id"],
                severity=Severity(row["severity"]),
            )
        return out

    # -------------------------------------------------------------- дифф

    def diff_against_previous(self, report: Report) -> Diff | None:
        """Сравнивает отчёт с последним сохранённым прогоном того же адреса."""
        previous = self.last_run(report.target)
        if previous is None:
            return None

        # Сравнивать можно только модули, отработавшие в обоих прогонах: иначе
        # запуск с --only показал бы все находки отключённых модулей «исправленными».
        current_modules = {m.key for m in report.modules}
        shared = current_modules & set(previous.modules) if previous.modules else current_modules
        if not shared:
            return None

        before = {
            k: item for k, item in self._findings_of(previous.id).items() if item.module in shared
        }
        now: dict[str, DiffItem] = {}
        for module in report.modules:
            if module.key not in shared:
                continue
            for f in module.findings:
                if f.severity in (Severity.OK, Severity.INFO):
                    continue
                key = f"{module.key}:{f.id}"
                now[key] = DiffItem(
                    key=key, module=module.key, title=f.title, severity=f.severity
                )

        appeared = [now[k] for k in now.keys() - before.keys()]
        fixed = [before[k] for k in before.keys() - now.keys()]
        appeared.sort(key=lambda i: (i.severity.rank, i.title))
        fixed.sort(key=lambda i: (i.severity.rank, i.title))

        return Diff(
            previous_at=previous.started_at,
            previous_score=previous.score,
            current_score=report.score,
            appeared=appeared,
            fixed=fixed,
            still_open=len(now.keys() & before.keys()),
            same_modules=bool(previous.modules) and set(previous.modules) == current_modules,
        )


def _key(target: str) -> str:
    """Ключ адреса для сравнения прогонов: без схемы, www и хвостового слэша."""
    value = target.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    if value.startswith("www."):
        value = value[4:]
    return value.rstrip("/") or target
