"""JSON-вывод отчёта."""

from __future__ import annotations

import json

from ..models import Report


def render_json(reports: list[Report], indent: int = 2) -> str:
    payload = {
        "tool": "siteaudit",
        "version": __import__("siteaudit").__version__,
        "reports": [r.to_dict() for r in reports],
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)
