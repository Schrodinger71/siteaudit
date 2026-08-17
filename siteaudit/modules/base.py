"""Базовый класс модуля аудита."""

from __future__ import annotations

from ..context import AuditContext
from ..models import ModuleResult


class Module:
    """Наследники реализуют `analyze` и складывают находки в `result`."""

    key: str = ""
    title: str = ""
    weight: float = 1.0

    async def run(self, ctx: AuditContext) -> ModuleResult:
        result = ModuleResult(key=self.key, title=self.title, weight=self.weight)
        try:
            await self.analyze(ctx, result)
        except Exception as exc:  # noqa: BLE001 — падение модуля не должно ронять аудит
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:  # pragma: no cover
        raise NotImplementedError
