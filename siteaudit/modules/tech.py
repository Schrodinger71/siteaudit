"""Определение движка сайта, фреймворков, сервера, CDN и сторонних сервисов."""

from __future__ import annotations

import re

from ..context import AuditContext
from ..models import ModuleResult, Severity, Tech
from ..signatures import OUTDATED_THRESHOLDS, SIGNATURES
from ..utils import counted, truncate
from ..vulns import CHECKABLE, lookup_many
from .base import Module


def _version_tuple(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[.\-_]", v):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts) or (0,)


def _older_than(found: str, threshold: str) -> bool:
    a, b = _version_tuple(found), _version_tuple(threshold)
    size = max(len(a), len(b))
    a += (0,) * (size - len(a))
    b += (0,) * (size - len(b))
    return a < b


class TechModule(Module):
    key = "tech"
    title = "Движок и технологии"
    weight = 0.10

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        page = ctx.page
        if not page.ok:
            result.error = page.error or f"HTTP {page.status}"
            return

        html = ctx.html
        headers = page.headers
        cookie_names = _cookie_names(page)
        script_srcs = ctx.resources()["script"]
        generator = ctx.meta("generator") or ""

        detected: dict[str, Tech] = {}
        for sig in SIGNATURES:
            tech = _match(sig, html, headers, cookie_names, script_srcs, generator)
            if tech:
                detected[tech.name] = tech

        # Подтягиваем подразумеваемые технологии
        for sig in SIGNATURES:
            if sig["name"] in detected:
                for implied in sig.get("implies", []):
                    if implied not in detected:
                        detected[implied] = Tech(
                            name=implied,
                            category=_category_of(implied),
                            confidence=40,
                            evidence=[f"подразумевается наличием «{sig['name']}»"],
                        )

        techs = sorted(detected.values(), key=lambda t: (-t.confidence, t.category, t.name))
        ctx.techs = techs

        # Сначала CVE: если по технологии есть конкретные уязвимости, общее
        # предупреждение «версия устарела» становится лишним шумом.
        if ctx.options.check_cve:
            vulnerable = await self._cve(ctx, result, techs)
        else:
            vulnerable = set()
            result.fact("Проверка уязвимостей", "отключена флагом --no-cve")
        self._report(ctx, result, techs, vulnerable)

    async def _cve(
        self, ctx: AuditContext, result: ModuleResult, techs: list[Tech]
    ) -> set[str]:
        """Сверяет найденные версии с базой уязвимостей OSV.dev."""
        outcome = await lookup_many(ctx.fetcher, techs)
        self._cve_fact(result, techs, outcome)

        if outcome.failed:
            result.add(
                "tech.cve.unavailable",
                f"Не удалось проверить по базе уязвимостей "
                f"{counted(outcome.failed, 'версию', 'версии', 'версий')}",
                Severity.INFO,
                "Сервис osv.dev не ответил. Это не значит, что уязвимостей нет — "
                "проверка просто не состоялась.",
                "Повторите запуск позже или отключите проверку флагом --no-cve.",
            )
        if not outcome.found:
            if outcome.checked:
                result.ok(
                    "tech.cve.clean",
                    f"Известных уязвимостей не найдено "
                    f"({counted(outcome.checked, 'версия', 'версии', 'версий')} проверено)",
                )
            return set()

        for name, vulns in outcome.found.items():
            tech = next((t for t in techs if t.name == name), None)
            version = tech.version if tech else "?"
            worst = vulns[0].severity
            severity = Severity.CRITICAL if worst == "CRITICAL" else Severity.HIGH
            result.add(
                f"tech.cve.{name.lower()}",
                f"{name} {version}: известные уязвимости ({len(vulns)})",
                severity,
                f"Версия числится уязвимой в базе OSV.dev. Максимальная критичность: {worst}.",
                f"Обновите {name} до последней версии. Если обновление ломает совместимость, "
                "проверьте, эксплуатируется ли уязвимость в вашем сценарии, и закройте "
                "её обходным путём (WAF, CSP, отключение уязвимого компонента).",
                evidence=[
                    f"{v.label} [{v.severity}] {truncate(v.summary, 70)}" for v in vulns[:6]
                ],
            )
        return set(outcome.found)

    @staticmethod
    def _cve_fact(result: ModuleResult, techs: list[Tech], outcome) -> None:
        """Статус сверки с базой уязвимостей выводится всегда.

        Иначе «сверять было нечего» выглядит в отчёте так же, как «не сверяли».
        """
        if outcome.found:
            total = sum(len(v) for v in outcome.found.values())
            status = (
                f"найдено {counted(total, 'уязвимость', 'уязвимости', 'уязвимостей')} "
                f"в {counted(len(outcome.found), 'компоненте', 'компонентах', 'компонентах')}"
            )
        elif outcome.checked:
            status = (
                f"{counted(outcome.checked, 'версия', 'версии', 'версий')} сверено с OSV.dev, "
                "известных уязвимостей нет"
            )
        else:
            blind = sorted({t.name for t in techs if t.name in CHECKABLE and not t.version})
            if blind:
                status = "сверять нечего: не удалось определить версию — " + ", ".join(blind)
            else:
                status = "сверять нечего: библиотек с известными версиями не найдено"

        if outcome.failed:
            status += f"; не удалось проверить: {outcome.failed}"
        result.fact("Проверка уязвимостей", status)

    # ------------------------------------------------------------------ вывод

    def _report(
        self,
        ctx: AuditContext,
        result: ModuleResult,
        techs: list[Tech],
        vulnerable: set[str] | None = None,
    ) -> None:
        vulnerable = vulnerable or set()
        by_cat: dict[str, list[Tech]] = {}
        for t in techs:
            by_cat.setdefault(t.category, []).append(t)

        cms = by_cat.get("CMS") or by_cat.get("Конструктор") or by_cat.get("E-commerce")
        engine = cms[0] if cms else None

        if engine:
            ver = f" {engine.version}" if engine.version else ""
            result.fact("Движок сайта", f"{engine.name}{ver}")
        else:
            fw = by_cat.get("Фреймворк")
            result.fact("Движок сайта", fw[0].name if fw else "не определён (самописный или SPA)")

        for cat in ("Фреймворк", "Сервер", "Язык", "CDN", "Хостинг", "Аналитика", "Библиотека"):
            items = by_cat.get(cat)
            if items:
                result.fact(
                    cat,
                    ", ".join(t.name + (f" {t.version}" if t.version else "") for t in items),
                )

        result.fact("Протокол", ctx.page.http_version or "—")
        server = ctx.page.header("server")
        result.fact("Заголовок Server", server or "скрыт")

        if not techs:
            result.add(
                "tech.none",
                "Технологии не определились",
                Severity.INFO,
                "Ни одна сигнатура не сработала — вероятно, самописное решение, "
                "статика или агрессивная обфускация сборки.",
            )
        else:
            names = ", ".join(t.name for t in techs[:12])
            result.add(
                "tech.stack",
                f"Обнаружено технологий: {len(techs)}",
                Severity.INFO,
                truncate(names, 300),
            )

        # Устаревшие версии
        for t in techs:
            if not t.version or t.name not in OUTDATED_THRESHOLDS or t.name in vulnerable:
                continue
            threshold, why = OUTDATED_THRESHOLDS[t.name]
            if _older_than(t.version, threshold):
                result.add(
                    f"tech.outdated.{t.name.lower()}",
                    f"Устаревшая версия: {t.name} {t.version}",
                    Severity.HIGH,
                    why,
                    f"Обновите {t.name} минимум до {threshold}. "
                    "Перед обновлением снимите бэкап и проверьте совместимость шаблона/плагинов.",
                    evidence=t.evidence[:3],
                )
            else:
                result.ok(
                    f"tech.version.{t.name.lower()}",
                    f"{t.name} {t.version} — актуальная ветка",
                )

        # Аналитика
        analytics = by_cat.get("Аналитика", [])
        if not analytics:
            result.add(
                "tech.analytics.missing",
                "Не найдено ни одной системы аналитики",
                Severity.MEDIUM,
                "На странице нет счётчиков Google Analytics, Яндекс.Метрики, GTM и подобных.",
                "Подключите Яндекс.Метрику и/или GA4 — без данных о поведении "
                "невозможно оценивать эффект от доработок.",
            )
        else:
            result.ok(
                "tech.analytics",
                "Аналитика подключена",
                ", ".join(t.name for t in analytics),
            )

        # Микс из тяжёлых конструкторов
        if len([t for t in techs if t.category in ("CMS", "Конструктор", "E-commerce")]) > 1:
            result.add(
                "tech.multiple-cms",
                "Признаки нескольких CMS одновременно",
                Severity.LOW,
                "Возможен недомигрированный сайт или остатки старого движка в разметке.",
                "Проверьте, не осталось ли на сервере файлов прошлой CMS — "
                "они часто становятся точкой входа для взлома.",
            )

        if not by_cat.get("CDN"):
            result.add(
                "tech.cdn.missing",
                "CDN не используется",
                Severity.LOW,
                "Статика отдаётся напрямую с исходного сервера.",
                "Для географически распределённой аудитории подключите CDN "
                "(Cloudflare, Gcore, CloudFront) — это снижает TTFB и разгружает сервер.",
            )


def _match(
    sig: dict,
    html: str,
    headers: dict[str, str],
    cookies: list[str],
    scripts: list[str],
    generator: str,
) -> Tech | None:
    evidence: list[str] = []
    confidence = 0

    for name, pattern in (sig.get("headers") or {}).items():
        value = headers.get(name.lower())
        if value is None:
            continue
        if not pattern or re.search(pattern, value, re.I):
            evidence.append(f"заголовок {name}: {truncate(value, 60)}")
            confidence += 45

    if sig.get("meta") and generator and re.search(sig["meta"], generator, re.I):
        evidence.append(f"meta generator: {truncate(generator, 60)}")
        confidence += 45

    for pattern in sig.get("html", []):
        m = re.search(pattern, html, re.I)
        if m:
            evidence.append(f"в HTML: {truncate(m.group(0), 60)}")
            confidence += 25
            break

    for pattern in sig.get("cookies", []):
        for name in cookies:
            if re.search(pattern, name, re.I):
                evidence.append(f"cookie: {name}")
                confidence += 35
                break

    for pattern in sig.get("scripts", []):
        for src in scripts:
            if re.search(pattern, src, re.I):
                evidence.append(f"скрипт: {truncate(src, 70)}")
                confidence += 30
                break

    if confidence < 25:
        return None

    version = None
    haystack = html + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + "\n".join(scripts)
    for pattern in sig.get("version", []):
        m = re.search(pattern, haystack, re.I)
        if m and m.group(1):
            version = m.group(1)
            break

    return Tech(
        name=sig["name"],
        category=sig["category"],
        version=version,
        confidence=min(99, confidence),
        evidence=evidence[:4],
    )


def _cookie_names(page) -> list[str]:
    names: list[str] = []
    for key, value in page.raw_headers:
        if key.lower() == "set-cookie":
            names.append(value.split("=", 1)[0].strip())
    return names


def _category_of(name: str) -> str:
    for sig in SIGNATURES:
        if sig["name"] == name:
            return sig["category"]
    return "Прочее"
