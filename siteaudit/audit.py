"""Оркестрация аудита: собирает контекст и прогоняет модули."""

from __future__ import annotations

import asyncio
import time

from .context import Options, build_context
from .fetcher import DEFAULT_UA, MOBILE_UA, Fetcher
from .models import Report
from .modules import ALL_MODULES, Module
from .modules.crawl import CrawlModule
from .modules.tech import TechModule
from .modules.vitals import VitalsModule
from .utils import normalize_url


def select_modules(
    only: list[str] | None,
    skip: list[str] | None,
    crawl: int = 0,
    browser: bool = False,
) -> list[type[Module]]:
    mods = list(ALL_MODULES)
    if only:
        wanted = {k.strip().lower() for k in only}
        mods = [m for m in mods if m.key in wanted]
    if skip:
        unwanted = {k.strip().lower() for k in skip}
        mods = [m for m in mods if m.key not in unwanted]
    # Дорогие модули включаются только явными флагами
    if not crawl:
        mods = [m for m in mods if m is not CrawlModule]
    if not browser:
        mods = [m for m in mods if m is not VitalsModule]
    return mods


def choose_user_agent(options: Options) -> str:
    """Свой User-Agent важнее всего, иначе десктопный или мобильный по флагу."""
    if options.user_agent:
        return options.user_agent
    return MOBILE_UA if options.mobile else DEFAULT_UA


async def audit_site(
    target: str,
    options: Options,
    modules: list[type[Module]] | None = None,
    progress=None,
) -> Report:
    """Полный аудит одного сайта."""
    started = time.perf_counter()
    try:
        url = normalize_url(target)
    except ValueError as exc:
        return Report(target=target, error=str(exc))

    report = Report(target=url)
    mods = modules if modules is not None else list(ALL_MODULES)

    fetcher = Fetcher(
        timeout=options.timeout,
        concurrency=options.concurrency,
        user_agent=choose_user_agent(options),
        verify=not options.insecure,
    )
    try:
        if progress:
            progress("загрузка страницы")
        ctx = await build_context(url, fetcher, options)
        report.final_url = ctx.page.url

        if not ctx.page.ok:
            report.error = ctx.page.error or f"сервер ответил HTTP {ctx.page.status}"
            return report

        # Технологии определяем первыми — остальные модули на них опираются
        tech_cls = next((m for m in mods if m is TechModule), None)
        if tech_cls:
            if progress:
                progress("определение движка")
            report.modules.append(await tech_cls().run(ctx))
            report.techs = ctx.techs

        rest = [m for m in mods if m is not TechModule]
        if rest:
            if progress:
                progress("проверки: " + ", ".join(m.key for m in rest))
            results = await asyncio.gather(*[m().run(ctx) for m in rest])
            report.modules.extend(results)

        order = {m.key: i for i, m in enumerate(mods)}
        report.modules.sort(key=lambda r: order.get(r.key, 99))
        report.screenshot = ctx.screenshot
    finally:
        await fetcher.aclose()
        report.duration = time.perf_counter() - started

    return report


async def audit_many(
    targets: list[str],
    options: Options,
    modules: list[type[Module]] | None = None,
    progress=None,
) -> list[Report]:
    reports: list[Report] = []
    for target in targets:
        if progress:
            progress(f"{target}: старт")
        reports.append(await audit_site(target, options, modules, progress))
    return reports
