"""Командный интерфейс siteaudit."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .audit import audit_many, select_modules
from .context import Options
from .history import DEFAULT_PATH, History
from .modules import ALL_MODULES
from .report import render_console, render_html, render_json
from .report.console import render_history

EPILOG = """\
Примеры:
  siteaudit example.com
  siteaudit https://example.com --html отчёт.html --json отчёт.json
  siteaudit example.com --only security,performance -v
  siteaudit example.com --crawl 20 --assets 80
  siteaudit example.com --browser
  siteaudit example.com --history-list
  siteaudit site1.ru site2.ru --safe

Используйте инструмент только на сайтах, которыми владеете или на проверку
которых у вас есть разрешение: часть проверок обращается к служебным адресам.
"""


def build_parser() -> argparse.ArgumentParser:
    keys = ", ".join(m.key for m in ALL_MODULES)
    p = argparse.ArgumentParser(
        prog="siteaudit",
        description="Полный аудит сайта: SEO, производительность, безопасность, движок.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("urls", nargs="*", metavar="URL", help="адреса сайтов для проверки")
    p.add_argument("--only", help=f"проверять только эти модули ({keys})")
    p.add_argument("--skip", help="пропустить эти модули")
    p.add_argument("--html", metavar="ФАЙЛ", help="сохранить HTML-отчёт")
    p.add_argument("--json", metavar="ФАЙЛ", help="сохранить JSON-отчёт")
    p.add_argument("-v", "--verbose", action="store_true", help="показывать пройденные проверки")
    p.add_argument("-q", "--quiet", action="store_true", help="не печатать отчёт в терминал")
    p.add_argument("--timeout", type=float, default=20.0, help="таймаут запроса, с (по умолчанию 20)")
    p.add_argument("--concurrency", type=int, default=10, help="параллельных запросов (10)")
    p.add_argument("--assets", type=int, default=40, help="сколько ресурсов взвешивать (40)")
    p.add_argument("--links", type=int, default=30, help="сколько ссылок проверять на битость (30)")
    p.add_argument("--crawl", type=int, default=0, help="обойти до N страниц сайта (включает модуль crawl)")
    p.add_argument("--depth", type=int, default=3, help="максимальная глубина обхода от главной (3)")
    p.add_argument(
        "--browser",
        action="store_true",
        help="запустить настоящий браузер: Core Web Vitals, рендеринг JS, скриншот",
    )
    p.add_argument(
        "--mobile",
        action="store_true",
        help="проверять как мобильный: мобильный User-Agent, а с --browser ещё и "
        "замер на экране телефона рядом с десктопным",
    )
    p.add_argument("--safe", action="store_true", help="без активных проб служебных файлов (.git, .env и т. п.)")
    p.add_argument(
        "--no-cve",
        action="store_true",
        help="не обращаться к osv.dev за списком уязвимостей найденных версий",
    )
    p.add_argument("--insecure", action="store_true", help="не проверять TLS-сертификат при запросах")
    p.add_argument(
        "--set-version",
        action="append",
        metavar="ИМЯ=ВЕРСИЯ",
        default=[],
        help="задать версию вручную, если её не удалось определить из разметки "
        "(например: --set-version React=18.2.0). Имя — как в отчёте. "
        "Флаг можно повторять",
    )
    p.add_argument("--user-agent", help="свой User-Agent")
    p.add_argument(
        "--fail-under",
        type=int,
        metavar="N",
        help="выйти с кодом 1, если итоговая оценка ниже N (для CI)",
    )
    history = p.add_argument_group("история прогонов")
    history.add_argument(
        "--no-history", action="store_true", help="не сохранять прогон и не показывать дифф"
    )
    history.add_argument(
        "--history-list",
        nargs="?",
        type=int,
        const=15,
        metavar="N",
        help="показать последние N прогонов (для указанных URL или для всех) и выйти",
    )
    history.add_argument(
        "--history-db", metavar="ФАЙЛ", help=f"путь к базе истории (по умолчанию {DEFAULT_PATH})"
    )
    p.add_argument("--version", action="version", version=f"siteaudit {__version__}")
    return p


def _parse_versions(pairs: list[str]) -> dict[str, str]:
    """Разбирает значения --set-version вида «React=18.2.0»."""
    versions: dict[str, str] = {}
    for pair in pairs:
        name, sep, version = pair.partition("=")
        name, version = name.strip(), version.strip()
        if not sep or not name or not version:
            raise ValueError(
                f"Не разобрать --set-version «{pair}». Ожидается ИМЯ=ВЕРСИЯ, "
                "например React=18.2.0"
            )
        versions[name] = version
    return versions


def _prepare(raw: str) -> Path:
    path = Path(raw).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    err = Console(stderr=True)
    db_path = Path(args.history_db).expanduser() if args.history_db else None

    if args.history_list is not None:
        with History(db_path) as history:
            targets = args.urls or [None]
            for target in targets:
                render_history(history.runs(target, limit=args.history_list), target, console)
        return 0

    if not args.urls:
        err.print("[red]Не указан ни один адрес.[/red] Пример: siteaudit example.com")
        return 2

    try:
        versions = _parse_versions(args.set_version)
    except ValueError as exc:
        err.print(f"[red]{exc}[/red]")
        return 2

    options = Options(
        timeout=args.timeout,
        concurrency=max(1, args.concurrency),
        max_assets=max(0, args.assets),
        max_links=max(0, args.links),
        crawl=max(0, args.crawl),
        depth=max(0, args.depth),
        safe=args.safe,
        insecure=args.insecure,
        check_cve=not args.no_cve,
        browser=args.browser,
        mobile=args.mobile,
        versions=versions,
        user_agent=args.user_agent,
    )
    modules = select_modules(
        args.only.split(",") if args.only else None,
        args.skip.split(",") if args.skip else None,
        crawl=options.crawl,
        browser=options.browser,
    )
    if not modules:
        err.print("[red]Не выбрано ни одного модуля.[/red] Проверьте --only/--skip.")
        return 2

    with console.status("[grey62]Проверка…") as status:
        reports = asyncio.run(
            audit_many(
                args.urls,
                options,
                modules,
                progress=lambda msg: status.update(f"[grey62]{msg}"),
            )
        )

    if not args.no_history:
        try:
            with History(db_path) as history:
                for report in reports:
                    if report.error:
                        continue
                    # Дифф считаем до записи, иначе сравним прогон сам с собой
                    report.diff = history.diff_against_previous(report)
                    history.save(report)
        except Exception as exc:  # noqa: BLE001 — история не должна ронять аудит
            err.print(f"[yellow]История недоступна:[/yellow] {exc}")

    if not args.quiet:
        render_console(reports, console, verbose=args.verbose)

    if args.html:
        path = _prepare(args.html)
        path.write_text(render_html(reports), encoding="utf-8")
        console.print(f"HTML-отчёт: [cyan]{path.resolve()}[/cyan]")
    if args.json:
        path = _prepare(args.json)
        path.write_text(render_json(reports), encoding="utf-8")
        console.print(f"JSON-отчёт: [cyan]{path.resolve()}[/cyan]")

    if any(r.error for r in reports):
        return 2
    if args.fail_under is not None and any(r.score < args.fail_under for r in reports):
        err.print(f"[red]Оценка ниже порога {args.fail_under}.[/red]")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
