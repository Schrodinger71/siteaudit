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
from .modules import ALL_MODULES
from .report import render_console, render_html, render_json

EPILOG = """\
Примеры:
  siteaudit example.com
  siteaudit https://example.com --html отчёт.html --json отчёт.json
  siteaudit example.com --only security,performance -v
  siteaudit example.com --crawl 20 --assets 80
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
    p.add_argument("urls", nargs="+", metavar="URL", help="адреса сайтов для проверки")
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
    p.add_argument("--crawl", type=int, default=0, help="дополнительно просканировать N внутренних страниц")
    p.add_argument("--safe", action="store_true", help="без активных проб служебных файлов (.git, .env и т. п.)")
    p.add_argument("--insecure", action="store_true", help="не проверять TLS-сертификат при запросах")
    p.add_argument("--user-agent", help="свой User-Agent")
    p.add_argument(
        "--fail-under",
        type=int,
        metavar="N",
        help="выйти с кодом 1, если итоговая оценка ниже N (для CI)",
    )
    p.add_argument("--version", action="version", version=f"siteaudit {__version__}")
    return p


def _prepare(raw: str) -> Path:
    path = Path(raw).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    err = Console(stderr=True)

    options = Options(
        timeout=args.timeout,
        concurrency=max(1, args.concurrency),
        max_assets=max(0, args.assets),
        max_links=max(0, args.links),
        crawl=max(0, args.crawl),
        safe=args.safe,
        insecure=args.insecure,
        user_agent=args.user_agent,
    )
    modules = select_modules(
        args.only.split(",") if args.only else None,
        args.skip.split(",") if args.skip else None,
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
