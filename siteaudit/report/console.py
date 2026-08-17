"""Вывод отчёта в терминал."""

from __future__ import annotations

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Report, Severity

BAR_WIDTH = 24


def _score_color(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 70:
        return "yellow"
    if score >= 45:
        return "dark_orange"
    return "red"


def _bar(score: int, width: int = BAR_WIDTH) -> Text:
    filled = round(score / 100 * width)
    color = _score_color(score)
    return Text("█" * filled, style=color) + Text("░" * (width - filled), style="grey35")


def render_console(reports: list[Report], console: Console | None = None, verbose: bool = False) -> None:
    console = console or Console()
    for report in reports:
        _render_one(report, console, verbose)
        console.print()


def _render_one(report: Report, console: Console, verbose: bool) -> None:
    header = Table.grid(padding=(0, 2))
    header.add_column(justify="left")
    header.add_column(justify="left")

    if report.error:
        console.print(
            Panel(
                Text(f"Не удалось проверить сайт: {report.error}", style="red"),
                title=f"[bold]{report.target}[/bold]",
                border_style="red",
            )
        )
        return

    score = report.score
    header.add_row(
        Text("Итоговая оценка", style="bold"),
        Text.assemble(
            _bar(score),
            Text(f"  {score}/100  ", style=f"bold {_score_color(score)}"),
            Text(f"({report.grade})", style="grey62"),
        ),
    )
    for module in report.modules:
        header.add_row(
            Text(module.title, style="grey70"),
            Text.assemble(
                _bar(module.score, 18),
                Text(f"  {module.score}/100" if not module.error else "  — ошибка", style=_score_color(module.score)),
            ),
        )
    header.add_row(Text("Адрес", style="grey70"), Text(report.final_url or report.target, style="cyan"))
    header.add_row(Text("Время проверки", style="grey70"), Text(f"{report.duration:.1f} с", style="grey62"))

    console.print(
        Panel(header, title=f"[bold]Аудит {report.target}[/bold]", border_style=_score_color(score))
    )

    counts = _total_counts(report)
    summary = Text.assemble(
        Text("Найдено: ", style="bold"),
        Text(f"критично {counts['critical']}  ", style="bold red"),
        Text(f"важно {counts['high']}  ", style="red"),
        Text(f"средне {counts['medium']}  ", style="yellow"),
        Text(f"мелочи {counts['low']}  ", style="cyan"),
        Text(f"пройдено {counts['ok']}", style="green"),
    )
    console.print(summary)
    console.print()

    for module in report.modules:
        _render_module(module, console, verbose)

    top = [f for f in report.all_problems() if f.severity in (Severity.CRITICAL, Severity.HIGH)][:7]
    if top:
        plan = Table.grid(padding=(0, 1))
        plan.add_column(style="bold grey62", width=3)
        plan.add_column()
        for i, f in enumerate(top, 1):
            plan.add_row(
                f"{i}.",
                Group(
                    Text(f.title, style=f.severity.color),
                    Text(f.recommendation or f.detail, style="grey70"),
                ),
            )
        console.print(Panel(plan, title="[bold]Что делать в первую очередь[/bold]", border_style="magenta"))


def _render_module(module, console: Console, verbose: bool) -> None:
    title = f"[bold]{module.title}[/bold] — {module.score}/100"
    if module.error:
        console.print(Panel(Text(module.error, style="red"), title=title, border_style="red"))
        return

    blocks = []

    if module.facts:
        facts = Table(show_header=False, box=None, padding=(0, 2))
        facts.add_column(style="grey62", no_wrap=True)
        facts.add_column(style="white")
        for name, value in module.facts:
            facts.add_row(name, value)
        blocks.append(facts)

    problems = module.problems
    if problems:
        blocks.append(Text())
        for f in problems:
            blocks.append(_finding_text(f))
    else:
        blocks.append(Text("\nПроблем не найдено.", style="green"))

    if verbose:
        for f in module.notes:
            blocks.append(_finding_text(f))
        if module.passed:
            blocks.append(Text())
            for f in module.passed:
                blocks.append(Text(f"  ✓ {f.title}", style="green"))

    console.print(Panel(Group(*blocks), title=title, border_style=_score_color(module.score)))


def _finding_text(f) -> Padding:
    parts: list = [
        Text.assemble(
            Text(f"[{f.severity.label}] ", style=f.severity.color),
            Text(f.title, style="bold"),
        )
    ]
    if f.detail:
        parts.append(Padding(Text(f.detail, style="grey70"), (0, 0, 0, 2)))
    for ev in f.evidence[:5]:
        parts.append(Padding(Text(f"· {ev}", style="grey50"), (0, 0, 0, 4)))
    if f.recommendation:
        parts.append(Padding(Text(f"→ {f.recommendation}", style="cyan"), (0, 0, 0, 2)))
    parts.append(Text())
    return Padding(Group(*parts), (0, 0, 0, 2))


def _total_counts(report: Report) -> dict[str, int]:
    total = {s.value: 0 for s in Severity}
    for m in report.modules:
        for key, value in m.counts().items():
            total[key] += value
    return total
