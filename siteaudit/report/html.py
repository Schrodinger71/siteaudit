"""Самодостаточный HTML-отчёт."""

from __future__ import annotations

from datetime import datetime
from html import escape

from ..models import Report, Severity

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.OK]

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f6f7f9; --panel:#fff; --line:#e3e6ea; --text:#1c2024; --muted:#697077;
  --crit:#c92a2a; --high:#e8590c; --med:#c9a227; --low:#1c7ed6; --info:#5c7cfa; --ok:#2b8a3e;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 4px 12px rgba(16,24,40,.05);
}
@media (prefers-color-scheme:dark){
  :root{--bg:#14171a;--panel:#1c2024;--line:#2b3138;--text:#e7eaee;--muted:#9aa4ae;
        --crit:#ff6b6b;--high:#ff922b;--med:#ffd43b;--low:#4dabf7;--info:#91a7ff;--ok:#51cf66;
        --shadow:0 1px 2px rgba(0,0,0,.4)}
}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 72px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:0}
a{color:var(--low)}
.sub{color:var(--muted);font-size:13px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:20px 22px;margin-bottom:18px;box-shadow:var(--shadow)}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px}
.score{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;
  box-shadow:var(--shadow)}
.score .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.score .value{font-size:32px;font-weight:700;line-height:1.1;margin-top:6px}
.score .value span{font-size:14px;color:var(--muted);font-weight:400}
.bar{height:6px;border-radius:3px;background:var(--line);margin-top:10px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:3px}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 0}
.pill{font-size:12px;padding:3px 10px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}
.pill b{color:var(--text)}
table.facts{width:100%;border-collapse:collapse;margin:6px 0 18px;font-size:14px}
table.facts td{padding:7px 0;border-bottom:1px solid var(--line);vertical-align:top}
table.facts td:first-child{color:var(--muted);width:38%;padding-right:16px}
.finding{border-left:3px solid var(--line);padding:10px 0 10px 14px;margin:14px 0}
.finding .head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.tag{font-size:11px;font-weight:700;letter-spacing:.05em;padding:2px 8px;border-radius:5px;
  color:#fff;white-space:nowrap}
.finding .title{font-weight:600}
.finding .detail{color:var(--muted);margin-top:5px;font-size:14px}
.finding .rec{margin-top:8px;font-size:14px;padding:9px 12px;border-radius:8px;
  background:color-mix(in srgb,var(--low) 10%,transparent)}
.finding .rec b{font-weight:600}
.evidence{margin:8px 0 0;padding:0;list-style:none;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  font-size:12.5px;color:var(--muted)}
.evidence li{padding:2px 0;overflow-wrap:anywhere}
.sev-critical{border-left-color:var(--crit)} .tag-critical{background:var(--crit)}
.sev-high{border-left-color:var(--high)} .tag-high{background:var(--high)}
.sev-medium{border-left-color:var(--med)} .tag-medium{background:var(--med);color:#1c2024}
.sev-low{border-left-color:var(--low)} .tag-low{background:var(--low)}
.sev-info{border-left-color:var(--info)} .tag-info{background:var(--info)}
.sev-ok{border-left-color:var(--ok)} .tag-ok{background:var(--ok)}
.passed{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.passed span{font-size:12.5px;color:var(--ok);border:1px solid var(--line);border-radius:99px;padding:3px 10px}
ol.plan{padding-left:20px;margin:6px 0 0}
ol.plan li{margin-bottom:12px}
ol.plan .t{font-weight:600}
ol.plan .r{color:var(--muted);font-size:14px}
.delta{font-size:13px;font-weight:700;padding:2px 9px;border-radius:99px;margin-left:8px;
  vertical-align:middle}
.delta.up{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.delta.down{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
.delta.same{background:var(--line);color:var(--muted)}
.diffcols{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;margin-top:14px}
.diffcols h3{font-size:14px;margin:0 0 6px}
.diffcols h3.good{color:var(--ok)} .diffcols h3.bad{color:var(--crit)}
ul.difflist{margin:0;padding-left:18px;font-size:14px}
ul.difflist li{margin-bottom:5px}
ul.difflist.good li::marker{color:var(--ok)}
ul.difflist.bad li::marker{color:var(--crit)}
.shot{display:block;width:100%;max-width:100%;height:auto;margin-top:10px;
  border:1px solid var(--line);border-radius:8px}
.tech{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.tech span{font-size:13px;border:1px solid var(--line);border-radius:8px;padding:4px 10px}
.tech b{font-weight:600}
.err{color:var(--crit)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:36px}
"""


def _color_var(score: int) -> str:
    if score >= 85:
        return "var(--ok)"
    if score >= 70:
        return "var(--med)"
    if score >= 45:
        return "var(--high)"
    return "var(--crit)"


def render_html(reports: list[Report]) -> str:
    body = "\n".join(_report_html(r) for r in reports)
    generated = datetime.now().strftime("%d.%m.%Y %H:%M")
    return f"""<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Аудит сайта — siteaudit</title>
<style>{CSS}</style>
</head><body><div class="wrap">
{body}
<footer>Отчёт сформирован siteaudit · {generated}</footer>
</div></body></html>"""


def _report_html(report: Report) -> str:
    if report.error:
        return (
            f'<div class="card"><h1>{escape(report.target)}</h1>'
            f'<p class="err">Не удалось проверить сайт: {escape(report.error)}</p></div>'
        )

    parts = [
        f"<h1>Аудит: {escape(report.target)}</h1>",
        f'<div class="sub">Итоговый адрес: <a href="{escape(report.final_url)}">'
        f"{escape(report.final_url)}</a> · проверка заняла {report.duration:.1f} с · "
        f'{report.started_at.strftime("%d.%m.%Y %H:%M")}</div>',
        _scores_html(report),
        _diff_html(report),
        _plan_html(report),
        _screenshot_html(report),
        _tech_html(report),
    ]
    for module in report.modules:
        parts.append(_module_html(module))
    return "\n".join(parts)


def _scores_html(report: Report) -> str:
    cards = [
        f'<div class="score"><div class="label">Итог ({report.grade})</div>'
        f'<div class="value">{report.score}<span>/100</span></div>'
        f'<div class="bar"><i style="width:{report.score}%;background:{_color_var(report.score)}"></i></div></div>'
    ]
    for m in report.modules:
        value = "—" if m.error else f"{m.score}<span>/100</span>"
        cards.append(
            f'<div class="score"><div class="label">{escape(m.title)}</div>'
            f'<div class="value">{value}</div>'
            f'<div class="bar"><i style="width:{m.score}%;background:{_color_var(m.score)}"></i></div></div>'
        )
    return f'<div class="scores">{"".join(cards)}</div>'


def _plan_html(report: Report) -> str:
    top = [f for f in report.all_problems() if f.severity in (Severity.CRITICAL, Severity.HIGH)][:8]
    if not top:
        return (
            '<div class="card"><h2>План работ</h2>'
            '<p class="sub" style="margin:8px 0 0">Критичных и важных проблем не найдено — '
            "смотрите список мелких замечаний ниже.</p></div>"
        )
    items = "".join(
        f'<li><div class="t">{escape(f.title)}</div>'
        f'<div class="r">{escape(f.recommendation or f.detail)}</div></li>'
        for f in top
    )
    return f'<div class="card"><h2>Что делать в первую очередь</h2><ol class="plan">{items}</ol></div>'


def _diff_html(report: Report) -> str:
    diff = report.diff
    if not diff:
        return ""

    delta = diff.score_delta
    when = diff.previous_at.strftime("%d.%m.%Y %H:%M")
    if not diff.same_modules:
        badge = ""
        caption = (
            f"Прошлая проверка от {when} запускалась с другим набором модулей — "
            "баллы не сравниваем, сопоставлены только находки общих проверок."
        )
    else:
        if delta > 0:
            badge = f'<span class="delta up">▲ +{delta}</span>'
        elif delta < 0:
            badge = f'<span class="delta down">▼ {delta}</span>'
        else:
            badge = '<span class="delta same">без изменений</span>'
        caption = (
            f"было {diff.previous_score}/100 ({when}) → стало {diff.current_score}/100 · "
            f"без изменений остаётся находок: {diff.still_open}"
        )

    columns = []
    if diff.fixed:
        items = "".join(f"<li>{escape(i.title)}</li>" for i in diff.fixed[:10])
        columns.append(
            f'<div><h3 class="good">Исправлено — {len(diff.fixed)}</h3>'
            f'<ul class="difflist good">{items}</ul></div>'
        )
    if diff.appeared:
        items = "".join(f"<li>{escape(i.title)}</li>" for i in diff.appeared[:10])
        columns.append(
            f'<div><h3 class="bad">Появилось — {len(diff.appeared)}</h3>'
            f'<ul class="difflist bad">{items}</ul></div>'
        )
    if not columns:
        columns.append('<div class="sub">Состав находок не изменился.</div>')

    return (
        f'<div class="card"><h2>Изменения с прошлой проверки {badge}</h2>'
        f'<div class="sub" style="margin:6px 0 0">{escape(caption)}</div>'
        f'<div class="diffcols">{"".join(columns)}</div></div>'
    )


def _screenshot_html(report: Report) -> str:
    if not report.screenshot:
        return ""
    return (
        '<div class="card"><h2>Так страница выглядит в браузере</h2>'
        f'<img class="shot" src="{report.screenshot}" alt="Скриншот первого экрана" '
        'loading="lazy"></div>'
    )


def _tech_html(report: Report) -> str:
    if not report.techs:
        return ""
    chips = "".join(
        f'<span><b>{escape(t.name)}</b>'
        + (f" {escape(t.version)}" if t.version else "")
        + f' · {escape(t.category)}</span>'
        for t in report.techs
    )
    return f'<div class="card"><h2>Обнаруженные технологии</h2><div class="tech">{chips}</div></div>'


def _module_html(module) -> str:
    if module.error:
        return (
            f'<div class="card"><h2>{escape(module.title)}</h2>'
            f'<p class="err">Модуль не отработал: {escape(module.error)}</p></div>'
        )

    counts = module.counts()
    pills = "".join(
        f'<span class="pill">{label} <b>{counts[sev.value]}</b></span>'
        for sev, label in (
            (Severity.CRITICAL, "критично"),
            (Severity.HIGH, "важно"),
            (Severity.MEDIUM, "средне"),
            (Severity.LOW, "мелочи"),
            (Severity.OK, "пройдено"),
        )
        if counts[sev.value]
    )

    facts = ""
    if module.facts:
        rows = "".join(
            f"<tr><td>{escape(n)}</td><td>{escape(v)}</td></tr>" for n, v in module.facts
        )
        facts = f'<table class="facts">{rows}</table>'

    findings = "".join(_finding_html(f) for f in module.problems)
    notes = "".join(_finding_html(f) for f in module.notes)
    if not findings:
        findings = '<p style="color:var(--ok)">Проблем в этой категории не найдено.</p>'

    passed = ""
    if module.passed:
        chips = "".join(f"<span>✓ {escape(f.title)}</span>" for f in module.passed)
        passed = f'<div class="passed">{chips}</div>'

    return (
        f'<div class="card"><h2>{escape(module.title)} — {module.score}/100</h2>'
        f'<div class="pills">{pills}</div>{facts}{findings}{notes}{passed}</div>'
    )


def _finding_html(f) -> str:
    sev = f.severity.value
    evidence = ""
    if f.evidence:
        items = "".join(f"<li>{escape(e)}</li>" for e in f.evidence[:8])
        evidence = f'<ul class="evidence">{items}</ul>'
    detail = f'<div class="detail">{escape(f.detail)}</div>' if f.detail else ""
    rec = (
        f'<div class="rec"><b>Что делать:</b> {escape(f.recommendation)}</div>'
        if f.recommendation
        else ""
    )
    return (
        f'<div class="finding sev-{sev}"><div class="head">'
        f'<span class="tag tag-{sev}">{f.severity.label}</span>'
        f'<span class="title">{escape(f.title)}</span></div>'
        f"{detail}{evidence}{rec}</div>"
    )
