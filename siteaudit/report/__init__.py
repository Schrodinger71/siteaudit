"""Форматы вывода отчёта."""

from .console import render_console, render_history
from .html import render_html
from .json_report import render_json

__all__ = ["render_console", "render_history", "render_html", "render_json"]
