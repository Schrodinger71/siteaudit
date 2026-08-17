"""Общие фикстуры: локальные HTTP-стенды для тестов аудита.

Стенды хранят в разметке плейсхолдер {{BASE}} вместо адреса, потому что порт
выбирается свободный. Перед запуском сервера копия стенда кладётся во временный
каталог, и плейсхолдер заменяется на реальный базовый URL.
"""

from __future__ import annotations

import shutil
import socket
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent
PLACEHOLDER = "{{BASE}}"
TEXT_SUFFIXES = {".html", ".xml", ".txt", ".css", ".js", ".json"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _materialize(source: Path, target: Path, base: str) -> None:
    """Копирует стенд и подставляет базовый URL вместо плейсхолдера."""
    shutil.copytree(source, target, dirs_exist_ok=True)
    for path in target.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if PLACEHOLDER in text:
                path.write_text(text.replace(PLACEHOLDER, base), encoding="utf-8")


class _QuietHandler(SimpleHTTPRequestHandler):
    """Тот же статический сервер, но без логов в stderr на каждый запрос."""

    def log_message(self, fmt, *args):  # noqa: A003 — сигнатура задана базовым классом
        pass


def _serve(directory: Path, port: int) -> ThreadingHTTPServer:
    handler = partial(_QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _stand(name: str, tmp_root: Path):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    directory = tmp_root / name
    _materialize(FIXTURES / name, directory, base)
    server = _serve(directory, port)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def dirty_site(tmp_path_factory) -> str:
    """Стенд с намеренными ошибками: битые ссылки, дубли, открытые файлы."""
    yield from _stand("fixture", tmp_path_factory.mktemp("dirty"))


@pytest.fixture(scope="session")
def clean_site(tmp_path_factory) -> str:
    """Эталонный стенд: всё сделано правильно, находок быть не должно."""
    yield from _stand("fixture-clean", tmp_path_factory.mktemp("clean"))
