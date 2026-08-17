"""Ручной запуск тестового стенда: python tests/serve.py [fixture|fixture-clean] [порт].

Нужен потому, что в файлах стенда лежит плейсхолдер {{BASE}}, и просто отдать
каталог через `python -m http.server` нельзя — канонические адреса и sitemap
окажутся нерабочими.
"""

from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from conftest import _materialize, _serve  # noqa: E402


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "fixture"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8931
    source = Path(__file__).parent / name
    if not source.is_dir():
        print(f"Нет такого стенда: {source}")
        return 2

    base = f"http://127.0.0.1:{port}"
    target = Path(tempfile.mkdtemp(prefix="siteaudit-stand-")) / name
    _materialize(source, target, base)
    server = _serve(target, port)

    print(f"Стенд «{name}» поднят: {base}")
    print("Остановить — Ctrl+C")
    try:
        # _serve уже крутит serve_forever в фоновом потоке, здесь только ждём
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nОстановлен.")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
