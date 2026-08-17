"""Аудит безопасности: HTTPS/TLS, заголовки, cookies, утечки, открытые файлы."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

from ..context import AuditContext
from ..models import ModuleResult, Severity
from ..utils import truncate
from .base import Module

# Заголовок → (важность, что это даёт, как чинить)
SECURITY_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "strict-transport-security": (
        Severity.HIGH,
        "HSTS заставляет браузер ходить только по HTTPS и защищает от даунгрейд-атак.",
        "Добавьте `Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
        "Начните с небольшого max-age, убедившись, что весь сайт работает по HTTPS.",
    ),
    "content-security-policy": (
        Severity.HIGH,
        "CSP — основная защита от XSS: браузер выполняет только разрешённые источники кода.",
        "Начните в режиме наблюдения: `Content-Security-Policy-Report-Only` со сбором отчётов, "
        "затем переведите в боевой режим. Минимум: default-src 'self'.",
    ),
    "x-content-type-options": (
        Severity.MEDIUM,
        "Запрещает браузеру угадывать MIME-тип (MIME sniffing).",
        "Добавьте `X-Content-Type-Options: nosniff`. Одна строка, нулевой риск.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Защищает от кликджекинга — встраивания сайта в чужой iframe.",
        "Добавьте `X-Frame-Options: SAMEORIGIN` или директиву frame-ancestors в CSP.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Ограничивает, сколько информации об источнике уходит на внешние сайты.",
        "Добавьте `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Отключает ненужные API браузера (камера, микрофон, геолокация) для страницы и её фреймов.",
        "Добавьте `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
    ),
}

# Пути, которые не должны быть доступны снаружи
SENSITIVE_PATHS: list[tuple[str, str, Severity, str]] = [
    ("/.git/HEAD", r"ref:\s*refs/", Severity.CRITICAL, "Открыт Git-репозиторий — можно выкачать весь исходный код вместе с историей и паролями в конфигах."),
    ("/.env", r"(?im)^\s*[A-Z_]{3,}\s*=", Severity.CRITICAL, "Открыт файл переменных окружения — обычно содержит пароли БД, ключи API и секрет приложения."),
    ("/.svn/entries", r"^\d+|dir", Severity.CRITICAL, "Открыты служебные файлы SVN — доступен исходный код."),
    ("/wp-config.php.bak", r"DB_PASSWORD|DB_NAME", Severity.CRITICAL, "Резервная копия конфигурации WordPress доступна публично."),
    ("/config.php.bak", r"password|mysql|db", Severity.CRITICAL, "Резервная копия конфигурации доступна публично."),
    ("/.htaccess", r"RewriteEngine|Options", Severity.HIGH, "Файл конфигурации Apache читается снаружи — раскрывает внутреннюю структуру."),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", Severity.HIGH, "phpinfo раскрывает полную конфигурацию сервера — подарок для атакующего."),
    ("/server-status", r"Apache Server Status", Severity.HIGH, "Открыта страница статуса Apache со списком запросов и клиентов."),
    ("/.DS_Store", r"Bud1|\x00\x00\x00\x01Bud1", Severity.MEDIUM, "Файл macOS раскрывает список файлов и папок каталога."),
    ("/backup.sql", r"INSERT INTO|CREATE TABLE", Severity.CRITICAL, "Публично доступен дамп базы данных."),
    ("/dump.sql", r"INSERT INTO|CREATE TABLE", Severity.CRITICAL, "Публично доступен дамп базы данных."),
    ("/composer.json", r'"require"', Severity.LOW, "Виден список зависимостей и их версий — упрощает подбор эксплойта."),
    ("/package.json", r'"dependencies"', Severity.LOW, "Виден список зависимостей и их версий."),
    ("/adminer.php", r"Adminer|Login", Severity.HIGH, "Публично доступен веб-клиент к базе данных."),
    ("/.well-known/security.txt", r"Contact:", Severity.OK, "Файл security.txt — канал для сообщений об уязвимостях."),
]


class SecurityModule(Module):
    key = "security"
    title = "Безопасность"
    weight = 0.30

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not ctx.page.ok:
            result.error = ctx.page.error or f"HTTP {ctx.page.status}"
            return

        self._https(ctx, result)
        await self._tls(ctx, result)
        self._headers(ctx, result)
        self._cookies(ctx, result)
        self._leaks(ctx, result)
        self._mixed_content(ctx, result)
        self._forms(ctx, result)
        self._cors(ctx, result)
        if not ctx.options.safe:
            await self._exposed_paths(ctx, result)
        else:
            result.add(
                "sec.paths.skipped",
                "Проверка открытых служебных файлов пропущена (--safe)",
                Severity.INFO,
                "Запуск без активных проб: .git, .env, дампы БД и подобное не проверялись.",
            )

    # --------------------------------------------------------------- HTTPS

    def _https(self, ctx: AuditContext, result: ModuleResult) -> None:
        result.fact("Схема", "HTTPS" if ctx.is_https else "HTTP")
        if not ctx.is_https:
            result.add(
                "sec.https.missing",
                "Сайт работает по незащищённому HTTP",
                Severity.CRITICAL,
                "Весь трафик, включая пароли и формы, передаётся открытым текстом. "
                "Браузеры помечают такие сайты как «Не защищено», поисковики понижают их.",
                "Выпустите бесплатный сертификат Let's Encrypt, включите HTTPS и настройте "
                "301-редирект всего HTTP-трафика на HTTPS.",
            )
            return

        result.ok("sec.https", "Сайт работает по HTTPS")

        probe = ctx.http_probe
        if probe and not probe.error:
            if probe.status in (301, 308):
                location = probe.headers.get("location", "")
                if location.startswith("https://"):
                    result.ok("sec.https.redirect", "HTTP корректно перенаправляется на HTTPS (301)")
                else:
                    result.add(
                        "sec.https.redirect-target",
                        "HTTP редиректит не на HTTPS",
                        Severity.HIGH,
                        f"Location: {truncate(location, 70)}",
                        "Настройте редирект строго на https-версию того же URL.",
                    )
            elif probe.status in (302, 303, 307):
                result.add(
                    "sec.https.temp-redirect",
                    f"HTTP → HTTPS через временный редирект ({probe.status})",
                    Severity.LOW,
                    "",
                    "Замените на постоянный 301 — временный редирект не склеивает "
                    "версии сайта для поисковиков.",
                )
            elif probe.status == 200:
                result.add(
                    "sec.https.http-works",
                    "Сайт открывается и по HTTP без редиректа",
                    Severity.HIGH,
                    "Существуют две доступные версии сайта: http и https.",
                    "Настройте безусловный 301-редирект с http на https — иначе это и дыра "
                    "в безопасности, и дубли страниц для поисковика.",
                )

    async def _tls(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not ctx.is_https:
            return
        info = await asyncio.get_running_loop().run_in_executor(None, _tls_info, ctx.host)

        if info.get("error"):
            err = str(info["error"])
            result.fact("TLS-сертификат", f"ошибка проверки: {truncate(err, 60)}")
            severity = Severity.CRITICAL
            hint = "Проверьте цепочку сертификатов и срок действия (например, на ssllabs.com)."
            if "expired" in err.lower():
                hint = "Сертификат истёк — перевыпустите его и настройте автопродление (certbot renew)."
            elif "hostname" in err.lower() or "match" in err.lower():
                hint = "Сертификат выписан на другое имя — перевыпустите с нужным доменом и всеми поддоменами."
            elif "self signed" in err.lower():
                hint = "Самоподписанный сертификат браузеры не примут. Выпустите бесплатный Let's Encrypt."
            result.add(
                "sec.tls.invalid",
                "Проблема с TLS-сертификатом",
                severity,
                err,
                hint,
            )
            return

        days = info.get("days_left")
        result.fact("Издатель сертификата", info.get("issuer", "—"))
        result.fact("Сертификат действует ещё", f"{days} дн." if days is not None else "—")
        result.fact("Версия TLS", info.get("protocol", "—"))
        result.fact("Шифр", info.get("cipher", "—"))

        if days is not None:
            if days < 0:
                result.add(
                    "sec.tls.expired",
                    "Сертификат просрочен",
                    Severity.CRITICAL,
                    f"Истёк {abs(days)} дн. назад.",
                    "Перевыпустите сертификат немедленно и включите автопродление.",
                )
            elif days < 14:
                result.add(
                    "sec.tls.expiring",
                    f"Сертификат истекает через {days} дн.",
                    Severity.HIGH,
                    "",
                    "Продлите сертификат и настройте автоматическое обновление "
                    "(certbot/acme.sh по расписанию), чтобы это не повторялось.",
                )
            elif days < 30:
                result.add(
                    "sec.tls.soon",
                    f"Сертификат истекает через {days} дн.",
                    Severity.LOW,
                    "",
                    "Проверьте, что автопродление действительно работает.",
                )
            else:
                result.ok("sec.tls", f"Сертификат валиден ещё {days} дн.")

        proto = info.get("protocol") or ""
        if proto in ("TLSv1", "TLSv1.1"):
            result.add(
                "sec.tls.old-protocol",
                f"Соединение установлено по устаревшему {proto}",
                Severity.HIGH,
                "",
                "Отключите TLS 1.0/1.1 на сервере, оставьте только TLS 1.2 и 1.3.",
            )

        if info.get("legacy_supported"):
            result.add(
                "sec.tls.legacy-enabled",
                "Сервер принимает устаревшие TLS 1.0/1.1",
                Severity.MEDIUM,
                f"Согласован протокол: {info['legacy_supported']}",
                "В nginx оставьте `ssl_protocols TLSv1.2 TLSv1.3;`. Старые версии "
                "не соответствуют PCI DSS и уязвимы к ряду атак.",
            )
        elif info.get("legacy_checked"):
            result.ok("sec.tls.modern", "Устаревшие версии TLS отключены")

    # ------------------------------------------------------------ заголовки

    def _headers(self, ctx: AuditContext, result: ModuleResult) -> None:
        headers = ctx.page.headers
        present, missing = [], []
        for name, (severity, why, how) in SECURITY_HEADERS.items():
            if name in headers:
                present.append(name)
            else:
                missing.append(name)
                result.add(
                    f"sec.header.{name}",
                    f"Нет заголовка {_pretty(name)}",
                    severity,
                    why,
                    how,
                )
        result.fact(
            "Security-заголовки",
            f"{len(present)} из {len(SECURITY_HEADERS)}: {', '.join(_pretty(h) for h in present) or 'нет'}",
        )
        if not missing:
            result.ok("sec.headers", "Все базовые security-заголовки на месте")

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15_552_000:
                result.add(
                    "sec.hsts.short",
                    f"Слишком короткий max-age у HSTS ({m.group(1)} с)",
                    Severity.LOW,
                    hsts,
                    "Доведите max-age минимум до 15552000 (полгода), "
                    "затем добавьте includeSubDomains.",
                )

        csp = headers.get("content-security-policy", "")
        if csp and re.search(r"'unsafe-inline'|'unsafe-eval'|\*\s*;|default-src\s+\*", csp):
            result.add(
                "sec.csp.weak",
                "CSP задан, но ослаблен",
                Severity.MEDIUM,
                truncate(csp, 160),
                "Директивы 'unsafe-inline'/'unsafe-eval' и wildcard-источники сводят защиту "
                "от XSS почти к нулю. Переходите на nonce или hash для инлайн-скриптов.",
            )

    def _cookies(self, ctx: AuditContext, result: ModuleResult) -> None:
        raw = [v for k, v in ctx.page.raw_headers if k.lower() == "set-cookie"]
        if not raw:
            result.fact("Cookies", "не выставляются на главной")
            return
        result.fact("Cookies", f"{len(raw)} шт.")

        no_secure, no_httponly, no_samesite = [], [], []
        for cookie in raw:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            if ctx.is_https and "secure" not in low:
                no_secure.append(name)
            if "httponly" not in low:
                no_httponly.append(name)
            if "samesite" not in low:
                no_samesite.append(name)

        if no_secure:
            result.add(
                "sec.cookie.secure",
                f"Cookies без флага Secure ({len(no_secure)})",
                Severity.MEDIUM,
                ", ".join(no_secure[:6]),
                "Добавьте флаг Secure — иначе cookie уйдёт и по незашифрованному соединению.",
            )
        if no_httponly:
            result.add(
                "sec.cookie.httponly",
                f"Cookies без флага HttpOnly ({len(no_httponly)})",
                Severity.MEDIUM,
                ", ".join(no_httponly[:6]),
                "Сессионным cookie обязателен HttpOnly — иначе их можно украсть через XSS. "
                "Для cookie, нужных фронтенду (например, счётчикам), это допустимо.",
            )
        if no_samesite:
            result.add(
                "sec.cookie.samesite",
                f"Cookies без атрибута SameSite ({len(no_samesite)})",
                Severity.LOW,
                ", ".join(no_samesite[:6]),
                "Задайте SameSite=Lax (или Strict для админки) — это базовая защита от CSRF.",
            )
        if not (no_secure or no_httponly or no_samesite):
            result.ok("sec.cookies", "У всех cookies выставлены флаги безопасности")

    def _leaks(self, ctx: AuditContext, result: ModuleResult) -> None:
        headers = ctx.page.headers
        leaks = []
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache"):
            value = headers.get(name)
            if value and re.search(r"\d+\.\d+", value):
                leaks.append(f"{_pretty(name)}: {value}")

        if leaks:
            result.add(
                "sec.leak.version",
                "Сервер раскрывает версии ПО в заголовках",
                Severity.MEDIUM,
                "; ".join(leaks),
                "Скройте версии: в nginx `server_tokens off;`, в PHP `expose_php = Off`, "
                "в ASP.NET уберите заголовки в web.config. Это не защита сама по себе, "
                "но снимает сайт с прицела массовых сканеров.",
                evidence=leaks,
            )
        else:
            result.ok("sec.leak.version", "Версии ПО в заголовках не раскрываются")

        comments = re.findall(r"<!--(.*?)-->", ctx.html, re.S)
        suspicious = [
            truncate(c, 90)
            for c in comments
            if re.search(r"\b(todo|fixme|password|passwd|api[_-]?key|secret|token|debug)\b", c, re.I)
        ]
        if suspicious:
            result.add(
                "sec.leak.comments",
                f"Подозрительные HTML-комментарии ({len(suspicious)})",
                Severity.LOW,
                "В комментариях встречаются слова вроде password, api_key, TODO, debug.",
                "Вырезайте комментарии разработчика при сборке продакшн-версии.",
                evidence=suspicious[:5],
            )

        inline_keys = re.findall(
            r"(?i)(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
            ctx.html,
        )
        if inline_keys:
            result.add(
                "sec.leak.keys",
                f"В HTML найдены строки, похожие на ключи API ({len(inline_keys)})",
                Severity.HIGH,
                "Значения длиной 20+ символов рядом со словами api_key/secret/token.",
                "Проверьте вручную: если это приватный ключ — немедленно отзовите и перевыпустите его, "
                "а обращения к API перенесите на серверную сторону.",
                evidence=[f"{k[:6]}…{k[-4:]}" for k in inline_keys[:5]],
            )

        if re.search(r"(Warning|Fatal error|Notice):\s+.*\son line \d+", ctx.html) or re.search(
            r"Traceback \(most recent call last\)", ctx.html
        ):
            result.add(
                "sec.leak.errors",
                "На странице видны серверные ошибки/трейсбек",
                Severity.HIGH,
                "Вывод ошибок раскрывает пути на диске и структуру кода.",
                "Отключите display_errors в продакшене и логируйте ошибки в файл.",
            )

    def _mixed_content(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not ctx.is_https:
            return
        insecure: list[str] = []
        for attr in ("src", "href", "action"):
            for tag in ctx.soup.find_all(attrs={attr: re.compile(r"^http://", re.I)}):
                if tag.name == "a" and attr == "href":
                    continue  # обычные ссылки не создают mixed content
                insecure.append(f"<{tag.name} {attr}={truncate(tag.get(attr, ''), 60)}>")

        if insecure:
            result.add(
                "sec.mixed-content",
                f"Смешанный контент: {len(insecure)} ресурсов по HTTP",
                Severity.HIGH,
                "Браузер заблокирует такие ресурсы или пометит страницу как небезопасную.",
                "Переведите все ссылки на ресурсы на https:// (или протокол-независимые пути). "
                "Проверьте базу данных — часто http-адреса зашиты в контенте.",
                evidence=insecure[:6],
            )
        else:
            result.ok("sec.mixed-content", "Смешанного контента нет")

    def _forms(self, ctx: AuditContext, result: ModuleResult) -> None:
        forms = ctx.soup.find_all("form")
        if not forms:
            return
        result.fact("Форм на странице", len(forms))

        insecure_action = [
            f for f in forms if (f.get("action") or "").lower().startswith("http://")
        ]
        if insecure_action:
            result.add(
                "sec.form.http",
                f"Формы отправляют данные по HTTP ({len(insecure_action)})",
                Severity.CRITICAL,
                "Введённые пользователем данные уйдут незашифрованными.",
                "Смените action на https:// немедленно.",
            )

        password_forms = [f for f in forms if f.find("input", attrs={"type": "password"})]
        for form in password_forms:
            has_token = bool(
                form.find("input", attrs={"name": re.compile(r"csrf|token|_token|authenticity", re.I)})
            )
            if not has_token:
                result.add(
                    "sec.form.csrf",
                    "Форма с паролем без видимого CSRF-токена",
                    Severity.MEDIUM,
                    "В форме не найдено скрытого поля с токеном.",
                    "Добавьте CSRF-токен (большинство фреймворков делают это из коробки). "
                    "Если защита реализована через SameSite-cookie — проверьте, что она включена.",
                )
                break

        if password_forms and not ctx.is_https:
            result.add(
                "sec.form.password-http",
                "Форма ввода пароля на HTTP-странице",
                Severity.CRITICAL,
                "",
                "Переведите сайт на HTTPS до того, как принимать любые учётные данные.",
            )

    def _cors(self, ctx: AuditContext, result: ModuleResult) -> None:
        acao = ctx.page.header("access-control-allow-origin")
        acac = ctx.page.header("access-control-allow-credentials").lower()
        if acao == "*" and acac == "true":
            result.add(
                "sec.cors.wildcard-creds",
                "CORS: разрешены любые источники вместе с передачей учётных данных",
                Severity.HIGH,
                f"Access-Control-Allow-Origin: * и Allow-Credentials: true",
                "Такая комбинация позволяет чужому сайту читать ответы от имени пользователя. "
                "Замените * на явный список доверенных доменов.",
            )
        elif acao == "*":
            result.add(
                "sec.cors.wildcard",
                "CORS открыт для всех источников (*)",
                Severity.LOW,
                "Для публичного контента это нормально, для приватных данных — нет.",
                "Если по этому адресу отдаются данные пользователей, ограничьте список источников.",
            )

    # -------------------------------------------------------- активные пробы

    async def _exposed_paths(self, ctx: AuditContext, result: ModuleResult) -> None:
        base = ctx.origin
        baseline = ctx.soft404
        paths = [p for p in SENSITIVE_PATHS]
        responses = await asyncio.gather(
            *[ctx.fetcher.get(base + path) for path, _, _, _ in paths]
        )

        found_security_txt = False
        for (path, pattern, severity, why), resp in zip(paths, responses):
            if resp.error or resp.status != 200:
                continue
            body = resp.text[:4000]
            if pattern and not re.search(pattern, body, re.I):
                continue
            # отсекаем soft-404: тот же контент, что и на случайном адресе
            if baseline and baseline.status == 200 and resp.text[:2000] == baseline.text[:2000]:
                continue

            if severity is Severity.OK:
                found_security_txt = True
                result.ok("sec.security-txt", "Есть /.well-known/security.txt")
                continue

            result.add(
                f"sec.exposed{path.replace('/', '.')}",
                f"Публично доступен {path}",
                severity,
                why,
                _fix_for(path),
                evidence=[f"{base}{path} → HTTP 200, {len(resp.content)} байт"],
            )

        if not found_security_txt:
            result.add(
                "sec.security-txt.missing",
                "Нет файла /.well-known/security.txt",
                Severity.LOW,
                "Исследователям некуда сообщить о найденной уязвимости.",
                "Создайте /.well-known/security.txt с полями Contact и Expires (RFC 9116).",
            )

        # Листинг каталогов
        listing = await ctx.fetcher.get(f"{base}/uploads/")
        if listing.status == 200 and re.search(r"Index of /|<title>Directory listing", listing.text[:2000], re.I):
            result.add(
                "sec.dir-listing",
                "Включён листинг каталогов",
                Severity.MEDIUM,
                f"{base}/uploads/ показывает список файлов.",
                "Отключите автоиндекс: `autoindex off;` в nginx или `Options -Indexes` в Apache.",
            )


def _fix_for(path: str) -> str:
    if path.startswith("/.git") or path.startswith("/.svn"):
        return (
            "Закройте служебные каталоги VCS на уровне веб-сервера и, что важнее, "
            "не выкладывайте .git на продакшн — деплойте сборкой, а не `git pull`. "
            "Считайте все секреты, лежавшие в репозитории, скомпрометированными: смените их."
        )
    if path.endswith((".env", ".bak")) or "config" in path:
        return (
            "Немедленно удалите файл с сервера и смените все пароли и ключи, которые в нём были. "
            "Запретите отдачу таких файлов на уровне веб-сервера."
        )
    if path.endswith(".sql"):
        return (
            "Удалите дамп с публичного каталога и считайте базу утёкшей: смените пароли, "
            "уведомьте пользователей, если утекли персональные данные. Бэкапы храните вне webroot."
        )
    if path in ("/phpinfo.php", "/server-status", "/adminer.php"):
        return "Удалите файл или закройте доступ по IP/авторизации. Это стандартная цель массовых сканеров."
    return "Закройте доступ к файлу на уровне веб-сервера или удалите его с продакшна."


def _pretty(header: str) -> str:
    return "-".join(part.capitalize() for part in header.split("-"))


def _tls_info(host: str, port: int = 443) -> dict:
    """Синхронно снимает информацию о сертификате и согласованном протоколе."""
    out: dict = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                out["protocol"] = tls.version()
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else None
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        out["issuer"] = issuer.get("organizationName") or issuer.get("commonName") or "—"
        not_after = cert.get("notAfter")
        if not_after:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            out["days_left"] = (expires - datetime.now(timezone.utc)).days
    except Exception as exc:  # noqa: BLE001 — любая ошибка TLS информативна
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    # Отдельно проверяем, принимает ли сервер устаревшие протоколы
    out["legacy_checked"] = True
    try:
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        legacy.minimum_version = ssl.TLSVersion.TLSv1
        legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host, port), timeout=8) as sock:
            with legacy.wrap_socket(sock, server_hostname=host) as tls:
                out["legacy_supported"] = tls.version()
    except Exception:  # noqa: BLE001 — отказ = хорошо, старые протоколы выключены
        out["legacy_supported"] = None
    return out
