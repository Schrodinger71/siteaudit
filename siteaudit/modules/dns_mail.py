"""Аудит DNS-зоны и почтовой защиты домена: SPF, DKIM, DMARC, CAA, DNSSEC."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import string

from ..context import AuditContext
from ..models import ModuleResult, Severity
from ..utils import registrable, truncate
from .base import Module

try:  # dnspython — обязательная зависимость, но модуль не должен ронять весь аудит
    import dns.asyncresolver
    import dns.rdatatype
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    DNS_AVAILABLE = False

# Селекторы DKIM, которые чаще всего встречаются у популярных почтовых сервисов
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "sig1", "mandrill", "zoho", "yandex", "mailru", "sendgrid",
    "smtp", "key1", "everlytickey1", "protonmail",
]

# Механизмы SPF, каждый из которых стоит одного DNS-запроса (лимит — 10)
SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")


class DnsModule(Module):
    key = "dns"
    title = "DNS и почта"
    weight = 0.15

    async def analyze(self, ctx: AuditContext, result: ModuleResult) -> None:
        if not DNS_AVAILABLE:
            result.error = "не установлен dnspython — выполните: pip install dnspython"
            return

        try:
            ipaddress.ip_address(ctx.host)
        except ValueError:
            pass
        else:
            result.error = "сайт открыт по IP-адресу — проверять DNS-зону и почту нечего"
            return

        domain = registrable(ctx.host)
        result.fact("Проверяемый домен", domain)

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(10.0, ctx.options.timeout)
        resolver.timeout = min(5.0, ctx.options.timeout)

        a, aaaa, ns, mx, txt, caa, dnskey, dmarc, mta_sts, wildcard = await asyncio.gather(
            _query(resolver, domain, "A"),
            _query(resolver, domain, "AAAA"),
            _query(resolver, domain, "NS"),
            _query(resolver, domain, "MX"),
            _query(resolver, domain, "TXT"),
            _query(resolver, domain, "CAA"),
            _query(resolver, domain, "DNSKEY"),
            _query(resolver, f"_dmarc.{domain}", "TXT"),
            _query(resolver, f"_mta-sts.{domain}", "TXT"),
            _query(resolver, f"{_noise()}.{domain}", "A"),
        )

        self._addresses(result, a, aaaa)
        self._nameservers(result, ns)
        has_mail = self._mx(result, mx)
        self._spf(result, txt, has_mail)
        self._dmarc(result, dmarc, has_mail)
        await self._dkim(ctx, result, resolver, domain, has_mail)
        self._caa(result, caa)
        self._dnssec(result, dnskey)
        self._mta_sts(result, mta_sts, has_mail)
        self._wildcard(result, wildcard)

    # ------------------------------------------------------------- адреса

    def _addresses(self, result: ModuleResult, a, aaaa) -> None:
        result.fact("A-записи", ", ".join(a.values) if a.values else "нет")
        result.fact("AAAA (IPv6)", ", ".join(aaaa.values) if aaaa.values else "нет")

        if not a.values and not aaaa.values:
            result.add(
                "dns.a.missing",
                "У домена нет A/AAAA-записей",
                Severity.CRITICAL,
                a.error or "Домен не резолвится в IP-адрес.",
                "Проверьте DNS-зону: без A-записи домен недоступен напрямую.",
            )
        else:
            result.ok("dns.a", f"Домен резолвится ({len(a.values) + len(aaaa.values)} адресов)")

        if not aaaa.values:
            result.add(
                "dns.ipv6.missing",
                "Нет IPv6-адреса (AAAA)",
                Severity.LOW,
                "Часть мобильных операторов работает через IPv6-only сети с трансляцией.",
                "Добавьте AAAA-запись, если хостинг поддерживает IPv6. "
                "Не критично, но снижает задержки для части аудитории.",
            )

        if a.ttl is not None:
            result.fact("TTL A-записи", f"{a.ttl} с")
            if a.ttl < 120:
                result.add(
                    "dns.ttl.low",
                    f"Очень низкий TTL A-записи ({a.ttl} с)",
                    Severity.LOW,
                    "Резолверы будут переспрашивать адрес почти на каждый запрос.",
                    "Если переезд не планируется, поднимите TTL до 3600 с — "
                    "это снизит задержку резолва для пользователей.",
                )
            elif a.ttl > 86400:
                result.add(
                    "dns.ttl.high",
                    f"Очень высокий TTL A-записи ({a.ttl} с)",
                    Severity.LOW,
                    "Смена хостинга растянется на сутки и больше.",
                    "Перед плановым переездом заранее снизьте TTL до 300 с.",
                )

    def _nameservers(self, result: ModuleResult, ns) -> None:
        servers = [v.rstrip(".") for v in ns.values]
        result.fact("NS-серверы", ", ".join(servers) if servers else "нет")

        if len(servers) < 2:
            result.add(
                "dns.ns.single",
                f"Меньше двух NS-серверов ({len(servers)})",
                Severity.HIGH,
                "Единственный DNS-сервер — единая точка отказа: он упадёт, и сайт пропадёт целиком.",
                "Добавьте минимум второй NS-сервер (этого требует и RFC 1034). "
                "Большинство DNS-хостингов дают несколько серверов по умолчанию.",
            )
        else:
            zones = {".".join(s.split(".")[-2:]) for s in servers}
            if len(zones) == 1:
                result.add(
                    "dns.ns.same-provider",
                    "Все NS-серверы у одного провайдера",
                    Severity.LOW,
                    f"Зона: {', '.join(zones)}",
                    "Для критичных сайтов держите вторичный DNS у другого провайдера — "
                    "это защищает от аварии и DDoS у основного.",
                )
            else:
                result.ok("dns.ns", f"NS-серверы у разных провайдеров ({len(servers)} шт.)")

    def _mx(self, result: ModuleResult, mx) -> bool:
        hosts = [v.split()[-1].rstrip(".") for v in mx.values if v]
        result.fact("MX-записи", ", ".join(hosts) if hosts else "нет")
        if not hosts:
            result.add(
                "dns.mx.missing",
                "У домена нет MX-записей",
                Severity.INFO,
                "Почта на этом домене не принимается.",
                "Если почта не нужна — это нормально. Но SPF и DMARC всё равно стоит "
                "настроить с политикой отклонения, чтобы от вашего имени не рассылали спам.",
            )
            return False
        result.ok("dns.mx", f"Почта настроена ({len(hosts)} MX)")
        return True

    # --------------------------------------------------------------- SPF

    def _spf(self, result: ModuleResult, txt, has_mail: bool) -> None:
        records = [v for v in txt.values if v.lower().startswith("v=spf1")]
        result.fact("SPF", truncate(records[0], 80) if records else "не настроен")

        if not records:
            result.add(
                "dns.spf.missing",
                "Не настроен SPF",
                Severity.HIGH if has_mail else Severity.MEDIUM,
                "Без SPF любой может отправлять письма от имени вашего домена, "
                "и они с большой вероятностью дойдут до получателя.",
                "Добавьте TXT-запись вида `v=spf1 include:<ваш почтовый провайдер> ~all`. "
                "Если домен вообще не отправляет почту — поставьте `v=spf1 -all`.",
            )
            return

        if len(records) > 1:
            result.add(
                "dns.spf.multiple",
                f"Несколько SPF-записей ({len(records)})",
                Severity.HIGH,
                "; ".join(truncate(r, 60) for r in records[:3]),
                "По стандарту SPF-запись должна быть одна — при нескольких проверка "
                "возвращает permerror и защита не работает. Объедините их в одну.",
            )
            return

        spf = records[0]
        lookups = sum(spf.lower().count(m) for m in SPF_LOOKUP_MECHANISMS)
        if lookups > 10:
            result.add(
                "dns.spf.lookups",
                f"SPF превышает лимит DNS-запросов ({lookups} из 10)",
                Severity.HIGH,
                truncate(spf, 120),
                "При превышении лимита проверка даёт permerror и SPF перестаёт действовать. "
                "Сократите число include: уберите неиспользуемые сервисы или сверните "
                "их в плоский список адресов.",
            )

        if re.search(r"[\s]\+all\b", spf) or spf.strip().endswith("+all"):
            result.add(
                "dns.spf.allow-all",
                "SPF разрешает отправку кому угодно (+all)",
                Severity.CRITICAL,
                truncate(spf, 120),
                "Механизм `+all` полностью обесценивает SPF. Замените на `~all` "
                "(мягкий отказ) или `-all` (жёсткий).",
            )
        elif "?all" in spf:
            result.add(
                "dns.spf.neutral",
                "SPF заканчивается нейтральным ?all",
                Severity.MEDIUM,
                truncate(spf, 120),
                "Нейтральная политика не защищает от подделки. Переходите на `~all`, "
                "а после наблюдения — на `-all`.",
            )
        elif "-all" in spf:
            result.ok("dns.spf", "SPF настроен со строгой политикой (-all)")
        elif "~all" in spf:
            result.ok("dns.spf", "SPF настроен (~all)")
        else:
            result.add(
                "dns.spf.no-all",
                "В SPF не указан завершающий механизм all",
                Severity.MEDIUM,
                truncate(spf, 120),
                "Добавьте `~all` или `-all` в конец записи — иначе политика по умолчанию "
                "нейтральна и подделку никто не отсечёт.",
            )

    # -------------------------------------------------------------- DMARC

    def _dmarc(self, result: ModuleResult, dmarc, has_mail: bool) -> None:
        records = [v for v in dmarc.values if v.lower().startswith("v=dmarc1")]
        result.fact("DMARC", truncate(records[0], 80) if records else "не настроен")

        if not records:
            result.add(
                "dns.dmarc.missing",
                "Не настроен DMARC",
                Severity.HIGH,
                "DMARC связывает SPF и DKIM с политикой: что делать с письмами, "
                "не прошедшими проверку. Без него фишинг от имени домена проходит свободно.",
                "Добавьте TXT-запись `_dmarc.<домен>` со значением "
                "`v=DMARC1; p=none; rua=mailto:почта@домен`. Пособирайте отчёты пару недель, "
                "затем ужесточите до p=quarantine и p=reject.",
            )
            return

        record = records[0]
        policy = re.search(r"p\s*=\s*(none|quarantine|reject)", record, re.I)
        value = policy.group(1).lower() if policy else ""

        if value == "reject":
            result.ok("dns.dmarc", "DMARC с жёсткой политикой (p=reject)")
        elif value == "quarantine":
            result.ok("dns.dmarc", "DMARC настроен (p=quarantine)")
        elif value == "none":
            result.add(
                "dns.dmarc.none",
                "DMARC работает только в режиме наблюдения (p=none)",
                Severity.MEDIUM,
                truncate(record, 120),
                "Политика none ничего не блокирует — она нужна только на этапе сбора отчётов. "
                "Если отчёты уже собраны и легитимные отправители известны, переводите "
                "на p=quarantine, затем на p=reject.",
            )
        else:
            result.add(
                "dns.dmarc.invalid",
                "В DMARC не указана политика p=",
                Severity.HIGH,
                truncate(record, 120),
                "Запись без обязательного тега p= игнорируется. Добавьте `p=none` для начала.",
            )

        if "rua=" not in record.lower():
            result.add(
                "dns.dmarc.no-rua",
                "В DMARC не указан адрес для отчётов (rua)",
                Severity.LOW,
                "",
                "Добавьте `rua=mailto:dmarc@вашдомен` — без отчётов вы не узнаете, "
                "кто и как шлёт письма от вашего имени.",
            )

    async def _dkim(
        self, ctx: AuditContext, result: ModuleResult, resolver, domain: str, has_mail: bool
    ) -> None:
        answers = await asyncio.gather(
            *[_query(resolver, f"{sel}._domainkey.{domain}", "TXT") for sel in DKIM_SELECTORS]
        )
        found = [
            sel
            for sel, ans in zip(DKIM_SELECTORS, answers)
            if any("p=" in v or "v=dkim1" in v.lower() for v in ans.values)
        ]
        result.fact("DKIM-селекторы", ", ".join(found) if found else "не найдены")

        if found:
            result.ok("dns.dkim", f"DKIM настроен (селекторы: {', '.join(found)})")
        elif has_mail:
            result.add(
                "dns.dkim.missing",
                "DKIM не найден по частым селекторам",
                Severity.MEDIUM,
                f"Проверено {len(DKIM_SELECTORS)} распространённых селекторов — ни один не отвечает. "
                "Возможен нестандартный селектор, который перебором не найти.",
                "Убедитесь, что почтовый провайдер выдал DKIM-ключ и он добавлен в зону. "
                "Без DKIM письма чаще уходят в спам, а DMARC остаётся наполовину нерабочим.",
            )

    # ------------------------------------------------------- прочие записи

    def _caa(self, result: ModuleResult, caa) -> None:
        result.fact("CAA", ", ".join(truncate(v, 40) for v in caa.values) if caa.values else "нет")
        if not caa.values:
            result.add(
                "dns.caa.missing",
                "Нет CAA-записи",
                Severity.LOW,
                "CAA указывает, каким удостоверяющим центрам разрешено выпускать "
                "сертификаты для вашего домена.",
                "Добавьте, например, `0 issue \"letsencrypt.org\"` — это защищает "
                "от выпуска сертификата злоумышленником через другой УЦ.",
            )
        else:
            result.ok("dns.caa", "CAA-запись настроена")

    def _dnssec(self, result: ModuleResult, dnskey) -> None:
        enabled = bool(dnskey.values)
        result.fact("DNSSEC", "включён" if enabled else "выключен")
        if not enabled:
            result.add(
                "dns.dnssec.off",
                "DNSSEC не включён",
                Severity.LOW,
                "Без подписи зоны ответы DNS можно подменить (cache poisoning).",
                "Включите DNSSEC в панели DNS-хостинга и добавьте DS-запись у регистратора. "
                "Операция обратимая, но требует аккуратности: ошибка в DS полностью "
                "выключит домен.",
            )
        else:
            result.ok("dns.dnssec", "DNSSEC включён")

    def _mta_sts(self, result: ModuleResult, mta_sts, has_mail: bool) -> None:
        if not has_mail:
            return
        if any("v=stsv1" in v.lower() for v in mta_sts.values):
            result.ok("dns.mta-sts", "Настроен MTA-STS")
        else:
            result.add(
                "dns.mta-sts.missing",
                "Не настроен MTA-STS",
                Severity.LOW,
                "MTA-STS обязывает отправителей использовать TLS при доставке почты вам.",
                "Опционально: добавьте TXT `_mta-sts.<домен>` и файл политики "
                "на `mta-sts.<домен>`. Актуально, если через почту идут чувствительные данные.",
            )

    def _wildcard(self, result: ModuleResult, wildcard) -> None:
        if wildcard.values:
            result.add(
                "dns.wildcard",
                "Обнаружен wildcard в DNS (*.домен)",
                Severity.LOW,
                f"Случайный поддомен резолвится в {', '.join(wildcard.values[:2])}.",
                "Wildcard плодит бесконечные поддомены-дубли для поисковика и упрощает "
                "фишинг на поддоменах. Если он не нужен для логики сайта — уберите.",
            )


class _Answer:
    __slots__ = ("values", "ttl", "error")

    def __init__(self, values: list[str], ttl: int | None = None, error: str | None = None) -> None:
        self.values = values
        self.ttl = ttl
        self.error = error


async def _query(resolver, name: str, rdtype: str) -> _Answer:
    """Мягкий DNS-запрос: отсутствие записи — не ошибка, а пустой ответ."""
    try:
        answer = await resolver.resolve(name, rdtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
    ):
        return _Answer([])
    except Exception as exc:  # noqa: BLE001 — таймауты и прочие сетевые сбои
        return _Answer([], error=f"{type(exc).__name__}: {exc}")

    values: list[str] = []
    for item in answer:
        if rdtype == "TXT":
            values.append(b"".join(item.strings).decode("utf-8", errors="replace"))
        else:
            values.append(item.to_text())
    ttl = getattr(answer.rrset, "ttl", None) if answer.rrset is not None else None
    return _Answer(values, ttl=ttl)


def _noise() -> str:
    return "siteaudit-" + "".join(random.choices(string.ascii_lowercase, k=10))
