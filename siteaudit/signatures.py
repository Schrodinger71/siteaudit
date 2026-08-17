"""Сигнатуры для определения движка сайта, фреймворков, сервера и сервисов.

Формат одной сигнатуры:
    name      — отображаемое имя
    category  — CMS / Фреймворк / Сервер / CDN / Аналитика / Библиотека / Язык / Хостинг
    html      — regex по исходному HTML
    meta      — regex по содержимому <meta name="generator">
    headers   — {имя заголовка: regex по значению} ("" = достаточно наличия)
    cookies   — regex по именам cookie из Set-Cookie
    scripts   — regex по src подключаемых скриптов
    version   — список regex с одной группой (версия)
    implies   — какие технологии подразумеваются найденной
"""

from __future__ import annotations

from typing import Any

SIGNATURES: list[dict[str, Any]] = [
    # ---------------------------------------------------------------- CMS
    {
        "name": "WordPress",
        "category": "CMS",
        "meta": r"WordPress",
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "cookies": [r"^wordpress_", r"^wp-settings"],
        "version": [r'name="generator"\s+content="WordPress\s+([\d.]+)', r"/wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)"],
    },
    {
        "name": "WooCommerce",
        "category": "E-commerce",
        "html": [r"/plugins/woocommerce/", r"woocommerce-page", r"wc-add-to-cart"],
        "version": [r"woocommerce[^\"']*\.js\?ver=([\d.]+)"],
        "implies": ["WordPress"],
    },
    {
        "name": "Elementor",
        "category": "CMS-плагин",
        "html": [r"/plugins/elementor/", r"elementor-page"],
        "version": [r"elementor[^\"']*\.js\?ver=([\d.]+)"],
        "implies": ["WordPress"],
    },
    {
        "name": "1C-Bitrix",
        "category": "CMS",
        "html": [r"/bitrix/js/", r"/bitrix/templates/", r"BX\.message", r"bitrix_sessid"],
        "headers": {"x-powered-cms": r"Bitrix"},
        "cookies": [r"^BITRIX_SM_"],
        "version": [r"/bitrix/js/main/core/core\.js\?[^\"']*v?([\d.]+)"],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "meta": r"Joomla",
        "html": [r"/media/jui/", r"/components/com_", r"joomla-script-options"],
        "cookies": [r"^joomla_"],
        "version": [r'name="generator"\s+content="Joomla!\s*-?\s*.*?([\d.]+)'],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "meta": r"Drupal",
        "html": [r"/sites/default/files/", r"drupal-settings-json", r"Drupal\.settings"],
        "headers": {"x-generator": r"Drupal"},
        "version": [r"Drupal\s+([\d.]+)"],
    },
    {
        "name": "MODX",
        "category": "CMS",
        "meta": r"MODX",
        "html": [r"/assets/components/", r"MODX\.config"],
        "headers": {"x-powered-by": r"MODX"},
    },
    {
        "name": "OpenCart",
        "category": "CMS",
        "html": [r"index\.php\?route=common/home", r"catalog/view/theme/"],
        "cookies": [r"^OCSESSID"],
    },
    {
        "name": "Magento",
        "category": "E-commerce",
        "html": [r"/static/version\d+/frontend/", r"Magento_", r"mage/cookies"],
        "cookies": [r"^X-Magento", r"^mage-"],
    },
    {
        "name": "Shopify",
        "category": "E-commerce",
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopid": "", "x-shopify-stage": ""},
    },
    {
        "name": "Tilda",
        "category": "Конструктор",
        "html": [r"tildacdn\.com", r"t-body", r"tilda\.ws"],
        "meta": r"Tilda",
    },
    {
        "name": "Wix",
        "category": "Конструктор",
        "html": [r"static\.parastorage\.com", r"wix-?code", r"X-Wix"],
        "headers": {"x-wix-request-id": ""},
    },
    {
        "name": "Squarespace",
        "category": "Конструктор",
        "html": [r"static1\.squarespace\.com", r"Squarespace\.afterBodyLoad"],
        "headers": {"x-servedby": r"squarespace"},
    },
    {
        "name": "Ghost",
        "category": "CMS",
        "meta": r"Ghost",
        "html": [r"/assets/built/", r"ghost-sdk"],
    },
    {
        "name": "DataLife Engine",
        "category": "CMS",
        "html": [r"/engine/classes/", r"dle_root", r"engine/ajax/"],
        "meta": r"DataLife Engine",
    },
    {
        "name": "UMI.CMS",
        "category": "CMS",
        "html": [r"/templates/[^\"']+/js/umi", r"umi\.js"],
        "headers": {"x-powered-by": r"UMI"},
    },
    {
        "name": "InSales",
        "category": "E-commerce",
        "html": [r"static\.insales\.ru", r"assets\.insales"],
    },
    {
        "name": "HostCMS",
        "category": "CMS",
        "meta": r"HostCMS",
        "html": [r"/hostcmsfiles/"],
    },
    {
        "name": "Craft CMS",
        "category": "CMS",
        "headers": {"x-powered-by": r"Craft CMS"},
        "cookies": [r"^CraftSessionId"],
    },
    {
        "name": "Strapi",
        "category": "Headless CMS",
        "headers": {"x-powered-by": r"Strapi"},
    },
    # ------------------------------------------------------- Фреймворки JS
    {
        "name": "Next.js",
        "category": "Фреймворк",
        "html": [r"/_next/static/", r"__NEXT_DATA__"],
        "headers": {"x-powered-by": r"Next\.js"},
        "version": [r"x-powered-by:\s*Next\.js\s*([\d.]+)"],
        "implies": ["React"],
    },
    {
        "name": "Nuxt",
        "category": "Фреймворк",
        "html": [r"/_nuxt/", r"__NUXT__", r"window\.__NUXT_"],
        "implies": ["Vue.js"],
    },
    {
        "name": "React",
        "category": "Фреймворк",
        "html": [r"data-reactroot", r"react-dom", r"__REACT_DEVTOOLS", r"_reactListening"],
        "scripts": [r"react(-dom)?[.\-@][\d.]*\.?(production|development|min)?\.js"],
    },
    {
        "name": "Vue.js",
        "category": "Фреймворк",
        "html": [r"data-v-[0-9a-f]{8}", r"__vue__", r"v-cloak", r"id=\"app\"[^>]*data-server-rendered"],
        "scripts": [r"vue(@|\.|-)[\d.]*(runtime|min)?\.js"],
    },
    {
        "name": "Angular",
        "category": "Фреймворк",
        "html": [r"ng-version=", r"_nghost-", r"ng-app"],
        "scripts": [r"(main|polyfills|runtime)\.[0-9a-f]+\.js"],
        "version": [r'ng-version="([\d.]+)"'],
    },
    {
        "name": "Svelte / SvelteKit",
        "category": "Фреймворк",
        "html": [r"svelte-[0-9a-z]{6}", r"__sveltekit_"],
    },
    {
        "name": "Astro",
        "category": "Фреймворк",
        "html": [r"astro-island", r"data-astro-"],
        "meta": r"Astro",
    },
    {
        "name": "Gatsby",
        "category": "Фреймворк",
        "html": [r"___gatsby", r"/page-data/"],
    },
    # -------------------------------------------------- Бэкенд и языки
    {
        "name": "PHP",
        "category": "Язык",
        "headers": {"x-powered-by": r"PHP"},
        "cookies": [r"^PHPSESSID"],
        "version": [r"PHP/([\d.]+)"],
    },
    {
        "name": "Laravel",
        "category": "Фреймворк",
        "cookies": [r"^laravel_session", r"^XSRF-TOKEN"],
        "implies": ["PHP"],
    },
    {
        "name": "Symfony",
        "category": "Фреймворк",
        "headers": {"x-debug-token": ""},
        "html": [r"/_profiler/", r"sf-toolbar"],
        "implies": ["PHP"],
    },
    {
        "name": "Django",
        "category": "Фреймворк",
        "cookies": [r"^csrftoken", r"^django_language"],
        "html": [r"csrfmiddlewaretoken"],
    },
    {
        "name": "Ruby on Rails",
        "category": "Фреймворк",
        "headers": {"x-runtime": ""},
        "cookies": [r"^_.*_session"],
        "html": [r'name="csrf-param"'],
    },
    {
        "name": "ASP.NET",
        "category": "Фреймворк",
        "headers": {"x-aspnet-version": "", "x-powered-by": r"ASP\.NET"},
        "cookies": [r"^ASP\.NET_SessionId", r"^\.AspNet"],
        "html": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "version": [r"x-aspnet-version:\s*([\d.]+)"],
    },
    {
        "name": "Express",
        "category": "Фреймворк",
        "headers": {"x-powered-by": r"Express"},
    },
    # -------------------------------------------------------- Веб-серверы
    {"name": "nginx", "category": "Сервер", "headers": {"server": r"nginx"}, "version": [r"nginx/([\d.]+)"]},
    {"name": "Apache", "category": "Сервер", "headers": {"server": r"Apache"}, "version": [r"Apache/([\d.]+)"]},
    {"name": "Microsoft IIS", "category": "Сервер", "headers": {"server": r"Microsoft-IIS"}, "version": [r"Microsoft-IIS/([\d.]+)"]},
    {"name": "LiteSpeed", "category": "Сервер", "headers": {"server": r"LiteSpeed"}},
    {"name": "Caddy", "category": "Сервер", "headers": {"server": r"Caddy"}},
    {"name": "OpenResty", "category": "Сервер", "headers": {"server": r"openresty"}},
    # --------------------------------------------------------------- CDN
    {
        "name": "Cloudflare",
        "category": "CDN",
        "headers": {"cf-ray": "", "server": r"cloudflare"},
    },
    {"name": "Akamai", "category": "CDN", "headers": {"x-akamai-transformed": "", "server": r"AkamaiGHost"}},
    {"name": "Fastly", "category": "CDN", "headers": {"x-served-by": r"cache-", "x-fastly-request-id": ""}},
    {"name": "Amazon CloudFront", "category": "CDN", "headers": {"x-amz-cf-id": "", "via": r"CloudFront"}},
    {"name": "Gcore", "category": "CDN", "headers": {"server": r"gcore", "x-id": r"gcore"}},
    {"name": "Selectel CDN", "category": "CDN", "headers": {"server": r"selectel"}},
    {"name": "Vercel", "category": "Хостинг", "headers": {"x-vercel-id": "", "server": r"Vercel"}},
    {"name": "Netlify", "category": "Хостинг", "headers": {"x-nf-request-id": "", "server": r"Netlify"}},
    {"name": "GitHub Pages", "category": "Хостинг", "headers": {"server": r"GitHub\.com"}},
    {"name": "Timeweb", "category": "Хостинг", "headers": {"server": r"timeweb", "x-powered-by": r"timeweb"}},
    # --------------------------------------------------------- Аналитика
    {"name": "Google Analytics 4", "category": "Аналитика", "html": [r"gtag/js\?id=G-", r"googletagmanager\.com/gtag"]},
    {"name": "Google Tag Manager", "category": "Аналитика", "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"]},
    {"name": "Яндекс.Метрика", "category": "Аналитика", "html": [r"mc\.yandex\.ru/metrika", r"ym\(\d+"]},
    {"name": "Facebook Pixel", "category": "Аналитика", "html": [r"connect\.facebook\.net/[^\"']+/fbevents\.js", r"fbq\('init'"]},
    {"name": "VK Pixel", "category": "Аналитика", "html": [r"vk\.com/js/api/openapi\.js", r"top-fwz1\.mail\.ru"]},
    {"name": "Hotjar", "category": "Аналитика", "html": [r"static\.hotjar\.com"]},
    {"name": "Roistat", "category": "Аналитика", "html": [r"cloud\.roistat\.com"]},
    {"name": "Sentry", "category": "Мониторинг", "html": [r"browser\.sentry-cdn\.com", r"Sentry\.init"]},
    # -------------------------------------------------------- Библиотеки
    {
        "name": "jQuery",
        "category": "Библиотека",
        "scripts": [r"jquery[.\-]"],
        "html": [r"jQuery\.fn\.jquery"],
        "version": [
            r"jquery[^\"']*?\bver(?:sion)?=([\d]+\.[\d]+(?:\.[\d]+)?)",
            r"jquery[.\-@]v?([\d]+\.[\d]+(?:\.[\d]+)?)",
            r"jQuery\.fn\.jquery\s*=\s*[\"']([\d.]+)",
        ],
    },
    {"name": "Bootstrap", "category": "Библиотека", "scripts": [r"bootstrap[.\-]"], "html": [r"class=\"[^\"]*\b(container-fluid|navbar-toggler|col-md-\d+)\b"], "version": [r"bootstrap[.\-@]v?([\d.]+)"]},
    {"name": "Tailwind CSS", "category": "Библиотека", "html": [r"cdn\.tailwindcss\.com", r"class=\"[^\"]*\b(flex\s+items-center|text-\w+-\d{3})\b"]},
    {"name": "Swiper", "category": "Библиотека", "scripts": [r"swiper[.\-]"], "html": [r"swiper-container", r"swiper-slide"]},
    {"name": "Font Awesome", "category": "Библиотека", "html": [r"font-?awesome", r"class=\"fa[srlbd]?\s+fa-"]},
    {"name": "Google Fonts", "category": "Шрифты", "html": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"]},
    {"name": "reCAPTCHA", "category": "Защита", "html": [r"google\.com/recaptcha", r"g-recaptcha"]},
    {"name": "Cloudflare Turnstile", "category": "Защита", "html": [r"challenges\.cloudflare\.com/turnstile"]},
]

# Технологии, о версии которых имеет смысл предупреждать при устаревании.
OUTDATED_THRESHOLDS: dict[str, tuple[str, str]] = {
    "PHP": ("8.1", "PHP младше 8.1 не получает обновлений безопасности"),
    "jQuery": ("3.5", "jQuery до 3.5 содержит известные XSS-уязвимости (CVE-2020-11022/11023)"),
    "Bootstrap": ("4.3.1", "Bootstrap до 4.3.1 уязвим к XSS в компонентах с data-атрибутами"),
    "nginx": ("1.22", "устаревшая ветка nginx без актуальных патчей"),
    "WordPress": ("6.4", "устаревшее ядро WordPress — частая причина взлома"),
}
