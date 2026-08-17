"""Модули аудита."""

from .a11y import A11yModule
from .base import Module
from .crawl import CrawlModule
from .dns_mail import DnsModule
from .performance import PerformanceModule
from .security import SecurityModule
from .seo import SeoModule
from .tech import TechModule
from .vitals import VitalsModule

ALL_MODULES: list[type[Module]] = [
    SeoModule,
    PerformanceModule,
    VitalsModule,
    A11yModule,
    SecurityModule,
    DnsModule,
    CrawlModule,
    TechModule,
]

__all__ = [
    "Module",
    "SeoModule",
    "PerformanceModule",
    "VitalsModule",
    "A11yModule",
    "SecurityModule",
    "DnsModule",
    "CrawlModule",
    "TechModule",
    "ALL_MODULES",
]
