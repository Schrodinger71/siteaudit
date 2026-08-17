"""Модули аудита."""

from .base import Module
from .performance import PerformanceModule
from .security import SecurityModule
from .seo import SeoModule
from .tech import TechModule

ALL_MODULES: list[type[Module]] = [
    SeoModule,
    PerformanceModule,
    SecurityModule,
    TechModule,
]

__all__ = [
    "Module",
    "SeoModule",
    "PerformanceModule",
    "SecurityModule",
    "TechModule",
    "ALL_MODULES",
]
