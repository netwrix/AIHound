"""Scanner auto-discovery registry."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Type

from aihound.core.scanner import BaseScanner

_registry: list[Type[BaseScanner]] = []


def register(cls: Type[BaseScanner]) -> Type[BaseScanner]:
    """Decorator to register a scanner class."""
    _registry.append(cls)
    return cls


def discover_scanners() -> list[Type[BaseScanner]]:
    """Import all scanner modules to trigger @register decorators."""
    for _, name, _ in pkgutil.iter_modules(__path__):
        importlib.import_module(f".{name}", __package__)
    return list(_registry)


def get_all_scanners() -> list[BaseScanner]:
    """Instantiate all registered scanners."""
    discover_scanners()
    return [cls() for cls in _registry]
