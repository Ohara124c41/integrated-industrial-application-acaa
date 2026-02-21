from __future__ import annotations

from typing import Dict, Iterable, List

from .base import PluginBase


class PluginRegistry:
    """Simple dependency-aware plugin registry."""

    def __init__(self) -> None:
        self._plugins: Dict[str, PluginBase] = {}

    def register(self, plugin: PluginBase) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"Duplicate plugin name: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def names(self) -> List[str]:
        return list(self._plugins.keys())

    def get(self, name: str) -> PluginBase:
        return self._plugins[name]

    def all(self) -> Iterable[PluginBase]:
        return self._plugins.values()

    def resolve_order(self) -> List[str]:
        """Topological order by declared dependencies."""
        visited: Dict[str, int] = {}
        order: List[str] = []

        def dfs(name: str) -> None:
            state = visited.get(name, 0)
            if state == 1:
                raise ValueError(f"Cyclic dependency detected at plugin: {name}")
            if state == 2:
                return
            visited[name] = 1
            plugin = self._plugins[name]
            for dep in plugin.depends_on:
                if dep not in self._plugins:
                    raise KeyError(f"Missing dependency '{dep}' for plugin '{name}'")
                dfs(dep)
            visited[name] = 2
            order.append(name)

        for name in self._plugins:
            if visited.get(name, 0) == 0:
                dfs(name)
        return order

