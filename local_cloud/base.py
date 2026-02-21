from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class PluginBase(ABC):
    """Base contract for local-cloud control-plane plugins."""

    name: str = "plugin"
    depends_on: List[str] = []

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute plugin logic and return context updates."""

    def health(self) -> Dict[str, Any]:
        return {"plugin": self.name, "status": "ok"}

