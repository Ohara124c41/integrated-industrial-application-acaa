from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .registry import PluginRegistry
from .plugins import AgentPlugin, GovernancePlugin, IngestPlugin, RCAPlugin, RiskPlugin, StoragePlugin


class LocalCloudControlPlane:
    """Dependency-aware plugin runtime with bounded failure handling."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)
        self.registry = PluginRegistry()
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.registry.register(IngestPlugin())
        self.registry.register(RiskPlugin())
        self.registry.register(RCAPlugin())
        self.registry.register(AgentPlugin())
        self.registry.register(GovernancePlugin())
        self.registry.register(StoragePlugin())

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        run_ctx = dict(context)
        run_ctx["output_dir"] = str(self.output_dir)
        run_ctx["execution_log"] = []

        order = self.registry.resolve_order()
        for name in order:
            plugin = self.registry.get(name)
            started = datetime.now(timezone.utc).isoformat()
            try:
                updates = plugin.run(run_ctx)
                if updates:
                    run_ctx.update(updates)
                status = "ok"
                error = ""
            except Exception as exc:  # pragma: no cover
                status = "error"
                error = str(exc)
                run_ctx["execution_log"].append(
                    {
                        "plugin": name,
                        "status": status,
                        "started_utc": started,
                        "error": error,
                    }
                )
                break

            run_ctx["execution_log"].append(
                {
                    "plugin": name,
                    "status": status,
                    "started_utc": started,
                    "error": error,
                }
            )

        self.output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "plugin_order": order,
            "execution_log": run_ctx["execution_log"],
            "governance_summary": run_ctx.get("governance_summary", {}),
            "risk_summary": run_ctx.get("risk_summary", {}),
            "agent_summary": run_ctx.get("agent_summary", {}),
            "storage_summary": run_ctx.get("storage_summary", {}),
            "rca_summary": run_ctx.get("rca_summary", {}),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        (self.output_dir / "local_cloud_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return run_ctx


def default_context(project_root: Path) -> Dict[str, Any]:
    project_root = Path(project_root)
    return {
        "integrated_packets_path": str(project_root / "outputs" / "integrated_packets.jsonl"),
        "meta_decisions_path": str(project_root / "outputs" / "meta_decisions.jsonl"),
        "rebuild_meta": True,
        "contested_llm_enabled": False,
        "contested_meta_llm_enabled": False,
        "contested_llm_passes": 1,
        "contested_model": "gpt-4o-mini",
    }


def run_local_cloud(project_root: Path, output_dir: Path | None = None) -> Dict[str, Any]:
    project_root = Path(project_root)
    out = Path(output_dir) if output_dir else project_root / "outputs"
    control_plane = LocalCloudControlPlane(out)
    return control_plane.run(default_context(project_root))
