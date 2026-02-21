from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

from ..base import PluginBase
import contested_orchestration as contested


class AgentPlugin(PluginBase):
    name = "agent"
    depends_on = ["ingest"]

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        output_dir = Path(context["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)

        rebuild_meta = bool(context.get("rebuild_meta", True))
        if rebuild_meta:
            integrated_packets_path = Path(context["integrated_packets_path"])
            run_out = contested.run_contested_orchestration(
                integrated_packets_path=integrated_packets_path,
                output_dir=output_dir,
                write_suffix="local_cloud",
                llm_enabled=bool(context.get("contested_llm_enabled", False)),
                model=str(context.get("contested_model", "gpt-4o-mini")),
                llm_passes=int(context.get("contested_llm_passes", 1)),
                meta_llm_enabled=bool(context.get("contested_meta_llm_enabled", False)),
            )
            meta_rows = run_out["meta_decisions"]
            meta_path = output_dir / "meta_decisions_local_cloud.jsonl"
        else:
            meta_path = Path(context["meta_decisions_path"])
            meta_rows = [json.loads(line) for line in meta_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        meta_df = pd.DataFrame(meta_rows)

        disagreement_rate = float(
            np.mean(
                meta_df["disagreement_flags"].apply(
                    lambda d: bool(d.get("recommendation_disagreement", False)) if isinstance(d, dict) else False
                )
            )
        ) if len(meta_df) else 0.0

        hitl_required_rate = float(np.mean(meta_df["hitl_required"])) if "hitl_required" in meta_df else 0.0

        return {
            "meta_df": meta_df,
            "agent_summary": {
                "meta_rows": int(len(meta_df)),
                "disagreement_rate": round(disagreement_rate, 4),
                "hitl_required_rate": round(hitl_required_rate, 4),
                "meta_decisions_path": str(meta_path),
                "meta_rebuilt_in_run": bool(rebuild_meta),
            },
        }
