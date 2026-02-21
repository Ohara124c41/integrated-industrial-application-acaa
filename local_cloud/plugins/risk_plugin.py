from __future__ import annotations

from typing import Any, Dict

import pandas as pd

from ..base import PluginBase


class RiskPlugin(PluginBase):
    name = "risk"
    depends_on = ["ingest"]

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        df: pd.DataFrame = context["packets_df"]
        risk = pd.to_numeric(df["risk_score_agentic"], errors="coerce")
        out = {
            "risk_summary": {
                "mean_risk": float(risk.mean()),
                "high_risk_count_ge_0_80": int((risk >= 0.80).sum()),
                "zone_mean_risk": df.groupby("zone")["risk_score_agentic"].mean().round(4).to_dict(),
            }
        }
        return out

