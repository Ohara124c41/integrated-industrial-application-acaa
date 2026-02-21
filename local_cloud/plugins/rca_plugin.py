from __future__ import annotations

from typing import Any, Dict

import pandas as pd

from ..base import PluginBase


class RCAPlugin(PluginBase):
    name = "rca"
    depends_on = ["ingest"]

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        df: pd.DataFrame = context["packets_df"]
        rca_cols = ["incident_id", "gen_hypothesis", "gen_quality_flags", "gen_failure_mode_tags"]
        existing = [c for c in rca_cols if c in df.columns]
        rca_view = df[existing].copy()

        quality_issue_count = 0
        if "gen_quality_flags" in rca_view.columns:
            quality_issue_count = int(
                rca_view["gen_quality_flags"].astype(str).str.contains(r"\[\]", regex=True, na=False).sum()
            )

        return {
            "rca_view": rca_view,
            "rca_summary": {
                "incident_count": int(len(rca_view)),
                "empty_quality_flag_rows": quality_issue_count,
            },
        }

