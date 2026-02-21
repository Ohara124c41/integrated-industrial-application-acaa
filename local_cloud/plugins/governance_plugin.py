from __future__ import annotations

from typing import Any, Dict

import pandas as pd

from ..base import PluginBase


class GovernancePlugin(PluginBase):
    name = "governance"
    depends_on = ["ingest", "agent"]

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        packets_df: pd.DataFrame = context["packets_df"]
        meta_df: pd.DataFrame = context["meta_df"]

        policy_fail_packet_ids = set(
            packets_df.loc[packets_df["policy_passed"] == False, "incident_id"].astype(str).tolist()  # noqa: E712
        )
        violations = 0
        if len(meta_df):
            for _, row in meta_df.iterrows():
                iid = str(row.get("incident_id"))
                if iid in policy_fail_packet_ids and str(row.get("final_recommendation")) != "escalate":
                    violations += 1

        return {
            "governance_summary": {
                "policy_fail_count": int(len(policy_fail_packet_ids)),
                "policy_gate_invariant_violations": int(violations),
                "status": "pass" if violations == 0 else "fail",
            }
        }

