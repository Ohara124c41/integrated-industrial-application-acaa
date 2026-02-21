from __future__ import annotations

from typing import Dict, List

from src.schemas import IncidentState, Stage


class EvidenceAgent:
    name = "evidence"

    def process(self, state: IncidentState, evidence_bundle: List[Dict]) -> IncidentState:
        state.stage = Stage.EVIDENCE
        state.evidence_bundle = evidence_bundle

        evid_count = len(evidence_bundle)
        has_telemetry_refs = len(state.telemetry_excerpt_ids) > 0
        has_risk_score = "risk_score" in state.local_risk_snapshot

        quality = 0.20
        quality += min(0.50, evid_count * 0.12)
        if has_telemetry_refs:
            quality += 0.15
        if has_risk_score:
            quality += 0.15
        state.evidence_quality = max(0.0, min(1.0, quality))

        state.add_log(
            "info",
            "Evidence scoring complete",
            evidence_count=evid_count,
            evidence_quality=round(state.evidence_quality, 4),
        )
        return state

