from __future__ import annotations

from typing import Dict, List

from src.llm_client import VocareumLLMClient
from src.schemas import AttackTechnique, Hypothesis, IncidentState, Stage
from src.tools import map_to_attack_techniques


class RCAAgent:
    name = "rca"

    def __init__(self, llm_client: VocareumLLMClient) -> None:
        self.llm = llm_client

    def process(self, state: IncidentState, risk_features: Dict) -> IncidentState:
        state.stage = Stage.RCA

        anomaly_tags: List[str] = list(risk_features.get("anomaly_tags", []))
        risk_score = float(risk_features.get("risk_score", 0.0))
        base_conf = 0.30 + 0.35 * risk_score + 0.35 * state.evidence_quality
        base_conf = max(0.05, min(0.95, base_conf))

        h1_text = "Likely coordinated suspicious traffic with potential control-channel behavior from anomalous protocol/flow signals."
        h2_text = "Alternative explanation: benign operational burst or maintenance process causing transient anomaly signatures."

        h1_text = self.llm.enrich_hypothesis(state.incident_text, h1_text, incident_id=state.incident_id)

        h1 = Hypothesis(
            hypothesis_id="H1",
            hypothesis_text=h1_text,
            confidence_score=round(base_conf, 4),
            supporting_evidence_ids=[str(x.get("evidence_id", "UNK")) for x in state.evidence_bundle[:3]],
            validation_steps=[
                "Check flow continuity and endpoint recurrence over next 15 minutes",
                "Cross-check destination pattern against known maintenance windows",
            ],
            business_impact_note="Potential integrity/availability impact if lateral propagation is present.",
        )
        h2 = Hypothesis(
            hypothesis_id="H2",
            hypothesis_text=h2_text,
            confidence_score=round(max(0.05, 1.0 - base_conf - 0.10), 4),
            supporting_evidence_ids=[str(x.get("evidence_id", "UNK")) for x in state.evidence_bundle[-2:]],
            validation_steps=["Verify maintenance/change calendar", "Compare with historical benign baselines"],
            business_impact_note="Lower immediate risk but can mask true malicious activity.",
        )

        state.rca_hypotheses = sorted([h1, h2], key=lambda x: x.confidence_score, reverse=True)
        state.selected_hypothesis = state.rca_hypotheses[0]

        mapped = map_to_attack_techniques(state.evidence_bundle, anomaly_tags)
        state.attack_techniques = [AttackTechnique(**m) for m in mapped]

        conf = state.selected_hypothesis.confidence_score if state.selected_hypothesis else 0.0
        state.confidence_band = "high" if conf >= 0.70 else ("medium" if conf >= 0.50 else "low")

        state.add_log(
            "info",
            "RCA hypotheses generated",
            selected_hypothesis=state.selected_hypothesis.hypothesis_id if state.selected_hypothesis else None,
            confidence=conf,
            attack_technique_count=len(state.attack_techniques),
        )
        return state
