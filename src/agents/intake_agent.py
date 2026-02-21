from __future__ import annotations

from typing import Dict

from src.schemas import IncidentState, Stage


class IntakeAgent:
    name = "intake"

    def process(self, state: IncidentState, risk_features: Dict) -> IncidentState:
        state.stage = Stage.INTAKE
        state.local_risk_snapshot = risk_features

        risk_score = float(risk_features.get("risk_score", 0.0))
        if risk_score >= 0.85:
            severity = "critical"
        elif risk_score >= 0.65:
            severity = "high"
        elif risk_score >= 0.40:
            severity = "medium"
        else:
            severity = "low"

        injection_markers = ["ignore previous", "disable safety", "override policy", "system prompt"]
        lowered = state.incident_text.lower()
        prompt_injection_flag = any(m in lowered for m in injection_markers)

        state.severity = severity
        if prompt_injection_flag:
            state.add_log("warning", "Potential prompt injection pattern detected", marker="text_instruction")

        state.add_log("info", "Intake classification complete", severity=severity, prompt_injection_flag=prompt_injection_flag)
        return state

