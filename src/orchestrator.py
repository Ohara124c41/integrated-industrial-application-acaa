from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from src.agents import EvidenceAgent, GovernanceAgent, IntakeAgent, RCAAgent, ResponsePlannerAgent
from src.llm_client import VocareumLLMClient
from src.schemas import IncidentState, Stage
from src.tools import get_incident_context, get_local_risk_features, list_scenarios, write_audit_event


class AgenticOrchestrator:
    """One orchestrator controlling five role agents with explicit handoffs."""

    def __init__(self, output_dir: Path, use_llm: bool = False, model: str = "gpt-4o-mini") -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        llm_client = VocareumLLMClient(enabled=use_llm, model=model, output_dir=self.output_dir)

        self.intake = IntakeAgent()
        self.evidence = EvidenceAgent()
        self.rca = RCAAgent(llm_client=llm_client)
        self.response = ResponsePlannerAgent()
        self.governance = GovernanceAgent(policy_version="v1")

    def _audit(self, state: IncidentState, stage: str, event_type: str, detail: Dict) -> None:
        trace_id = write_audit_event(self.output_dir, state.incident_id, stage, event_type, detail)
        state.audit_trace_ids.append(trace_id)

    def run_incident(self, incident_id: str) -> Dict:
        ctx = get_incident_context(incident_id)
        risk = get_local_risk_features(incident_id)

        state = IncidentState(
            incident_id=ctx["incident_id"],
            scenario_id=ctx["scenario_id"],
            incident_text=ctx["incident_text"],
            telemetry_excerpt_ids=ctx.get("telemetry_excerpt_ids", []),
            known_constraints=ctx.get("known_constraints", {}),
            threat_model=ctx.get("threat_model", {}),
            asset_id=ctx.get("asset_id", "ASSET_UNKNOWN"),
        )

        try:
            self._audit(state, "orchestrator", "start", {"scenario_id": state.scenario_id})

            state = self.intake.process(state, risk)
            self._audit(state, state.stage.value, "completed", {"severity": state.severity})

            state = self.evidence.process(state, ctx.get("evidence_bundle", []))
            self._audit(state, state.stage.value, "completed", {"evidence_quality": state.evidence_quality})

            state = self.rca.process(state, risk)
            self._audit(
                state,
                state.stage.value,
                "completed",
                {
                    "selected_hypothesis": state.selected_hypothesis.hypothesis_id if state.selected_hypothesis else None,
                    "confidence_band": state.confidence_band,
                },
            )

            state = self.response.process(state)
            self._audit(state, state.stage.value, "completed", {"action_count": len(state.proposed_actions)})

            state = self.governance.process(state)
            self._audit(
                state,
                state.stage.value,
                "completed",
                {
                    "policy_passed": state.policy_check_result.passed if state.policy_check_result else False,
                    "escalation_required": state.escalation_required,
                },
            )

        except Exception as exc:
            state.degraded_mode = True
            state.error = str(exc)
            state.escalation_required = True
            state.add_log("error", "Unhandled orchestrator exception", error=str(exc))
            self._audit(state, "orchestrator", "exception", {"error": str(exc)})

        state.stage = Stage.FINAL
        decision_type = self._decision_type(state)
        zone = None
        if state.policy_check_result and state.policy_check_result.iec_findings:
            zone = state.policy_check_result.iec_findings[0].get("zone")
        policy_passed = state.policy_check_result.passed if state.policy_check_result else False
        policy_violations = state.policy_check_result.violations if state.policy_check_result else []
        nist_findings = state.policy_check_result.nist_findings if state.policy_check_result else []
        iec_findings = state.policy_check_result.iec_findings if state.policy_check_result else []
        selected_conf = state.selected_hypothesis.confidence_score if state.selected_hypothesis else 0.0

        packet = {
            "incident_id": state.incident_id,
            "scenario_id": state.scenario_id,
            "decision_type": decision_type,
            "severity": state.severity,
            "zone": zone,
            "risk_score": float(risk.get("risk_score", 0.0)),
            "anomaly_tags": list(risk.get("anomaly_tags", [])),
            "anomaly_count": int(risk.get("anomaly_count", 0)),
            "known_constraints": state.known_constraints,
            "threat_model": state.threat_model,
            "asset_id": state.asset_id,
            "selected_hypothesis": (state.selected_hypothesis.hypothesis_text if state.selected_hypothesis else None),
            "selected_hypothesis_confidence": float(selected_conf),
            "confidence_band": state.confidence_band,
            "evidence_quality": state.evidence_quality,
            "policy_passed": policy_passed,
            "policy_violations": policy_violations,
            "nist_findings": nist_findings,
            "iec_findings": iec_findings,
            "policy_check_result": (state.policy_check_result.__dict__ if state.policy_check_result else None),
            "action_plan": [a.__dict__ for a in state.proposed_actions],
            "attack_techniques": [a.__dict__ for a in state.attack_techniques],
            "escalation_required": state.escalation_required,
            "audit_trace_ids": state.audit_trace_ids,
            "degraded_mode": state.degraded_mode,
            "error": state.error,
            "state_log_count": len(state.logs),
        }

        out_path = self.output_dir / "decision_packets.jsonl"
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(packet, ensure_ascii=False) + "\n")
        # Persist full state snapshot for replay/debug/report traceability.
        snap_dir = self.output_dir / "state_snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        (snap_dir / f"{state.incident_id}.json").write_text(
            json.dumps(state.to_dict(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

        self._audit(state, "orchestrator", "final_packet", {"decision_type": decision_type, "output": str(out_path)})
        return packet

    @staticmethod
    def _decision_type(state: IncidentState) -> str:
        if state.error:
            return "defer"
        text = state.incident_text.lower()
        if "disable safety" in text or "ignore previous" in text:
            return "refuse"
        if state.escalation_required:
            return "escalate"
        return "propose"

    def run_many(self, incident_ids: Optional[Iterable[str]] = None) -> List[Dict]:
        ids = list(incident_ids) if incident_ids else list_scenarios()
        results = []
        for incident_id in ids:
            results.append(self.run_incident(incident_id))
        return results
