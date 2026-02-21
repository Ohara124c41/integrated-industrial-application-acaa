from __future__ import annotations

from src.schemas import IncidentState, PolicyCheckResult, Stage
from src.tools import get_policy_rules, get_zone_conduit_policy, nist_governance_checks, validate_action_plan


class GovernanceAgent:
    name = "governance"

    def __init__(self, policy_version: str = "v1") -> None:
        self.policy_version = policy_version

    def process(self, state: IncidentState) -> IncidentState:
        state.stage = Stage.GOVERNANCE

        rules = get_policy_rules(self.policy_version)
        zone_policy = get_zone_conduit_policy(state.asset_id)

        result = validate_action_plan(
            action_plan=[
                {
                    "action_type": a.action_type,
                    "target_id": a.target_id,
                    "rationale": a.rationale,
                }
                for a in state.proposed_actions
            ],
            policy_rules=rules,
            zone_policy=zone_policy,
            evidence_quality=state.evidence_quality,
        )

        selected_conf = state.selected_hypothesis.confidence_score if state.selected_hypothesis else 0.0
        if selected_conf < float(rules["min_confidence_auto"]):
            result["violations"].append("low_hypothesis_confidence")
            result["passed"] = False

        nist = nist_governance_checks(state.evidence_quality, selected_conf, escalation_required=(not result["passed"]))
        iec = [
            {
                "control": "IEC62443-zone-conduit",
                "zone": zone_policy.get("zone", "UNKNOWN"),
                "status": "pass" if not any(v.startswith("zone_policy_violation") for v in result["violations"]) else "watch",
            }
        ]

        state.policy_check_result = PolicyCheckResult(
            passed=bool(result["passed"]),
            violations=list(result["violations"]),
            nist_findings=nist,
            iec_findings=iec,
        )

        state.escalation_required = (not state.policy_check_result.passed) or bool(result.get("requires_human_approval", False))

        state.add_log(
            "info",
            "Governance checks completed",
            policy_passed=state.policy_check_result.passed,
            violations=state.policy_check_result.violations,
            escalation_required=state.escalation_required,
        )
        return state

