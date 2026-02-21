from __future__ import annotations

from typing import Dict, List


def get_policy_rules(policy_version: str = "v1") -> Dict:
    return {
        "policy_version": policy_version,
        "allowed_action_types": [
            "monitor",
            "increase_logging",
            "isolate_segment",
            "request_patch_window",
            "block_external_egress",
            "manual_investigation",
        ],
        "requires_human_approval_for": [
            "isolate_segment",
            "block_external_egress",
        ],
        "max_actions": 3,
        "min_evidence_quality": 0.45,
        "min_confidence_auto": 0.55,
    }


def get_zone_conduit_policy(asset_id: str) -> Dict:
    asset = asset_id.upper()
    if "PLC" in asset:
        zone = "OT_CONTROL"
        permitted = ["monitor", "increase_logging", "request_patch_window", "manual_investigation"]
    elif "HMI" in asset:
        zone = "OT_SUPERVISORY"
        permitted = ["monitor", "increase_logging", "isolate_segment", "manual_investigation"]
    else:
        zone = "IT_DMZ"
        permitted = [
            "monitor",
            "increase_logging",
            "isolate_segment",
            "block_external_egress",
            "manual_investigation",
        ]
    return {"asset_id": asset_id, "zone": zone, "permitted_actions": permitted}


def validate_action_plan(action_plan: List[Dict], policy_rules: Dict, zone_policy: Dict, evidence_quality: float) -> Dict:
    violations: List[str] = []
    requires_approval = False

    if len(action_plan) > int(policy_rules["max_actions"]):
        violations.append(f"too_many_actions>{policy_rules['max_actions']}")

    for action in action_plan:
        action_type = action.get("action_type", "")
        if action_type not in policy_rules["allowed_action_types"]:
            violations.append(f"disallowed_action:{action_type}")
        if action_type in policy_rules["requires_human_approval_for"]:
            requires_approval = True
        if action_type not in zone_policy.get("permitted_actions", []):
            violations.append(f"zone_policy_violation:{zone_policy.get('zone')}:{action_type}")

    if evidence_quality < float(policy_rules["min_evidence_quality"]):
        violations.append("low_evidence_quality")

    return {
        "passed": len(violations) == 0,
        "violations": violations,
        "requires_human_approval": requires_approval,
    }


def nist_governance_checks(evidence_quality: float, confidence: float, escalation_required: bool) -> List[Dict[str, str]]:
    checks = []
    checks.append(
        {
            "csf_ref": "DE.CM-01",
            "check": "Monitoring coverage and data sufficiency",
            "status": "pass" if evidence_quality >= 0.45 else "watch",
        }
    )
    checks.append(
        {
            "csf_ref": "RS.AN-01",
            "check": "Incident analysis confidence",
            "status": "pass" if confidence >= 0.55 else "watch",
        }
    )
    checks.append(
        {
            "csf_ref": "RS.CO-03",
            "check": "Escalation path readiness",
            "status": "pass" if escalation_required else "watch",
        }
    )
    return checks

