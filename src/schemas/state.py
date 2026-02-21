from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Stage(str, Enum):
    INIT = "init"
    INTAKE = "intake"
    EVIDENCE = "evidence"
    RCA = "rca"
    RESPONSE = "response"
    GOVERNANCE = "governance"
    FINAL = "final"


@dataclass
class Hypothesis:
    hypothesis_id: str
    hypothesis_text: str
    confidence_score: float
    supporting_evidence_ids: List[str] = field(default_factory=list)
    counter_evidence_ids: List[str] = field(default_factory=list)
    validation_steps: List[str] = field(default_factory=list)
    business_impact_note: str = ""


@dataclass
class AttackTechnique:
    technique_id: str
    technique_name: str
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ActionProposal:
    action_type: str
    target_id: str
    rationale: str
    requires_human_approval: bool = False


@dataclass
class PolicyCheckResult:
    passed: bool
    violations: List[str] = field(default_factory=list)
    nist_findings: List[Dict[str, str]] = field(default_factory=list)
    iec_findings: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class IncidentState:
    incident_id: str
    scenario_id: str
    incident_text: str
    telemetry_excerpt_ids: List[str]
    known_constraints: Dict[str, Any]
    threat_model: Dict[str, Any]
    asset_id: str

    stage: Stage = Stage.INIT
    severity: str = "unknown"
    confidence_band: str = "low"
    escalation_required: bool = False

    local_risk_snapshot: Dict[str, Any] = field(default_factory=dict)
    evidence_bundle: List[Dict[str, Any]] = field(default_factory=list)
    evidence_quality: float = 0.0

    rca_hypotheses: List[Hypothesis] = field(default_factory=list)
    selected_hypothesis: Optional[Hypothesis] = None
    attack_techniques: List[AttackTechnique] = field(default_factory=list)

    proposed_actions: List[ActionProposal] = field(default_factory=list)
    policy_check_result: Optional[PolicyCheckResult] = None

    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    audit_trace_ids: List[str] = field(default_factory=list)
    logs: List[Dict[str, Any]] = field(default_factory=list)

    degraded_mode: bool = False
    error: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def add_log(self, level: str, message: str, **extra: Any) -> None:
        self.logs.append(
            {
                "ts": utc_now_iso(),
                "level": level,
                "stage": self.stage.value,
                "message": message,
                **extra,
            }
        )
        self.updated_at = utc_now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

