from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypedDict

import numpy as np
from langchain_core.prompts import PromptTemplate
from langgraph.graph import END, START, StateGraph

from src.llm_client import VocareumLLMClient


class OrchestrationState(TypedDict, total=False):
    packet: Dict[str, Any]
    security_branch: Dict[str, Any]
    operations_branch: Dict[str, Any]
    meta_decision: Dict[str, Any]


SECURITY_PROMPT = PromptTemplate.from_template(
    "Incident {incident_id} in zone {zone}: prioritize containment and assurance. "
    "risk={risk:.3f}, policy_passed={policy_passed}, attack_techniques={attack_count}. "
    "Generate a concise defensive rationale for a security-first recommendation."
)

OPS_PROMPT = PromptTemplate.from_template(
    "Incident {incident_id} in zone {zone}: prioritize continuity and bounded disruption. "
    "risk={risk:.3f}, policy_passed={policy_passed}, escalation_required={escalation_required}. "
    "Generate a concise rationale for an operations-continuity recommendation."
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _responsibility_entry(
    *,
    layer: str,
    owner: str,
    objective: str,
    constraints: List[str],
    decision_basis: List[str],
    incident_id: str,
) -> Dict[str, Any]:
    return {
        "incident_id": incident_id,
        "layer": layer,
        "owner": owner,
        "objective": objective,
        "constraints": constraints,
        "decision_basis": decision_basis,
        "timestamp_utc": _now_utc(),
    }


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _clip01(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


def _enforce_policy_gate(policy_passed: bool, recommendation: str) -> str:
    """Hard safety invariant: policy failures cannot end in propose/defer."""
    return recommendation if policy_passed else "escalate"


def _llm_multi_pass_refine(
    *,
    llm_client: VocareumLLMClient,
    incident_text: str,
    base_rationale: str,
    incident_id: str,
    perspective: str,
    llm_passes: int,
) -> tuple[str, List[Dict[str, Any]]]:
    passes = max(1, int(llm_passes))
    rationale = base_rationale
    notes: List[Dict[str, Any]] = []
    for i in range(passes):
        if i == 0:
            prompt_seed = rationale
        else:
            prompt_seed = (
                "Refine this defensive rationale in 1-2 lines with explicit uncertainty. "
                f"Perspective={perspective}. Prior draft: {rationale}"
            )
        out = llm_client.enrich_hypothesis(
            incident_text,
            prompt_seed,
            incident_id=f"{incident_id}:{perspective}:pass_{i + 1}",
        )
        rationale = out
        notes.append({"pass_index": i + 1, "text": out})
    return rationale, notes


def _security_assurance_node_factory(
    llm_client: VocareumLLMClient,
    *,
    llm_passes: int,
) -> Callable[[OrchestrationState], OrchestrationState]:
    def _security_assurance_node(state: OrchestrationState) -> OrchestrationState:
        p = state["packet"]
        risk = float(p.get("risk_score_agentic", 0.0))
        policy_passed = bool(p.get("policy_passed", False))
        attack_count = int(p.get("attack_technique_count", 0))
        escalation = bool(p.get("escalation_required", False))
        incident_id = str(p.get("incident_id"))

        attack_norm = min(1.0, attack_count / 4.0)
        score = _clip01(0.50 * risk + 0.25 * attack_norm + 0.20 * (0.0 if policy_passed else 1.0) + 0.05 * (1.0 if escalation else 0.0))
        recommendation = "escalate" if score >= 0.60 else "propose"
        recommendation = _enforce_policy_gate(policy_passed, recommendation)

        rationale_base = SECURITY_PROMPT.format(
            incident_id=p.get("incident_id"),
            zone=p.get("zone"),
            risk=risk,
            policy_passed=policy_passed,
            attack_count=attack_count,
        )
        incident_text = (
            f"Incident {incident_id} in zone {p.get('zone')} "
            f"risk={risk:.3f} policy_passed={policy_passed} "
            f"attack_count={attack_count} escalation={escalation}"
        )
        rationale, deliberation_notes = _llm_multi_pass_refine(
            llm_client=llm_client,
            incident_text=incident_text,
            base_rationale=rationale_base,
            incident_id=incident_id,
            perspective="security_assurance",
            llm_passes=llm_passes,
        )

        responsibility_log = [
            _responsibility_entry(
                layer="branch",
                owner="security_assurance_orchestrator",
                objective="Maximize containment assurance under policy and threat-surface constraints.",
                constraints=["policy_gates", "attack_surface_weighting", "escalation_signal"],
                decision_basis=["risk_score_agentic", "attack_technique_count", "policy_passed", "escalation_required"],
                incident_id=incident_id,
            )
        ]

        return {
            "security_branch": {
                "incident_id": incident_id,
                "branch_id": "security_assurance",
                "objective_weights": {"risk": 0.50, "attack_surface": 0.25, "policy": 0.20, "escalation_signal": 0.05},
                "branch_score": round(score, 4),
                "branch_recommendation": recommendation,
                "branch_tradeoff_note": rationale,
                "branch_deliberation_notes": deliberation_notes,
                "policy_violations": [] if policy_passed else ["policy_failed_in_packet"],
                "responsibility_log": responsibility_log,
                "llm_enriched": bool(llm_client.available()),
                "llm_passes": int(max(1, llm_passes)),
            }
        }

    return _security_assurance_node


def _operations_continuity_node_factory(
    llm_client: VocareumLLMClient,
    *,
    llm_passes: int,
) -> Callable[[OrchestrationState], OrchestrationState]:
    def _operations_continuity_node(state: OrchestrationState) -> OrchestrationState:
        p = state["packet"]
        risk = float(p.get("risk_score_agentic", 0.0))
        policy_passed = bool(p.get("policy_passed", False))
        escalation = bool(p.get("escalation_required", False))
        confidence = float(p.get("hypothesis_confidence", 0.0))
        incident_id = str(p.get("incident_id"))

        score = _clip01(0.45 * (1.0 - risk) + 0.30 * (1.0 if policy_passed else 0.0) + 0.15 * confidence + 0.10 * (0.0 if escalation else 1.0))
        recommendation = "propose" if score >= 0.55 and policy_passed else "escalate"

        rationale_base = OPS_PROMPT.format(
            incident_id=p.get("incident_id"),
            zone=p.get("zone"),
            risk=risk,
            policy_passed=policy_passed,
            escalation_required=escalation,
        )
        incident_text = (
            f"Incident {incident_id} in zone {p.get('zone')} "
            f"risk={risk:.3f} policy_passed={policy_passed} "
            f"confidence={confidence:.3f} escalation={escalation}"
        )
        rationale, deliberation_notes = _llm_multi_pass_refine(
            llm_client=llm_client,
            incident_text=incident_text,
            base_rationale=rationale_base,
            incident_id=incident_id,
            perspective="operations_continuity",
            llm_passes=llm_passes,
        )

        responsibility_log = [
            _responsibility_entry(
                layer="branch",
                owner="operations_continuity_orchestrator",
                objective="Minimize disruption while preserving bounded defensive posture.",
                constraints=["policy_cleanliness", "confidence_floor", "disruption_avoidance"],
                decision_basis=["risk_score_agentic", "policy_passed", "hypothesis_confidence", "escalation_required"],
                incident_id=incident_id,
            )
        ]

        return {
            "operations_branch": {
                "incident_id": incident_id,
                "branch_id": "operations_continuity",
                "objective_weights": {"continuity": 0.45, "policy_cleanliness": 0.30, "confidence": 0.15, "disruption_avoidance": 0.10},
                "branch_score": round(score, 4),
                "branch_recommendation": recommendation,
                "branch_tradeoff_note": rationale,
                "branch_deliberation_notes": deliberation_notes,
                "policy_violations": [] if policy_passed else ["policy_failed_in_packet"],
                "responsibility_log": responsibility_log,
                "llm_enriched": bool(llm_client.available()),
                "llm_passes": int(max(1, llm_passes)),
            }
        }

    return _operations_continuity_node


def _meta_adjudication_node_factory(
    llm_client: VocareumLLMClient,
    *,
    meta_llm_enabled: bool,
) -> Callable[[OrchestrationState], OrchestrationState]:
    def _meta_adjudication_node(state: OrchestrationState) -> OrchestrationState:
        p = state["packet"]
        sec = state["security_branch"]
        ops = state["operations_branch"]

        # Hard safety gate first.
        if not bool(p.get("policy_passed", False)):
            selected = "security_assurance"
            rationale = "Policy failure triggers safety-first selection."
        else:
            # Soft optimization under shared constraints.
            sec_score = float(sec.get("branch_score", 0.0))
            ops_score = float(ops.get("branch_score", 0.0))
            if sec_score >= ops_score:
                selected = "security_assurance"
                rationale = "Security branch score is higher under current constraints."
            else:
                selected = "operations_continuity"
                rationale = "Continuity branch score is higher while policy is satisfied."

        diff = abs(float(sec.get("branch_score", 0.0)) - float(ops.get("branch_score", 0.0)))
        disagree = sec.get("branch_recommendation") != ops.get("branch_recommendation")
        hitl_required = bool(diff < 0.10 or disagree)

        selected_packet = sec if selected == "security_assurance" else ops
        incident_id = str(p.get("incident_id"))
        meta_responsibility_log = [
            _responsibility_entry(
                layer="meta",
                owner="meta_orchestrator",
                objective="Resolve branch contention under cross-cutting system constraints.",
                constraints=["global_policy_gates", "zone_conduit_bounds", "attack_surface_awareness", "safety_first_fallback"],
                decision_basis=["branch_scores", "policy_passed", "recommendation_disagreement", "score_distance"],
                incident_id=incident_id,
            )
        ]
        meta_advisory_note = (
            f"Selected {selected} for incident {incident_id}. "
            f"policy_passed={bool(p.get('policy_passed', False))}, "
            f"score_distance={round(diff, 4)}, disagreement={disagree}."
        )
        if meta_llm_enabled:
            incident_text = (
                f"Incident {incident_id} zone={p.get('zone')} policy_passed={bool(p.get('policy_passed', False))} "
                f"sec_score={float(sec.get('branch_score', 0.0)):.4f} ops_score={float(ops.get('branch_score', 0.0)):.4f}"
            )
            advisory_seed = (
                "Generate a concise defensive meta-adjudication note in 1-2 lines. "
                "State tradeoff and residual uncertainty. "
                f"Selected={selected}. Rationale={rationale}."
            )
            meta_advisory_note = llm_client.enrich_hypothesis(
                incident_text,
                advisory_seed,
                incident_id=f"{incident_id}:meta_adjudication",
            )

        final_recommendation = _enforce_policy_gate(
            bool(p.get("policy_passed", False)),
            str(selected_packet.get("branch_recommendation")),
        )
        meta = {
            "incident_id": incident_id,
            "candidate_branches": [sec, ops],
            "selected_branch": selected,
            "selection_rationale": rationale,
            "cross_constraint_checks": {
                "policy_passed": bool(p.get("policy_passed", False)),
                "zone": p.get("zone"),
                "attack_technique_count": int(p.get("attack_technique_count", 0)),
            },
            "disagreement_flags": {
                "recommendation_disagreement": disagree,
                "score_distance": round(diff, 4),
            },
            "hitl_required": hitl_required,
            "final_recommendation": final_recommendation,
            "meta_advisory_note": meta_advisory_note,
            "meta_llm_enriched": bool(meta_llm_enabled and llm_client.available()),
            "responsibility_log": meta_responsibility_log,
            "meta_timestamp_utc": _now_utc(),
        }
        return {"meta_decision": meta}

    return _meta_adjudication_node


def build_contested_graph(
    *,
    llm_enabled: bool = False,
    model: str = "gpt-4o-mini",
    output_dir: Optional[Path] = None,
    llm_passes: int = 1,
    meta_llm_enabled: bool = False,
):
    llm_client = VocareumLLMClient(enabled=llm_enabled, model=model, output_dir=output_dir)
    graph = StateGraph(OrchestrationState)
    graph.add_node("security_assurance", _security_assurance_node_factory(llm_client, llm_passes=llm_passes))
    graph.add_node("operations_continuity", _operations_continuity_node_factory(llm_client, llm_passes=llm_passes))
    graph.add_node("meta_adjudication", _meta_adjudication_node_factory(llm_client, meta_llm_enabled=meta_llm_enabled))

    # True fan-out/fan-in topology: both branches operate from the same input packet,
    # then meta-adjudication runs after both branch outputs are available.
    graph.add_edge(START, "security_assurance")
    graph.add_edge(START, "operations_continuity")
    graph.add_edge("security_assurance", "meta_adjudication")
    graph.add_edge("operations_continuity", "meta_adjudication")
    graph.add_edge("meta_adjudication", END)
    return graph.compile()


def run_contested_orchestration(
    integrated_packets_path: Path,
    output_dir: Path,
    hitl_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    write_suffix: str = "",
    llm_enabled: bool = False,
    model: str = "gpt-4o-mini",
    llm_passes: int = 1,
    meta_llm_enabled: bool = False,
) -> Dict[str, Any]:
    packets = _read_jsonl(integrated_packets_path)
    app = build_contested_graph(
        llm_enabled=llm_enabled,
        model=model,
        output_dir=output_dir,
        llm_passes=llm_passes,
        meta_llm_enabled=meta_llm_enabled,
    )
    hitl_overrides = hitl_overrides or {}

    branch_rows: List[Dict[str, Any]] = []
    meta_rows: List[Dict[str, Any]] = []
    responsibility_rows: List[Dict[str, Any]] = []

    for p in packets:
        final_state = app.invoke({"packet": p})
        sec = dict(final_state["security_branch"])
        ops = dict(final_state["operations_branch"])
        meta = dict(final_state["meta_decision"])

        branch_rows.extend([sec, ops])

        incident_id = str(p.get("incident_id"))
        if incident_id in hitl_overrides:
            override = hitl_overrides[incident_id]
            selected_branch = override.get("selected_branch", meta["selected_branch"])
            operator_id = override.get("operator_id", "human_operator")
            reason = override.get("reason", "HITL override applied.")
            policy_passed = bool(meta.get("cross_constraint_checks", {}).get("policy_passed", False))

            if not policy_passed:
                # Safety gate: block HITL branch override on policy-failing incidents.
                meta["hitl_override"] = {
                    "applied": False,
                    "blocked_by_policy_gate": True,
                    "operator_id": operator_id,
                    "requested_selected_branch": selected_branch,
                    "reason": reason,
                    "timestamp_utc": _now_utc(),
                }
            else:
                if selected_branch == "operations_continuity":
                    selected_packet = ops
                else:
                    selected_branch = "security_assurance"
                    selected_packet = sec

                meta["hitl_override"] = {
                    "applied": True,
                    "blocked_by_policy_gate": False,
                    "operator_id": operator_id,
                    "selected_branch": selected_branch,
                    "reason": reason,
                    "timestamp_utc": _now_utc(),
                }
                meta["selected_branch"] = selected_branch
                meta["final_recommendation"] = _enforce_policy_gate(
                    policy_passed,
                    str(selected_packet.get("branch_recommendation")),
                )
        else:
            meta["hitl_override"] = {"applied": False, "blocked_by_policy_gate": False}

        responsibility_rows.extend(sec.get("responsibility_log", []))
        responsibility_rows.extend(ops.get("responsibility_log", []))
        responsibility_rows.extend(meta.get("responsibility_log", []))
        meta_rows.append(meta)

    suffix = f"_{write_suffix.strip('_')}" if write_suffix.strip("_") else ""
    _write_jsonl(output_dir / f"branch_packets{suffix}.jsonl", branch_rows)
    _write_jsonl(output_dir / f"meta_decisions{suffix}.jsonl", meta_rows)
    _write_jsonl(output_dir / f"responsibility_log{suffix}.jsonl", responsibility_rows)

    disagreement_rate = float(
        np.mean([m["disagreement_flags"]["recommendation_disagreement"] for m in meta_rows])
    ) if meta_rows else 0.0
    hitl_required_rate = float(np.mean([m["hitl_required"] for m in meta_rows])) if meta_rows else 0.0
    override_rate = float(np.mean([m["hitl_override"]["applied"] for m in meta_rows])) if meta_rows else 0.0
    policy_gate_violations = int(
        sum(
            1
            for m in meta_rows
            if (not bool(m.get("cross_constraint_checks", {}).get("policy_passed", False)))
            and str(m.get("final_recommendation")) != "escalate"
        )
    )
    blocked_override_rate = float(
        np.mean([bool(m.get("hitl_override", {}).get("blocked_by_policy_gate", False)) for m in meta_rows])
    ) if meta_rows else 0.0

    summary = {
        "incident_count": len(meta_rows),
        "branch_row_count": len(branch_rows),
        "disagreement_rate": round(disagreement_rate, 4),
        "hitl_required_rate": round(hitl_required_rate, 4),
        "hitl_override_rate": round(override_rate, 4),
        "selected_branch_distribution": {
            "security_assurance": int(sum(1 for m in meta_rows if m["selected_branch"] == "security_assurance")),
            "operations_continuity": int(sum(1 for m in meta_rows if m["selected_branch"] == "operations_continuity")),
        },
        "llm_enabled": bool(llm_enabled),
        "model": model,
        "llm_passes": int(max(1, llm_passes)),
        "meta_llm_enabled": bool(meta_llm_enabled),
        "policy_gate_invariant_violations": int(policy_gate_violations),
        "blocked_override_rate": round(blocked_override_rate, 4),
    }
    (output_dir / f"meta_summary{suffix}.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "branch_packets": branch_rows,
        "meta_decisions": meta_rows,
        "responsibility_log": responsibility_rows,
        "summary": summary,
    }
