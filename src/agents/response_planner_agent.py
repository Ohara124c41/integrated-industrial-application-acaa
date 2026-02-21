from __future__ import annotations

from src.schemas import ActionProposal, IncidentState, Stage


class ResponsePlannerAgent:
    name = "response_planner"

    def process(self, state: IncidentState) -> IncidentState:
        state.stage = Stage.RESPONSE

        actions = []
        if state.severity in {"critical", "high"}:
            actions.append(ActionProposal("increase_logging", state.asset_id, "Increase observability for short-window verification."))
            actions.append(ActionProposal("isolate_segment", state.asset_id, "Contain potential spread while investigation continues."))
            actions.append(ActionProposal("manual_investigation", state.asset_id, "Escalate to analyst for immediate review."))
        elif state.severity == "medium":
            actions.append(ActionProposal("increase_logging", state.asset_id, "Collect additional evidence before enforcement."))
            actions.append(ActionProposal("request_patch_window", state.asset_id, "Plan controlled remediation with operations."))
        else:
            actions.append(ActionProposal("monitor", state.asset_id, "Continue monitoring due to low-confidence low-severity signal."))

        state.proposed_actions = actions
        state.add_log("info", "Response plan drafted", action_count=len(actions), severity=state.severity)
        return state

