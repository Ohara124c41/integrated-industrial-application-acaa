from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def _data_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "scenarios.json"


def _load_scenarios() -> Dict[str, Dict[str, Any]]:
    with _data_path().open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def list_scenarios() -> List[str]:
    return sorted(_load_scenarios().keys())


def get_incident_context(incident_id: str) -> Dict[str, Any]:
    scenarios = _load_scenarios()
    if incident_id not in scenarios:
        raise KeyError(f"Unknown incident_id: {incident_id}")
    s = scenarios[incident_id]
    return {
        "incident_id": incident_id,
        "scenario_id": s["scenario_id"],
        "incident_text": s["incident_text"],
        "telemetry_excerpt_ids": s.get("telemetry_excerpt_ids", []),
        "known_constraints": s.get("known_constraints", {}),
        "asset_id": s.get("asset_id", "ASSET_UNKNOWN"),
        "threat_model": s.get("threat_model", {}),
        "evidence_bundle": s.get("evidence_bundle", []),
    }


def get_local_risk_features(incident_id: str) -> Dict[str, Any]:
    scenarios = _load_scenarios()
    if incident_id not in scenarios:
        raise KeyError(f"Unknown incident_id: {incident_id}")
    s = scenarios[incident_id]
    features = s.get("severity_signals", {}).copy()
    features["anomaly_tags"] = s.get("anomaly_tags", [])
    features["confidence_hint"] = s.get("confidence_hint", 0.5)
    return features

