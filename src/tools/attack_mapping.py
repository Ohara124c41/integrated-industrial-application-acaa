from __future__ import annotations

from typing import Dict, List

_TAG_TO_TECHNIQUE = {
    "possible_c2": ("T1071", "Application Layer Protocol", 0.74),
    "egress_spike": ("T1048", "Exfiltration Over Alternative Protocol", 0.71),
    "credential_anomaly": ("T1078", "Valid Accounts", 0.66),
    "lateral_movement": ("T1021", "Remote Services", 0.69),
    "service_abuse": ("T1569", "System Services", 0.58),
    "policy_tamper": ("T1562", "Impair Defenses", 0.61),
}


def map_to_attack_techniques(evidence_bundle: List[Dict], anomaly_tags: List[str]) -> List[Dict]:
    evidence_ids = [str(x.get("evidence_id", "UNK")) for x in evidence_bundle]
    results: List[Dict] = []
    seen = set()
    for tag in anomaly_tags:
        if tag in _TAG_TO_TECHNIQUE:
            tid, name, conf = _TAG_TO_TECHNIQUE[tag]
            if tid in seen:
                continue
            seen.add(tid)
            results.append(
                {
                    "technique_id": tid,
                    "technique_name": name,
                    "confidence": float(conf),
                    "evidence_ids": evidence_ids[:3],
                }
            )
    return sorted(results, key=lambda x: x["confidence"], reverse=True)

