from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def write_audit_event(output_dir: Path, incident_id: str, stage: str, event_type: str, detail: Dict[str, Any]) -> str:
    trace_id = f"{incident_id}:{stage}:{event_type}:{int(datetime.now(timezone.utc).timestamp())}"
    payload = {
        "ts": _utc_now(),
        "trace_id": trace_id,
        "incident_id": incident_id,
        "stage": stage,
        "event_type": event_type,
        "detail": detail,
    }
    append_jsonl(output_dir / "audit_log.jsonl", payload)
    return trace_id

