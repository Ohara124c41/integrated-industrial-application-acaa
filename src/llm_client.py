from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from openai import OpenAI

from utils import get_voc_creds


class VocareumLLMClient:
    def __init__(self, enabled: bool = False, model: str = "gpt-4o-mini", output_dir: Optional[Path] = None) -> None:
        self.enabled = enabled
        self.model = model
        self.output_dir = output_dir
        self.client: Optional[OpenAI] = None
        self.init_error: Optional[str] = None

        if not enabled:
            return

        try:
            api_key, base_url = get_voc_creds()
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        except Exception as exc:
            # Stay in deterministic fallback mode.
            self.client = None
            self.enabled = False
            self.init_error = str(exc)

    def available(self) -> bool:
        return bool(self.enabled and self.client is not None)

    def debug_status(self) -> dict:
        return {
            "enabled": bool(self.enabled),
            "client_initialized": bool(self.client is not None),
            "model": self.model,
            "init_error": self.init_error,
        }

    def _log_call(self, payload: dict) -> None:
        if not self.output_dir:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)
        p = self.output_dir / "llm_calls.jsonl"
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def enrich_hypothesis(self, incident_text: str, hypothesis: str, incident_id: Optional[str] = None) -> str:
        if not self.available():
            return hypothesis

        prompt = (
            "You are a defensive SOC assistant. Refine this RCA hypothesis in 1-2 lines, "
            "keep uncertainty explicit, no offensive guidance.\n\n"
            f"Incident: {incident_text}\n"
            f"Hypothesis: {hypothesis}"
        )

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Defensive cybersecurity analyst assistant."},
                    {"role": "user", "content": prompt},
                ],
                temperature=float(os.getenv("P6_LLM_TEMPERATURE", "0.1")),
                max_tokens=180,
            )
            out = (resp.choices[0].message.content or "").strip() or hypothesis
            self._log_call(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "incident_id": incident_id,
                    "model": self.model,
                    "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                    "prompt_preview": prompt[:280],
                    "response_preview": out[:280],
                    "used_vocareum": True,
                }
            )
            return out
        except Exception as exc:
            self._log_call(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "incident_id": incident_id,
                    "model": self.model,
                    "event": "llm_error_fallback",
                    "error": str(exc),
                    "used_vocareum": bool(self.available()),
                }
            )
            return hypothesis
