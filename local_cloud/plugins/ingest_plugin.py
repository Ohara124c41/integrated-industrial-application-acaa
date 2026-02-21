from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from ..base import PluginBase


class IngestPlugin(PluginBase):
    name = "ingest"
    depends_on = []

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        packets_path = Path(context["integrated_packets_path"])
        rows = [json.loads(line) for line in packets_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        df = pd.DataFrame(rows)
        return {
            "packets_df": df,
            "ingest_summary": {
                "packet_count": int(len(df)),
                "column_count": int(df.shape[1]),
                "packets_path": str(packets_path),
            },
        }

