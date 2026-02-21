from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from ..base import PluginBase


class StoragePlugin(PluginBase):
    name = "storage"
    depends_on = ["ingest", "risk", "governance"]

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        output_dir = Path(context["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)

        df: pd.DataFrame = context["packets_df"].copy()

        # Normalize list-like fields to strings for SQL storage.
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].astype(str)

        db_path = output_dir / "local_cloud_packets.db"
        conn = sqlite3.connect(db_path)
        df.to_sql("integrated_packets", conn, if_exists="replace", index=False)
        agg = pd.read_sql_query(
            "SELECT zone, decision_type, COUNT(*) AS n "
            "FROM integrated_packets GROUP BY zone, decision_type ORDER BY zone, decision_type",
            conn,
        )
        conn.close()

        parquet_path = output_dir / "local_cloud_packets.parquet"
        parquet_written = False
        parquet_error = ""
        try:
            df.to_parquet(parquet_path, index=False)
            parquet_written = True
        except Exception as exc:  # pragma: no cover
            parquet_error = str(exc)

        return {
            "storage_zone_decision_counts": agg,
            "storage_summary": {
                "sqlite_path": str(db_path),
                "parquet_path": str(parquet_path),
                "parquet_written": bool(parquet_written),
                "parquet_error": parquet_error,
            },
        }

