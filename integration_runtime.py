from __future__ import annotations

import argparse
import ast
import json
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd


class SourcePaths:
    def __init__(
        self,
        *,
        p3_csv: Path,
        p4_npz: Path,
        p4_meta: Path,
        p5_csv: Path,
        p6_packets: Path,
        p6_summary: Path,
    ) -> None:
        self.p3_csv = p3_csv
        self.p4_npz = p4_npz
        self.p4_meta = p4_meta
        self.p5_csv = p5_csv
        self.p6_packets = p6_packets
        self.p6_summary = p6_summary


def project_root() -> Path:
    return Path(__file__).resolve().parent


def load_local_env() -> None:
    env_path = project_root() / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv

        load_dotenv(env_path, override=False)
    except Exception:
        return


def default_paths() -> SourcePaths:
    root = project_root().parent
    return SourcePaths(
        p3_csv=root / "P3" / "data" / "processed" / "nvd_kev_model_data.csv",
        p4_npz=root / "P4" / "data" / "processed" / "rtiot2022_binary_rs42_n120000_split_arrays.npz",
        p4_meta=root / "P4" / "data" / "processed" / "rtiot2022_binary_rs42_n120000_metadata.json",
        p5_csv=root / "P5" / "data" / "processed" / "p5_generated_rca_artifacts.csv",
        p6_packets=root / "P6" / "outputs" / "decision_packets.jsonl",
        p6_summary=root / "P6" / "outputs" / "run_summary.json",
    )


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _require(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing required artifact: {path}")


def load_vulnerability_prior(p3_csv: Path) -> Dict[str, Any]:
    df = pd.read_csv(p3_csv)
    kev_rate = float(df["in_kev"].mean()) if "in_kev" in df else float("nan")
    cvss_mean = float(df["cvss_base_score"].mean()) if "cvss_base_score" in df else float("nan")
    cvss_p75 = float(df["cvss_base_score"].quantile(0.75)) if "cvss_base_score" in df else float("nan")
    top_vectors: Dict[str, int] = {}
    if "attack_vector" in df:
        top_vectors = (
            df["attack_vector"]
            .fillna("UNKNOWN")
            .astype(str)
            .value_counts()
            .head(5)
            .to_dict()
        )
    return {
        "rows": int(len(df)),
        "kev_rate": round(kev_rate, 4),
        "cvss_mean": round(cvss_mean, 4),
        "cvss_p75": round(cvss_p75, 4),
        "top_attack_vectors": top_vectors,
    }


def load_telemetry_profile(p4_npz: Path, p4_meta: Path) -> Dict[str, Any]:
    arr = np.load(p4_npz, allow_pickle=True)
    y_train = arr["y_train"]
    y_val = arr["y_val"]
    y_test = arr["y_test"]
    prevalence = float(np.mean(np.concatenate([y_train, y_val, y_test])))
    with p4_meta.open("r", encoding="utf-8") as f:
        meta = json.load(f)
    cat_field = meta.get("cat_features", [])
    if isinstance(cat_field, int):
        cat_repr: Any = int(cat_field)
    else:
        cat_repr = list(cat_field)
    return {
        "rows_total": int(y_train.shape[0] + y_val.shape[0] + y_test.shape[0]),
        "attack_prevalence": round(prevalence, 4),
        "num_features": int(meta.get("num_features", len(arr["X_train_num"][0]))),
        "cat_features": cat_repr,
    }


def load_generated_rca(p5_csv: Path) -> pd.DataFrame:
    df = pd.read_csv(p5_csv)
    keep = [
        "incident_id",
        "generation_id",
        "generated_summary",
        "rca_hypothesis",
        "quality_flags",
        "safety_flags",
        "failure_mode_tags",
        "model_version",
        "selected_model_name",
        "run_id",
    ]
    return df[[c for c in keep if c in df.columns]].copy()


def load_agentic_outputs(packets_path: Path, summary_path: Path) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    packets = _read_jsonl(packets_path)
    with summary_path.open("r", encoding="utf-8") as f:
        summary = json.load(f)
    return packets, summary


def _cmmc_map(packet: Dict[str, Any]) -> List[str]:
    mapped: List[str] = []
    if packet.get("policy_passed") is False:
        mapped.append("CA.L2-3.12.1")
        mapped.append("IR.L2-3.6.1")
    if packet.get("decision_type") in {"escalate", "refuse"}:
        mapped.append("IR.L2-3.6.2")
    if packet.get("audit_trace_ids"):
        mapped.append("AU.L2-3.3.1")
    return sorted(set(mapped))


def _parse_listlike(value: Any) -> Any:
    """Normalize list-like strings from CSV exports into Python lists."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                return value
    return value


def _clean_control_refs(items: Any) -> List[str]:
    out: List[str] = []
    if isinstance(items, list):
        for x in items:
            xs = str(x).strip()
            if xs:
                out.append(xs)
    return out


def build_integrated_packets(
    packets: List[Dict[str, Any]],
    generated_df: pd.DataFrame,
    vuln_prior: Dict[str, Any],
    telemetry_profile: Dict[str, Any],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if generated_df.empty:
        raise ValueError("Generated RCA dataframe is empty.")

    for idx, p in enumerate(packets):
        gen = generated_df.iloc[idx % len(generated_df)]
        nist_refs_raw = [
            str(x.get("csf_ref") or x.get("control") or "").strip()
            for x in p.get("nist_findings", [])
            if isinstance(x, dict)
        ]
        iec_refs_raw = [str(x.get("control", "")) for x in p.get("iec_findings", []) if isinstance(x, dict)]
        nist_refs = _clean_control_refs(nist_refs_raw)
        iec_refs = _clean_control_refs(iec_refs_raw)

        gen_quality_flags = _parse_listlike(gen.get("quality_flags", []))
        gen_safety_flags = _parse_listlike(gen.get("safety_flags", []))
        gen_failure_mode_tags = _parse_listlike(gen.get("failure_mode_tags", []))
        row = {
            "incident_id": p.get("incident_id"),
            "scenario_id": p.get("scenario_id"),
            "zone": p.get("zone"),
            "decision_type": p.get("decision_type"),
            "policy_passed": bool(p.get("policy_passed", False)),
            "escalation_required": bool(p.get("escalation_required", False)),
            "risk_score_agentic": float(p.get("risk_score", 0.0)),
            "evidence_quality": float(p.get("evidence_quality", 0.0)),
            "hypothesis_confidence": float(p.get("selected_hypothesis_confidence", 0.0)),
            "attack_technique_count": int(len(p.get("attack_techniques", []))),
            "attack_techniques": [a.get("technique_id") for a in p.get("attack_techniques", []) if isinstance(a, dict)],
            "vuln_kev_rate": vuln_prior["kev_rate"],
            "vuln_cvss_mean": vuln_prior["cvss_mean"],
            "telemetry_attack_prevalence": telemetry_profile["attack_prevalence"],
            "gen_incident_id": gen.get("incident_id"),
            "gen_generation_id": gen.get("generation_id"),
            "gen_summary": str(gen.get("generated_summary", "")),
            "gen_hypothesis": str(gen.get("rca_hypothesis", "")),
            "gen_quality_flags": gen_quality_flags,
            "gen_safety_flags": gen_safety_flags,
            "gen_failure_mode_tags": gen_failure_mode_tags,
            "framework_nist_refs": nist_refs,
            "framework_iec_refs": iec_refs,
            "framework_cmmc_refs": _cmmc_map(p),
            "integration_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        out.append(row)
    return out


def summarize_integrated(packets: List[Dict[str, Any]], p6_summary: Dict[str, Any]) -> Dict[str, Any]:
    df = pd.DataFrame(packets)
    total = len(df)
    decision_dist = df["decision_type"].value_counts(dropna=False).to_dict() if total else {}
    return {
        "run_count": int(total),
        "decision_distribution": decision_dist,
        "packet_completeness_rate": float(
            np.mean(df[["incident_id", "decision_type", "gen_hypothesis"]].notna().all(axis=1))
        )
        if total
        else 0.0,
        "policy_pass_rate": float(df["policy_passed"].mean()) if total else 0.0,
        "escalation_rate": float(df["escalation_required"].mean()) if total else 0.0,
        "mean_hypothesis_confidence": float(df["hypothesis_confidence"].mean()) if total else 0.0,
        "mean_attack_technique_count": float(df["attack_technique_count"].mean()) if total else 0.0,
        "zones": sorted([z for z in df["zone"].dropna().unique().tolist()]),
        "source_run_summary": p6_summary,
    }


def failure_cases(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in packets:
        reasons: List[str] = []
        if p["decision_type"] in {"refuse", "defer"}:
            reasons.append("high_safety_path")
        if not p["policy_passed"]:
            reasons.append("policy_failed")
        if p["hypothesis_confidence"] < 0.70:
            reasons.append("low_confidence")
        if "low_semantic_specificity" in p["gen_failure_mode_tags"]:
            reasons.append("weak_rca_specificity")
        if reasons:
            out.append(
                {
                    "incident_id": p["incident_id"],
                    "decision_type": p["decision_type"],
                    "reasons": sorted(set(reasons)),
                }
            )
    return out


def run_integration(output_dir: Path, paths: SourcePaths) -> Dict[str, Any]:
    for p in [paths.p3_csv, paths.p4_npz, paths.p4_meta, paths.p5_csv, paths.p6_packets, paths.p6_summary]:
        _require(p)

    vuln_prior = load_vulnerability_prior(paths.p3_csv)
    telemetry_profile = load_telemetry_profile(paths.p4_npz, paths.p4_meta)
    generated_df = load_generated_rca(paths.p5_csv)
    packets, p6_summary = load_agentic_outputs(paths.p6_packets, paths.p6_summary)
    integrated = build_integrated_packets(packets, generated_df, vuln_prior, telemetry_profile)
    summary = summarize_integrated(integrated, p6_summary)
    failures = failure_cases(integrated)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "integrated_packets.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in integrated) + "\n",
        encoding="utf-8",
    )
    (output_dir / "system_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "failure_cases.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def _text_diversity(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    texts = [str(r.get("selected_hypothesis", "")).strip() for r in rows]
    texts = [t for t in texts if t]
    n = len(texts)
    if n <= 1:
        return {"count": n, "unique_ratio": 1.0 if n == 1 else 0.0, "mean_pairwise_similarity": None}
    sims = []
    for i in range(n):
        for j in range(i + 1, n):
            sims.append(SequenceMatcher(None, texts[i], texts[j]).ratio())
    return {
        "count": n,
        "unique_ratio": round(len(set(texts)) / n, 4),
        "mean_pairwise_similarity": round(float(np.mean(sims)), 4),
        "max_pairwise_similarity": round(float(np.max(sims)), 4),
        "min_pairwise_similarity": round(float(np.min(sims)), 4),
    }


def run_agentic_comparison(output_dir: Path, model: str = "gpt-4o-mini") -> Dict[str, Any]:
    from src.orchestrator import AgenticOrchestrator
    from src.tools import list_scenarios

    incidents = list_scenarios()
    det_dir = output_dir / "agent_det"
    llm_dir = output_dir / "agent_llm"
    det_dir.mkdir(parents=True, exist_ok=True)
    llm_dir.mkdir(parents=True, exist_ok=True)

    det = AgenticOrchestrator(output_dir=det_dir, use_llm=False, model=model).run_many(incidents)
    llm = AgenticOrchestrator(output_dir=llm_dir, use_llm=True, model=model).run_many(incidents)

    det_idx = {r["incident_id"]: r for r in det}
    llm_idx = {r["incident_id"]: r for r in llm}
    common_ids = sorted(set(det_idx) & set(llm_idx))

    deltas = []
    for iid in common_ids:
        d = det_idx[iid]
        l = llm_idx[iid]
        deltas.append(
            {
                "incident_id": iid,
                "det_decision_type": d.get("decision_type"),
                "llm_decision_type": l.get("decision_type"),
                "decision_changed": d.get("decision_type") != l.get("decision_type"),
                "det_policy_passed": d.get("policy_passed"),
                "llm_policy_passed": l.get("policy_passed"),
                "policy_changed": d.get("policy_passed") != l.get("policy_passed"),
                "det_conf": float(d.get("selected_hypothesis_confidence", 0.0)),
                "llm_conf": float(l.get("selected_hypothesis_confidence", 0.0)),
                "conf_changed": float(d.get("selected_hypothesis_confidence", 0.0))
                != float(l.get("selected_hypothesis_confidence", 0.0)),
            }
        )

    comparison = {
        "incident_count": len(common_ids),
        "model": model,
        "decision_change_rate": float(np.mean([x["decision_changed"] for x in deltas])) if deltas else 0.0,
        "policy_change_rate": float(np.mean([x["policy_changed"] for x in deltas])) if deltas else 0.0,
        "confidence_change_rate": float(np.mean([x["conf_changed"] for x in deltas])) if deltas else 0.0,
        "det_text_diversity": _text_diversity(det),
        "llm_text_diversity": _text_diversity(llm),
        "deltas": deltas,
    }
    (output_dir / "agentic_comparison.json").write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return comparison


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Integrated industry synthesis runtime")
    p.add_argument("--output-dir", default="outputs", help="Output directory")
    p.add_argument("--agentic-compare", action="store_true", help="Run deterministic vs LLM agentic comparison")
    p.add_argument("--model", default="gpt-4o-mini", help="Model name for llm-enabled comparison mode")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    root = project_root()
    load_local_env()
    summary = run_integration(root / args.output_dir, default_paths())
    print(json.dumps(summary, indent=2))
    if args.agentic_compare:
        cmp_out = run_agentic_comparison(root / args.output_dir, model=args.model)
        print(json.dumps(cmp_out, indent=2))
