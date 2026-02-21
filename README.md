# Integrative Industry Synthesis

## Assurance-Centered Agentic AIOps: Parallel Contested Orchestration for Industrial DevSecAIOps
This project implements a new integrated DevSecAIOps synthesis artifact for local-cloud IIoT/OT operations by combining outputs and methods from P3, P4, P5, and P6.

Project repository: https://github.com/Ohara124c41/integrated-industrial-application-acaa

## Integrated components
- `P3`: vulnerability prior context (KEV/NVD signals)
- `P4`: telemetry risk profile and deep-model-derived prevalence context
- `P5`: generated RCA narratives with quality/safety tags
- `P6`: policy-gated multi-agent decision orchestration

## Core files
- `integrated_system.ipynb`: notebook for system execution, EDA/statistics, dimensional analysis, governance checks, and fairness screening
- `local_cloud_plugin_architecture.ipynb`: thesis-extension notebook for local-cloud plugin orchestration, storage materialization, and failure drills
- `integration_runtime.py`: integration backend that builds unified packets and evaluation outputs
- `contested_orchestration.py`: LangChain + LangGraph dual-branch orchestration and meta-adjudication with optional HITL overrides
- `local_cloud/`: plugin contracts, registry, runtime, and plugin modules for local-cloud control-plane emulation
- `data/contracts/*.json`: explicit interface contracts
- `diagrams/system_architecture.md`: architecture flow
- `diagrams/threat_model.md`: threat model
- `outputs/`: generated integrated artifacts

## Run order
1. Confirm upstream artifacts exist in `P3/`, `P4/`, `P5/`, and `P6/`.
2. Run notebook: `integrated_system.ipynb` (recommended).
3. Or run backend directly:
```bash
python integration_runtime.py --output-dir outputs
python integration_runtime.py --output-dir outputs --agentic-compare --model gpt-4o-mini
```

## Generated outputs
- `outputs/integrated_packets.jsonl`
- `outputs/system_summary.json`
- `outputs/failure_cases.json`
- `outputs/branch_packets.jsonl`
- `outputs/meta_decisions.jsonl`
- `outputs/meta_summary.json`
- `outputs/responsibility_log.jsonl`
- `outputs/local_cloud_summary.json`
- `outputs/meta_decisions_local_cloud.jsonl`
- `outputs/local_cloud_packets.db`
- `outputs/local_cloud_packets.parquet` (optional, if parquet engine available)

## Contested orchestration controls
- `P7_CONTESTED_LLM=1` enables LLM enrichment for branch rationale text.
- `P7_CONTESTED_MODEL=gpt-4o-mini` sets the branch-enrichment model name.
- `P7_CONTESTED_LLM_PASSES=2` controls multi-pass branch refinement depth (more calls, richer rationale notes).
- `P7_CONTESTED_META_LLM=1` enables a meta-level advisory LLM note per incident while keeping deterministic selection gates.
- Meta-selection remains policy-constrained even when branch text is LLM-enriched.
- Hard safety invariant: policy-failing incidents are forced to `final_recommendation='escalate'`.
- HITL overrides are allowed only within policy bounds; blocked override attempts are logged in `meta_decisions*.jsonl`.

## Notes
- This artifact is intentionally integration-focused and policy-first.
- It reuses prior validated modules and adds a new synthesis/evaluation layer with governance and audit emphasis.
- The `local_cloud_plugin_architecture.ipynb` notebook is thesis-oriented and can be cited as architecture-extension evidence without changing capstone submission scope.
