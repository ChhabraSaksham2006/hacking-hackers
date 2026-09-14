# Repository Cleanup Inventory

## Classification Key
- **A — Final/Authoritative:** Keep, do not modify
- **B — Research Evidence:** Keep (experimental proof)
- **C — Historical Important:** Keep (scientific precedent)
- **D — Obsolete/Safe to Remove:** Can be deleted
- **E — Temporary/Junk:** Should be removed

---

## SOURCE CODE

| Classification | Path | Reason |
|---------------|------|--------|
| A | `src/models/sparse_rssm.py` | Final production model architecture |
| A | `src/temporal/state_aggregator.py` | Canonical 54-D state definitions |
| A | `src/temporal/dataset_builder.py` | Authoritative dataset pipeline |
| A | `src/training/trainer.py` | Training loop (used by all phases) |
| A | `src/evaluation/metrics.py` | Evaluation metrics |
| A | `src/models/baselines/` | All 5 baseline implementations |
| C | `src/world_model.py` | Phase 1 LSTM (historical) |
| C | `src/build_dataset.py` | Phase 1 DARPA+CIC pipeline (historical) |
| C | `src/inference_engine.py`, `src/inference_stream.py`, `src/inference_batch.py` | Phase 4.5 inference code |
| C | `src/temporal_aggregator.py` | Pre-Phase-3 aggregator (superseded) |
| C | `src/train_*.py` (4 files) | Historical training scripts |
| C | `src/mitre_mapping.py` | Phase 4.5 MITRE mapping (superseded by Phase 7) |
| D | `src/__pycache__/`, `src/**/__pycache__/` | Python cache — safe to remove (auto-regenerated) |

---

## SCRIPTS

| Classification | Path | Reason |
|---------------|------|--------|
| A | `scripts/phase_7/run_phase_7.py` | Phase 7 master pipeline |
| A | `scripts/phase_6/run_phase_6.py` | Phase 6 master pipeline |
| A | `scripts/phase_5_5/run_phase_5_5.py` | Phase 5.5 master pipeline |
| A | `scripts/preprocessing/build_temporal_states.py` | State generation pipeline |
| A | `scripts/verification/verify_temporal_states.py` | Verification |
| B | `scripts/experiments/run_baseline_suite.py` | Phase 4 baseline experiments |
| B | `scripts/experiments/run_sparse_rssm.py` | Phase 5 RSSM experiments |
| C | `scripts/audit/` | Phase 4.5 audit scripts (all 8 files) |
| C | `scripts/experiments/` (remaining ~12 files) | Phase 4–5 experiment scripts |
| C | `scripts/gen_*.py` (8 files) | Phase 4 report generation |
| D | `scripts/phase_6/__pycache__/` | Python cache |
| D | `reports/phase_7.zip` | Untracked zip archive (redundant — reports exist in reports/phase_7/) |

---

## REPORTS

| Classification | Path | Reason |
|---------------|------|--------|
| A | `reports/phase_7/` (12 files) | Phase 7 authoritative reports |
| A | `reports/phase_6/` (3 files) | Phase 6 authoritative reports |
| A | `reports/phase_5_5/` (10 files + configs) | Phase 5.5 authoritative reports |
| B | `reports/temporal_audit/` (10 files) | Phase 3C forensic audit |
| B | `reports/temporal_design/` (4 files) | Phase 3A design reports |
| B | `reports/temporal_states/` (2 files) | Phase 3A verification |
| B | `reports/final_audit/` (26 files) | Phase 4.5 forensic audit |
| B | `reports/phase_4_5/` (27 files) | Phase 4.5 results reports |
| B | `reports/phase_5/` (16 files) | Phase 5 results (INVALIDATED, but evidence) |
| C | `reports/baselines/` | Phase 4 baseline reports |
| C | `reports/dataset_selection/` | Dataset selection documentation |
| C | `reports/data_pipeline/` | Data pipeline documentation |
| D | `reports/phase_7.zip` | Redundant zip |

---

## ARTIFACTS

| Classification | Path | Reason |
|---------------|------|--------|
| A | `artifacts/phase7/` (6 files) | FINAL production artifacts |
| B | `artifacts/phase6_onset/` (4 files) | Phase 6 champion artifacts |
| B | `artifacts/rssm/` (5 files) | Phase 5.5 champion artifacts |

---

## RESULTS (Raw Experimental Data)

| Classification | Path | Reason |
|---------------|------|--------|
| B | `results_phase5_5/` (13 directories, 26 files) | Phase 5.5 checkpoints + test outputs |
| C | `results_phase5/` (9 directories, 20 files) | Phase 5 checkpoints (INVALIDATED but traceable) |
| C | `legacy/results_selected_benchmark/` | Phase 4 benchmark results |
| C | `legacy/results_final_selected_k/` | Phase 5 long-horizon results |
| C | `legacy/results_history_conditioned/` | Phase 5 history-conditioned experiment |
| C | `legacy/results_rf_rssm_k200/` | Phase 5 RF-RSSM hybrid |
| C | `legacy/results_rssm_rf_k100/` | Phase 5 RSSM-RF hybrid |
| C | `legacy/results_rssm_rf_k100_valthreshold/` | Phase 5 hybrid variant |

---

## DATA

| Classification | Path | Reason |
|---------------|------|--------|
| A | `data/processed/temporal_states/*.parquet` (9 files) | Canonical 54-D state files — authoritative |

---

## TESTS

| Classification | Path | Reason |
|---------------|------|--------|
| A | `tests/test_phase7_artifacts.py` | Phase 7 artifact smoke test (PASSED) |

---

## DOCUMENTATION

| Classification | Path | Reason |
|---------------|------|--------|
| A | `docs/FINAL_RESEARCH_SUMMARY.md` | Created this session |
| A | `docs/flow/README.md` + 9 phase files | Created this session |
| A | `deployment/README.md`, `MODEL_CARD.md`, etc. | Created this session |

---

## DEPLOYMENT

| Classification | Path | Reason |
|---------------|------|--------|
| A | `deployment/` (all 12 files) | Production-ready deployment package |

---

## CLEANUP ACTIONS PERFORMED

1. ✅ No files deleted — all classified files are either A/B/C (scientifically valuable)
2. ✅ `__pycache__` directories are gitignored — no action needed (not tracked)
3. ✅ `reports/phase_7.zip` — Untracked, redundant. **Proposed: DELETE.**
   - Reason: Content already exists in `reports/phase_7/` (tracked directory)
   - Will not delete without explicit confirmation

---

## PROPOSED DELETIONS (Awaiting Confirmation)

| File | Reason | Impact |
|------|--------|--------|
| `reports/phase_7.zip` | Untracked zip, identical content in `reports/phase_7/` | Zero loss |

No other deletions are proposed. All other files contain scientific evidence.
