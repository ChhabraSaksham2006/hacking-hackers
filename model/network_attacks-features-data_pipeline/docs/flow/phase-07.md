# Phase 7 — Operational Early-Warning Optimization & Behavioral Attribution

## 1. Phase Identifier
Phase 7 | Commit: `d2c7da5` | Branch: `features/data_pipeline` (FINAL COMMIT)

## 2. Objective
1. Reduce false alarms from 1,101 FA/hr (Phase 6 raw) to operationally acceptable levels through temporal aggregation strategies.
2. Build a deterministic behavioral attribution layer that maps forecasted physical state changes to MITRE ATT&CK technique candidates.
3. Export a production-ready deployable artifact package.

## 3. Dataset
Same as Phase 6:
- Train: 89,027 pure-benign sequences | Val: 18,658 | Test: 45,530
- Test episodes: 7 (4 Infiltration, 3 Botnet — fully OOD)
- No model retraining — Phase 7 uses Phase 6 champion model (E602_10x, seed=42)

## 4. Input Features
54-D temporal state. P=10 lookback. Pure-benign history only (identical to Phase 6).

## 5. Model Architecture
SparseRSSM (Phase 7 final — inspected from `artifacts/phase7/config.json`):
- `architecture: SparseRSSM`
- `hidden_dim: 64` (Note: config.json reports 64, model was instantiated from Phase 6)
- `latent_dim: 128` (Phase 5.5 specification)
- `sparsity_ratio: 1.0` (dense — all units active)
- `state_dim: 54`
- `K: 10` (20-second forecast horizon)
- **Operational aggregation: 2-Consecutive + 60s cooldown (champion)**
- **Raw detection threshold: 0.04** (calibrated on validation)

## 6. Experiments Run

### A. Operating Point Analysis (9 calibrated thresholds)
From `reports/phase_7/02_operating_point_results.csv`:
- Max F1 threshold = 0.04 → Event Recall=100% (7/7), FPR=60.96%, FA/hr=1,095.93
- FPR-constrained (≤2%, ≤5%, ≤10%) → threshold=0.99 → **ZERO recall** (threshold too aggressive for fine-grained precursor signals)

### B. Alert Aggregation Strategies (17 configurations)
From `reports/phase_7/04_alert_aggregation_results.csv`:

| Aggregation Strategy | Event Recall | Events | FA/hr | FPR | Median Lead |
|---------------------|-------------|--------|-------|-----|------------|
| None (raw threshold 0.04) | 100.0% | 7/7 | 1,095.93 | 60.96% | 20.0s |
| 10s Alert Cooldown | **100.0%** | **7/7** | **229.02** | **12.74%** | **14.0s** |
| 30s Alert Cooldown | 71.43% | 5/7 | 78.95 | 4.39% | 6.0s |
| 60s Alert Cooldown | 57.14% | 4/7 | 39.89 | 2.22% | 12.0s |
| **2-Consec + 60s Cooldown ★** | **28.57%** | **2/7** | **39.57** | **2.20%** | **5.0s** |
| N=2 Consecutive | 100.0% | 7/7 | ~1,085 | ~60% | ~20s |
| Rolling Mean W=3 | 100.0% | 7/7 | 1,108.0 | ~62% | ~20s |
| Hysteresis (0.20/0.05) | 57.14% | 4/7 | 358.02 | 19.91% | ~10s |

**Champion selection:** 10s cooldown (100% recall, 229 FA/hr, 14s lead) is the operational "Tier 1" operating point for maximum coverage. 60s cooldown is "Tier 3" for reduced false-alarm environments.

### C. Hard Negative Analysis
From `reports/phase_7/03_hard_negative_analysis.csv`:
- 27,721 test false positive windows profiled
- 50 representative samples analyzed
- **Root causes:** TCP RST spikes (34%), Benign Multi-Port Queries/mDNS/NetBIOS (36%), Large file downloads (30%)

### D. Behavioral Attribution & MITRE Mapping
From `reports/phase_7/08_behavior_to_mitre.csv` (55 precursor windows):
- Attribution method: Δ S_{t+K} = Ŝ_{t+K} - S_t, scored across 5 domain clusters
- MITRE techniques: T1046 (Scanning), T1110 (Brute Force), T1498 (DoS), T1071 (C2), T1190 (Exploit)
- **Infiltration → Primary: T1071 (C2, 35%–44% confidence)**
- **Botnet → Primary: T1071 (C2, 31%–33%) + T1110 (Brute Force, 30%–33%)**

> ⚠️ The MITRE attribution is a **deterministic heuristic scoring system**, NOT a trained MITRE classifier. Attribution is based on feature delta magnitudes mapped via hand-crafted rules.

### E. Event-Level Breakdown (from `07_event_level_results.csv`)
- Infiltration episodes (4): ALL detected by raw threshold, NONE via 2-Consecutive+60s cooldown
- Botnet episode 5241: Detected by both raw and champion aggregator
- Botnet episode 20205: Detected by both raw and champion aggregator
- **Issue:** Champion aggregator (2-consecutive+60s) is too aggressive for Infiltration's short-burst signature

### F. Multi-Seed Results (from `09_multiseed_results.csv`)

| Seed | Raw Event Recall | Agg Event Recall | Raw FA/hr | Agg FA/hr |
|------|-----------------|-----------------|-----------|-----------|
| 42 | **100.0%** (7/7) | 28.57% (2/7) | 1,095.93 | 39.57 |
| 123 | 71.43% (5/7) | 28.57% (2/7) | 636.38 | 31.75 |
| 2025 | 100.0% (7/7) | 28.57% (2/7) | 1,797.83 | 60.09 |

> Note: Seed 123 achieves 5/7 (71.43%) in Phase 7 raw evaluation vs. 7/7 (100%) reported in Phase 6 CSV. See discrepancy note in Phase 6 doc.

## 7. Important Changes From Previous Phase
- No model retraining — purely operational/post-processing research
- First implementation of temporal alert aggregation strategies
- First implementation of MITRE behavioral attribution engine
- Production artifact packaging and smoke testing

## 8. Results — Summary

### Final Operational Benchmark Table (from `10_final_model_comparison.csv`)

| Model | Event Recall | Events | FA/hr | FPR | Median Lead | State MAE |
|-------|-------------|--------|-------|-----|------------|-----------|
| Majority Baseline | 0.0% | 0/7 | 0.0 | 0.0% | 0s | N/A |
| Logistic Regression | 42.86% | 3/7 | 251.48 | 13.99% | 6.0s | N/A |
| Random Forest | 85.71% | 6/7 | 688.73 | 38.31% | 19.0s | N/A |
| Phase 6 SparseRSSM (Raw) | **100.0%** | **7/7** | 1,101.27 | 61.26% | **20.0s** | 0.2766 |
| Phase 7 FPR≤5% OP | 0.0% | 0/7 | 0.0 | 0.0% | 0s | 0.2766 |
| **Phase 7 Champion (2-Consec+60s) ★** | 28.57% | 2/7 | **39.57** | **2.20%** | 5.0s | 0.2766 |
| **Phase 7 Tier 1 (10s Cooldown)** | **100.0%** | **7/7** | **229.02** | **12.74%** | **14.0s** | 0.2766 |

**State Forecasting:** Test State MAE=0.2766, Test State MSE=0.6155

## 9. Conclusion
Phase 7 established that:
1. A 10-second alert cooldown reduces raw false alarms by 79% (1,095 → 229 FA/hr) while preserving 100% event recall and 14s median lead time.
2. More aggressive aggregation (2-consecutive + 60s cooldown) cuts FA/hr by 96% (39.57) but sacrifices recall (28.57%/2 of 7 episodes).
3. Infiltration attack patterns are difficult to retain under aggressive aggregation due to short-burst temporal signatures.
4. The MITRE attribution layer provides evidence-based, human-interpretable technique candidates for SOC analysts.

## 10. Important Artifacts
- `artifacts/phase7/model.pt` — 862,047 bytes (SparseRSSM weights, seed=42, Phase 6 champion)
- `artifacts/phase7/scaler.pkl` — 1,721 bytes (StandardScaler, 54 dims, fitted on training split)
- `artifacts/phase7/feature_schema.json` — 4,430 bytes (54 feature names and ordering)
- `artifacts/phase7/config.json` — 662 bytes (model hyperparameters and operational settings)
- `artifacts/phase7/metadata.json` — 727 bytes (evaluation metrics and data lineage)
- `artifacts/phase7/inference_example.json` — 2,835 bytes (structured inference I/O example)
- `reports/phase_7/` — 12 files (02 through 11 CSV/MD reports)
- `tests/test_phase7_artifacts.py` — Smoke test (100% pass rate confirmed)

## 11. Git Commit
`d2c7da5` — "feat(phase7): implement operational early-warning aggregation, forensic attribution, and benchmark reports"

## 12. Scientific Status
**FINAL.** This is the production research freeze. No further experiments planned on this branch.

## 13. Known Issues / Bugs
- Infiltration episodes are not retained by the champion 2-consecutive+60s aggregator (architectural limitation of the short-burst pattern)
- Seed 123 achieves lower raw recall (5/7) than Seeds 42 and 2025 (7/7)
- FPR-constrained threshold optimization collapses to threshold=0.99 (zero recall) — the precursor signals do not support hard FPR constraints

## 14. Open Questions at End of Phase
(Phase 7 is final. These are deferred to future work.)
- Can attention-based temporal alignment improve Infiltration detection under cooldown?
- Can an LLM explain the MITRE attribution in natural language for SOC analysts?

## 15. Transition to Next Phase
Phase 8 (future): Streamlit SOC dashboard + LLM-assisted explanation. Not yet implemented.

## 16. Files Modified
`scripts/phase_7/run_phase_7.py` (created), `tests/test_phase7_artifacts.py` (created), `artifacts/phase7/` (6 files created), `reports/phase_7/` (12 files created)

## 17. Reproducibility Status
Fully reproducible. Run `scripts/phase_7/run_phase_7.py`. Artifacts verified via `tests/test_phase7_artifacts.py` (exit code 0). Inference smoke test confirmed prob range [0.0363, 0.0597].
