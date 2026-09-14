# Phase 2 — EDA, Anomaly Audit, Logistic Regression Baseline

## 1. Phase Identifier
Phase 2 | Commit: `d03a94f` | Branch: `features/data_pipeline`

## 2. Objective
Switch to CSE-CIC-IDS2018 exclusively. Perform thorough EDA. Audit data anomalies (NaN, infinite values, format issues). Establish chronological train/test split. Train and evaluate Logistic Regression baseline.

## 3. Dataset
- **Primary:** CSE-CIC-IDS2018
- **Format:** Raw CSV flow records from CIC FlowMeter
- **Canonical conversion:** Via `scripts/preprocessing/convert_raw_to_canonical_parquet.py`
- **Files processed:** 9 days of network traffic

## 4. Input Features
Per-flow CIC-FlowMeter features (78+ raw features). Adapted via `src/cic_feature_adapter.py` and `src/cic_mapping.py`.

## 5. Model Architecture
Logistic Regression (flat per-flow features, no temporal context).

## 6. Experiments Run
- EDA across all 9 CIC-IDS2018 days
- Anomaly detection: NaN audit, infinity value audit, class imbalance analysis
- Logistic Regression training with chronological split

## 7. Important Changes From Previous Phase
Complete dataset switch from DARPA+CIC2017 to CSE-CIC-IDS2018.

## 8. Results
Logistic Regression baseline established. Flow-level classification without temporal context. Exact numbers superseded by Phase 5.5 evaluation.

## 9. Conclusion
CIC-IDS2018 data requires substantial cleaning. Per-flow features alone insufficient for early-warning task. Temporal aggregation needed.

## 10. Important Artifacts
- `reports/dataset_selection/` — Dataset selection reports
- `reports/data_pipeline/` — Data pipeline audit reports
- `scripts/preprocessing/convert_raw_to_canonical_parquet.py` — Canonical conversion script

## 11. Git Commit
`d03a94f` — "feat(ml): complete EDA, anomaly audit, preprocessing pipeline, and Logistic Regression baseline for SIH26153"

## 12. Scientific Status
**SUPERSEDED** for modeling results. Pipeline code still used in production.

## 13. Known Issues / Bugs
None critical discovered post-audit.

## 14. Open Questions at End of Phase
How to build a temporally-aware feature representation from flow-level data?

## 15. Transition to Next Phase
Moved to Phase 3: 54-D temporal state aggregation.

## 16. Files Modified
`src/cic_feature_adapter.py`, `src/cic_mapping.py`, `scripts/preprocessing/convert_raw_to_canonical_parquet.py`, `scripts/verification/verify_canonical_parquets.py`

## 17. Reproducibility Status
Requires raw CIC-IDS2018 CSVs (not stored in repo). Canonical parquets stored in `data/processed/`.
