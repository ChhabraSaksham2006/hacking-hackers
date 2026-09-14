# Phase 1 — Initial Dataset Exploration & LSTM World Model

## 1. Phase Identifier
Phase 1 | Commit: `589dbda` | Branch: `feature/world-model-dataset-darpaWithCICIDS`

## 2. Objective
Build a proof-of-concept world model for network traffic forecasting using a combined DARPA+CIC-IDS2017 dataset. Establish a 47-dimensional multi-domain telemetry state and train an LSTM-based sequence model.

## 3. Dataset
- **Primary:** DARPA (KDD Cup 1999 derived) + CIC-IDS2017
- **State Dimension:** 47-D combined feature vector
- **Note:** This dataset was later ABANDONED in favor of CSE-CIC-IDS2018 exclusively.

## 4. Input Features
47-D multi-domain unified feature vector constructed from DARPA and CIC-IDS2017 flows.

## 5. Model Architecture
LSTM-based world model for sequence-to-sequence network state prediction. Architecture details preserved in `src/world_model.py` (legacy).

## 6. Experiments Run
- Initial LSTM training on combined DARPA+CIC-IDS2017 dataset
- Basic sequence-to-sequence evaluation

## 7. Important Changes From Previous Phase
First phase — no predecessor.

## 8. Results
Not formally benchmarked against later CSE-CIC-IDS2018 baselines. Proof-of-concept feasibility established.

## 9. Conclusion
The multi-dataset approach introduced distributional mismatch. Dataset was abandoned in Phase 2 in favor of CSE-CIC-IDS2018 exclusively. All DARPA+CIC-IDS2017 code is preserved in `legacy/` directory.

## 10. Important Artifacts
- `src/world_model.py` — Original LSTM world model
- `src/build_dataset.py` — Combined dataset builder
- `models/backup_darpa_week1/` — Checkpoint backup

## 11. Git Commit
`589dbda` — "feat: Prepared 47-D multi-domain dataset with DARPA+CIC-IDS2017 and also trained a LSTM based world model with inference pipeline"

## 12. Scientific Status
**SUPERSEDED.** Dataset and architecture replaced by CSE-CIC-IDS2018 + SparseRSSM pipeline.

## 13. Known Issues / Bugs
- Multi-dataset distributional mismatch
- No chronological train/test split documented

## 14. Open Questions at End of Phase
Can a single-dataset, temporally rigorous pipeline produce better-defined behavioral states?

## 15. Transition to Next Phase
Moved to CSE-CIC-IDS2018. Performed EDA and established Logistic Regression baseline.

## 16. Files Modified
`src/world_model.py`, `src/build_dataset.py`, `src/feature_extractor.py`, `src/dataset_sequence.py`, `notebooks/` (exploratory)

## 17. Reproducibility Status
Not fully reproducible from current main codebase (DARPA dataset not stored). Commit `589dbda` preserves code state.
