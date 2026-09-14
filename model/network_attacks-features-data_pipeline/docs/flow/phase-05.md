# Phase 5 — SparseRSSM Multi-Horizon Benchmark (PRE-BUG, SUPERSEDED)

## 1. Phase Identifier
Phase 5 | Commits: Various (prior to `6d20a8e`) | Branch: `features/data_pipeline`

## 2. Objective
Benchmark the SparseRSSM across multiple forecast horizons (K=1, 10, 50, 100, 300) with various sparsity ratios. Compare against baselines.

> ⚠️ **SUPERSEDED:** Phase 5 results are INVALIDATED by Phase 4.5 forensic audit. Do not cite these results in any paper or report.

## 3. Dataset
CSE-CIC-IDS2018 54-D temporal states. Same split as Phase 4.

## 4. Input Features
54-D temporal state. P=10 lookback.

## 5. Model Architecture
SparseRSSM with sparsity_ratio ∈ {0.10, 0.25, 0.50, 0.75, 1.00}. K ∈ {1, 10, 50, 100, 300}.

## 6. Experiments Run
- Dense RSSM (sparsity_ratio=1.0) at K=1,10,50,100,300
- Sparse RSSM (top10, top50) at K=10
- Pre-onset evaluation (with leakage — threshold selected from test data)
- Results stored in `results_phase5/`

## 7. Important Changes From Previous Phase
First training run of SparseRSSM. Attack head trained (but BCE gradient not confirmed flowing).

## 8. Results (Phase 5 Claims — INVALIDATED)
Phase 5 final verdict (`reports/phase_5/16_phase_5_final_verdict.md`) claimed:
- "28%–57% onset recall" — **CONTRADICTED** by actual Phase 5 CSVs ($0-4.5\%$ in artifacts)
- "14s–82s median lead time" — **UNVERIFIED** (pre-onset eval used test-set threshold)
- K_eval=100/300 results based on K_train=10 (extrapolation gap)

## 9. Conclusion
Phase 5 results are **SCIENTIFICALLY INVALID** due to:
- CRIT-01: Attack head gradient not confirmed flowing
- CRIT-02: K_train/K_eval mismatch (implicit 10-step cap)
- CRIT-03: Pre-onset threshold selected from test data (leakage)
- CRIT-04: Phase 5 final verdict contained numerical claims contradicted by actual artifact CSVs

**AUTHORITATIVE RESULTS:** See Phase 5.5.

## 10. Important Artifacts
- `results_phase5/` — Checkpoints and test_outputs.npz for all Phase 5 experiments (preserved)
- `reports/phase_5/01_rssm_code_audit.md` through `reports/phase_5/16_phase_5_final_verdict.md`
- `reports/phase_5/05_dense_rssm_results.csv` — Phase 5 metrics (INVALID)

## 11. Git Commit
Various commits prior to `6d20a8e` (bug-fix commit). Phase 5 scripts in `scripts/experiments/`.

## 12. Scientific Status
**SUPERSEDED / INVALIDATED.** All results superseded by Phase 5.5. Preserved as historical evidence only.

## 13. Known Issues / Bugs
ALL THREE critical bugs (CRIT-01, CRIT-02, CRIT-03) present in Phase 5.

## 14. Open Questions at End of Phase
(These were resolved by Phase 4.5 audit and Phase 5.5 correction.)

## 15. Transition to Next Phase
Phase 5.5: Forensic correction, fresh model training with all bugs fixed.

## 16. Files Modified
`scripts/experiments/run_sparse_rssm.py`, `scripts/experiments/run_each_experiment.py`, `src/training/trainer.py`

## 17. Reproducibility Status
Code state at Phase 5 preserved in git history. Results in `results_phase5/` (checkpoints) and `legacy/results_*` directories. Do not use these numbers in any claim.
