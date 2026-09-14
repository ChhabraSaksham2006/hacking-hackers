# Phase 4 — Baseline Forecasting Model Suite Benchmark

## 1. Phase Identifier
Phase 4 | Commit: `e3b6a20` | Branch: `features/data_pipeline`

## 2. Objective
Benchmark a comprehensive suite of baseline forecasting models across multiple horizons (K=1, 50, 100) to establish definitive performance baselines before testing the SparseRSSM world model.

## 3. Dataset
- **Primary:** CSE-CIC-IDS2018 (54-D temporal states)
- **Split:** Chronological (5 train days / 1 val day / 3 test days)
- **Sequences:** K_max=300 → 101,845 train / 21,536 val / 64,608 test (Note: count changed to 89,027/18,658/45,530 in later phases due to pure-benign filtering)

## 4. Input Features
54-D temporal state sequences. Lookback P=10 windows.

## 5. Model Architecture
| Model | Description |
|-------|-------------|
| Majority Class | Always predict 0 (benign) |
| Persistence | y_{t+K} = y_t |
| Logistic Regression | Linear on flattened 10×54=540-D lookback |
| Random Forest | Ensemble on 54-D current state |
| GRU | Recurrent sequence model |
| Transformer | Attention-based temporal model |

## 6. Experiments Run
- All baselines evaluated at K=1 (2s), K=50 (100s), K=100 (200s)
- Results stored in `legacy/results_selected_benchmark/`
- RF-RSSM hybrid experiments (`legacy/results_rf_rssm_k200/`, `legacy/results_rssm_rf_k100/`)

## 7. Important Changes From Previous Phase
First evaluation of all forecasting baselines on the 54-D temporal state dataset.

## 8. Results (from `reports/phase_5_5/baseline_comparison.csv` — authoritative Phase 5.5 re-evaluation)

| Model | K | F1 | Precision | Recall | FPR | PR-AUC |
|-------|---|----|-----------|--------|-----|--------|
| Persistence | 1 | 0.9996 | 99.96% | 99.96% | 0.02% | 0.9997 |
| Persistence | 10 | 0.9965 | 99.65% | 99.65% | 0.14% | 0.9970 |
| Persistence | 50 | 0.9861 | 98.61% | 98.61% | 0.57% | 0.9881 |
| Logistic Regression | 1 | 0.2078 | 80.75% | 11.93% | 1.17% | 0.5447 |
| Random Forest | 1 | 0.2035 | 93.68% | 11.42% | 0.32% | 0.6451 |
| Random Forest | 10 | 0.5589 | 40.60% | 89.67% | 53.91% | 0.5843 |

**Persistence Paradox:** Persistence achieves F1≈1.0 due to multi-hour contiguous attack episodes in CIC-IDS2018. On pre-onset transitions (y_t=0, y_{t+K}=1), Persistence achieves 0.00% recall.

## 9. Conclusion
Persistence is deceptively strong for continuation classification. The operationally meaningful task is pre-attack onset detection, where Persistence is useless. Random Forest competitive at K=1.

## 10. Important Artifacts
- `legacy/results_selected_benchmark/` — Phase 4 baseline results
- `legacy/results_rf_rssm_k200/` — RF-RSSM hybrid experiment
- `legacy/results_rssm_rf_k100/` — RSSM-RF hybrid experiment
- `reports/baselines/` — Baseline benchmark reports
- `scripts/experiments/run_baseline_suite.py` — Baseline training runner

## 11. Git Commit
`e3b6a20` — "feat(baselines): complete Phase 4 baseline forecasting model suite benchmarks and reports"

## 12. Scientific Status
**SUPERSEDED** for reported numbers (Phase 5.5 re-evaluated all baselines). **ACTIVE** as historical evidence.

## 13. Known Issues / Bugs
- GRU results not preserved in authoritative Phase 5.5 CSV (not re-run in Phase 5.5)
- K=100/300 results used K_train=10 (implicit cap) — discovered in Phase 5.5 audit

## 14. Open Questions at End of Phase
Why does Persistence perform so strongly? Can the RSSM outperform Persistence on genuine early-warning?

## 15. Transition to Next Phase
Phase 4.5: Comprehensive forensic audit of the SparseRSSM architecture.

## 16. Files Modified
`scripts/experiments/run_baseline_suite.py`, `scripts/experiments/run_selected_baseline_rssm.py`, `src/models/baselines/`

## 17. Reproducibility Status
Results stored in `legacy/` directory (git-tracked). Training scripts preserved in `scripts/experiments/`.
