# 20 — Result Consistency & Cross-Artifact Audit

## 1. Audit of Conflicting Metrics Across Artifacts

| Item / Claim | Source A | Value A | Source B | Value B | Root Cause | Trustworthy Source | Status |
|---|---|---|---|---|---|---|---|
| **Dense RSSM F1 at K=1** | `results_final_selected_k/.../metrics.json` | **0.5540** | `results_selected_benchmark/.../metrics.json` | **0.5507** | Different random weight initialization across independent runs | `results_final_selected_k` (final benchmark) | RESOLVED (RUN VARIATION) |
| **Dense RSSM FPR at K=100** | `results_final_selected_k` | **0.6608** | `results_selected_benchmark` | **0.6635** | Independent training run | `results_final_selected_k` | RESOLVED (RUN VARIATION) |
| **RF F1 at K=100** | `reports/baselines/06_multihorizon_comparison.csv` | **0.5581** | `results_final_selected_k/comparison.json` | **0.5522** | Report 06 used `max_horizon=100`; comparison used fixed `max_horizon=300` | `results_final_selected_k` (fixed 300 test set) | RESOLVED (TRUNCATION) |
| **Baseline FPR Values** | Baseline evaluator logs | ~0.01 – 0.05 | `comparison.json` | `NaN` / blank | Parser omitted confusion matrix counts when compiling summary JSON | Evaluator logs | RESOLVED (PARSER OMISSION) |
