# 17 — Phase 7 Multi-Seed Evaluation & Aggregation Stability

| Random Seed | Calibrated Threshold | Raw Event Recall | Raw Events Detected | Raw False Alarms / hr | Raw Window FPR | Aggregated Event Recall | Aggregated Events Detected | Aggregated False Alarms / hr | Aggregated Window FPR |
|---|---|---|---|---|---|---|---|---|---|
| **Seed 42** | 0.04 | **100.0%** | **7 / 7** | 1,095.93 | 60.96% | 28.57% | 2 / 7 | 39.57 | 2.20% |
| **Seed 123** | 0.04 | **71.43%** | 5 / 7 | 636.38 | 35.40% | 28.57% | 2 / 7 | 31.75 | 1.77% |
| **Seed 2025**| 0.04 | **100.0%** | **7 / 7** | 1,797.83 | 100.0% | 28.57% | 2 / 7 | 60.09 | 3.34% |
| **Mean $\pm$ Std** | — | **$90.48\% \pm 16.50\%$** | **$6.3 \pm 1.2$** | **$1176.7 \pm 585.0$** | **$65.45\% \pm 32.53\%$** | **$28.57\% \pm 0.00\%$** | **$2.0 \pm 0.0$** | **$43.80 \pm 14.64$** | **$2.44\% \pm 0.81\%$** |

### Interpretation

Multi-seed re-evaluation in Phase 7 confirms that under operational aggregation, detection consistency is perfectly identical across all random seeds (28.57% event recall, 2/7 detected). Under raw thresholding, seeds 42 and 2025 capture 100% of episodes, while seed 123 captures 71.43%. Across all seeds, the aggregation layer stabilizes false alarms to ~43 FA/hr.
