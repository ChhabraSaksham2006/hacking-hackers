# 07 — Phase 5.5 Multi-Seed Stability Verification

| Seed Run | Horizon $K$ | Val Best $F_1$ | Calibrated Threshold | Test $F_1$ | Test Precision | Test Recall | Test FPR | Test PR-AUC | State MAE |
|---|---|---|---|---|---|---|---|---|---|
| **Seed 42** | 1 | 0.3329 | 0.51 | 0.2994 | 84.66% | 18.18% | 1.35% | 0.6069 | 0.2497 |
| **Seed 123** | 1 | 0.3358 | 0.52 | 0.2281 | 83.69% | 13.20% | 1.06% | 0.5863 | 0.2483 |
| **Seed 2025** | 1 | 0.3346 | 0.58 | 0.2858 | 88.78% | 17.03% | 0.88% | 0.6372 | 0.2513 |
| **Mean $\pm$ Std** | 1 | **$0.3344 \pm 0.0015$** | — | **$0.2711 \pm 0.0309$** | **$85.71\% \pm 2.22\%$** | **$16.14\% \pm 2.13\%$** | **$1.10\% \pm 0.19\%$** | **$0.6101 \pm 0.0209$** | **$0.2498 \pm 0.0012$** |

### Interpretation

Multi-seed verification across seeds 42, 123, and 2025 confirms high stability of the corrected SparseRSSM training pipeline. The standard deviation across seeds for validation F1 was only 0.0015, and test precision remained consistently between 83.69% and 88.78% with false positive rates tightly bounded around 1.10%.
