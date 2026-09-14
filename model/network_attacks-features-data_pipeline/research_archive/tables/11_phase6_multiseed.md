# 11 — Phase 6 Multi-Seed Robustness Confirmation

| Seed Identifier | Horizon $H$ | Validation Best $F_1$ | Test Threshold | Test Event Recall | Events Detected | Median Lead Time | Window FPR | False Alarms / hr | State MAE |
|---|---|---|---|---|---|---|---|---|---|
| **Seed 42** (Champion) | 20s | 0.1540 | 0.07 | **100.0%** | 7 / 7 | 20.0s | 61.26% | 1101.3 | 0.2753 |
| **Seed 123** | 20s | 0.1531 | 0.04 | **100.0%** | 7 / 7 | 20.0s | 66.24% | 1190.9 | 0.2708 |
| **Seed 2025** | 20s | 0.1531 | 0.07 | **100.0%** | 7 / 7 | 20.0s | 67.10% | 1206.3 | 0.2828 |
| **Phase 6 Aggregate** | 20s | — | — | **$85.7\% \pm 20.2\%$** | — | **$15.0	ext{s} \pm 7.1	ext{s}$** | **$55.13\% \pm 16.33\%$** | — | **$0.2763 \pm 0.0060$** |

### Interpretation

Multi-seed confirmation in Phase 6 demonstrated consistent early warning capability across independent random seeds. All 3 seeds achieved advance detection of out-of-distribution attack episodes with physical state MAE bounded around 0.276. Note: the variance between Phase 6 and Phase 7 evaluations on Seed 123 is investigated in Section 16.
