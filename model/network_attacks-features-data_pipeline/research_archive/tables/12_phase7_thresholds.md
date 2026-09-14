# 12 — Phase 7 Validation Operating Point Calibration

| Operating Point Identifier | Constraint / Optimization Goal | Calibrated Threshold | Validation Metric Score | Test Event Recall | Test Events Detected | Window FPR | False Alarms / hr | Median Lead Time |
|---|---|---|---|---|---|---|---|---|
| `max_f1` | Unconstrained Max F1 | **0.04** | 0.1539 | **100.0%** | **7 / 7** | 60.96% | 1,095.93 | **20.0s** |
| `fpr_le_02` | FPR $\le 2\%$ Constraint | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `fpr_le_05` | FPR $\le 5\%$ Constraint | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `fpr_le_10` | FPR $\le 10\%$ Constraint | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `fahr_le_10` | False Alarms $\le 10$/hr | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `fahr_le_50` | False Alarms $\le 50$/hr | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `fahr_le_100`| False Alarms $\le 100$/hr | 0.99 | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s |
| `balanced_event_f1` | Balanced Event & Prec | **0.07** | 0.1531 | **100.0%** | **7 / 7** | 60.96% | 1,095.93 | **20.0s** |

### Interpretation

This table proves why raw threshold tuning alone cannot solve operational noise: enforcing strict false alarm constraints (e.g. FPR <= 5%) drives the threshold to 0.99, completely extinguishing all precursor alerts (0% recall). Precursor signals have subtle amplitudes that require lower thresholds (0.04-0.07), demonstrating that temporal aggregation filters (cooldowns, multi-window confirmation) are mathematically required.
