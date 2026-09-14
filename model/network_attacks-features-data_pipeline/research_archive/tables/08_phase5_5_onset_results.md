# 08 — Phase 5.5 Pre-Onset Early Warning Benchmark

| Warning Horizon $H$ | Test Lookahead Steps | Eligible Benign Samples | Isolated Onset Transitions | Validation Threshold | Onset Recall | False Alarms / hr | Median Lead Time |
|---|---|---|---|---|---|---|---|
| **$H=2.0$s** | 1 | 45,530 | 7 | 0.01 | **71.4%** (5/7) | 570.2 | 2.0s |
| **$H=10.0$s** | 5 | 45,530 | 30 | 0.01 | **50.0%** (15/30) | 581.4 | 10.0s |
| **$H=20.0$s** | 10 | 45,530 | 55 | 0.01 | **43.6%** (24/55) | 582.1 | 20.0s |
| **$H=60.0$s** | 30 | 45,530 | 155 | 0.01 | **53.5%** (83/155) | 580.6 | 60.0s |
| **$H=120.0$s** | 60 | 45,530 | 255 | 0.01 | **52.5%** (134/255) | 578.3 | 120.0s |
| **$H=300.0$s** | 150 | 45,530 | 255 | 0.01 | **52.5%** (134/255) | 578.3 | 300.0s |

### Interpretation

This table documents the preliminary pre-onset evaluation in Phase 5.5, enforcing strict validation-only threshold calibration. At sensitive detection thresholds (t=0.01), SparseRSSM successfully anticipated 43.6% to 71.4% of onset transitions in advance, whereas persistence captured 0.0%. However, false alarm rates remained elevated (~580 FA/hr), leading directly to Phase 6's transition loss weighting experiments.
