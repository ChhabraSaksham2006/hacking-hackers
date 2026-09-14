# 13 — Operational Alert Aggregation & Smoothing Evaluation

| Strategy Category | Aggregation Strategy Name | Filter Parameters | Threshold | Event Recall | Events Detected | False Alarms / hr | Window FPR | Median Lead Time | Operational Tier |
|---|---|---|---|---|---|---|---|---|---|
| **Raw Baseline** | Raw Instantaneous Threshold | None | 0.04 | **100.0%** | **7 / 7** | 1095.93 | 60.96% | **20.0s** | Unfiltered |
| **Cooldown** | 10s Alert Cooldown | $T_{	ext{cool}} = 10	ext{s}$ | 0.04 | **100.0%** | **7 / 7** | **229.02** | **12.74%** | **14.0s** | **Tier 1 (High Sensitivity)** |
| **Cooldown** | 30s Alert Cooldown | $T_{	ext{cool}} = 30	ext{s}$ | 0.04 | **71.43%** | 5 / 7 | **78.95** | **4.39%** | 6.0s | **Tier 2 (Balanced)** |
| **Cooldown** | 60s Alert Cooldown | $T_{	ext{cool}} = 60	ext{s}$ | 0.04 | **57.14%** | 4 / 7 | **39.89** | **2.22%** | 12.0s | **Tier 3 (Low Noise)** |
| **Consecutive + Cooldown**| Consecutive-2 + Cooldown 60s | $N=2, T=60	ext{s}$ | 0.04 | 28.57% | 2 / 7 | **39.57** | **2.20%** | 5.0s | Strict Confirmation |
| **Consecutive** | 2-Consecutive Positive | $N=2$ | 0.04 | **100.0%** | **7 / 7** | 1062.24 | 59.09% | 18.0s | Auxiliary Filter |
| **Consecutive** | 3-Consecutive Positive | $N=3$ | 0.04 | **100.0%** | **7 / 7** | 1030.15 | 57.30% | 16.0s | Auxiliary Filter |
| **Rolling Mean**| Rolling Mean Window 3 | $W=3$ | 0.04 | **100.0%** | **7 / 7** | 1108.01 | 61.63% | 20.0s | Smoothing Only |
| **Hysteresis** | Dual-Threshold Trigger | $	au_h=0.20, 	au_l=0.05$ | 0.20 | **57.14%** | 4 / 7 | 358.02 | 19.91% | 10.0s | Schmitt Trigger |

### Interpretation

This table documents the core engineering breakthrough of Phase 7: applying a 10-second operational cooldown preserves 100.0% event recall (all 7 out-of-distribution episodes detected) while cutting false alarm volume by 79.1% (from 1,095.9 down to 229.0 FA/hr). Extending cooldown to 60s achieves a 96.4% reduction in false alarms (39.89 FA/hr) while retaining 57.14% recall.
