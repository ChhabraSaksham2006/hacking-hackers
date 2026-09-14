# 10 — Multi-Horizon Early Warning Scaling (Champion Config)

| Forecast Horizon $H$ | Future Lead Time | Test Event Recall | Events Detected | Median Lead Time | Mean Lead Time | False Alarms / hr | Window FPR | Window $F_1$ | State MAE |
|---|---|---|---|---|---|---|---|---|---|
| **$H = 2$s** | 2.0s | **100.0%** | **7 / 7** | **2.0s** | 2.0s | 1209.7 | 67.22% | 0.0005 | 0.2575 |
| **$H = 10$s** | 10.0s | **100.0%** | **7 / 7** | **10.0s** | 8.6s | 1146.8 | 63.75% | 0.0021 | 0.2918 |
| **$H = 20$s** (Champion) | 20.0s | **100.0%** | **7 / 7** | **20.0s** | 15.7s | 1101.3 | 61.26% | 0.0039 | 0.2753 |
| **$H = 60$s** | 60.0s | **28.57%** | 2 / 7 | 32.0s | 32.0s | 267.1 | 14.89% | 0.0020 | 0.2643 |
| **$H = 120$s** | 120.0s | **71.43%** | 5 / 7 | **66.0s** | 70.4s | 325.1 | 18.18% | 0.0110 | 0.2512 |
| **$H = 300$s** (5 min) | 300.0s | **71.43%** | 5 / 7 | **168.0s** (2.8m)| 174.8s | **184.4** | **10.42%** | **0.0248** | 0.2503 |

### Interpretation

Evaluating the champion configuration across multi-minute forecast horizons reveals a key operational trade-off: at H=20s, the model achieves 100% recall with 20.0s lead time; at extended horizons (H=300s / 5 minutes), the model detects 71.43% of attack episodes nearly 3 minutes in advance while false alarms drop by 83% (down to 184.4 FA/hr and 10.42% FPR).
