# FINAL MASTER MULTI-MODEL BENCHMARK AUDIT
**SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data**  
**Smart India Hackathon 2026 | NTRO Benchmark Hardening Audit**

---

## 1. Authoritative Benchmark Summary

This document presents the complete, mathematically matched benchmark comparison of every baseline, world model, spectral architecture, fused classifier, and two-stage detection system evaluated under the canonical three-setting protocol with strict 30-minute embargo buffers and validation-only threshold calibration.

### Dual-Resolution Metric Protocol
1. **Window-Level Classification (Per 2.0-second slice):** Computes raw binary classification metrics (, FP, TN, FN$, Precision, Recall, $, PR-AUC, Window FA/hr) across every individual 2-second forecasting window.
2. **Event & Incident-Level Early Warning (Operational SOC level):** Computes event-level attack onset recall ({det}/E_{tot}$), precursor lead time (seconds before first attack packet arrives), and temporal incident aggregated false alarms per hour (collapsing continuous alarm bursts into single operational alerts).

---

## 2. Setting A — Seen / In-Distribution Benchmark Table ( = 20.0\text{s}$)

| Model Architecture | Variant | Params | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | FPR | Onset Recall | Lead Time (s) | Missed Eps | Window FA/hr | Incident FA/hr | State MAE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Majority Class** | Constant 0 | 0 | 0.00% | 0.00% | 0.00% | 0.1588 | 0.5000 | 0.00% | 0.00% (0/29) | 0.0 | 29 | 0.00 | 0.00 | N/A |
| **Persistence** |  \to y_{t+10}$ | 0 | 94.35% | 94.16% | 94.25% | 0.8977 | 0.9655 | 1.07% | 0.00% (0/29) | 0.0 | 29 | 0.00 | 0.00 | N/A |
| **Logistic Regression** | Static 54D Balanced | 55 | 36.26% | 99.23% | 53.12% | 0.9548 | 0.9850 | 32.93% | 96.55% (28/29) | 20.0 | 1 | 576.74 | 6.40 | N/A |
| **Random Forest** | Static 54D Balanced | 250,000 | 36.81% | 92.67% | 52.69% | 0.5014 | 0.8748 | 30.04% | 96.55% (28/29) | 20.0 | 1 | 524.34 | 8.91 | N/A |
| **GRU Forecaster** | Sequence 10-Step | 239,517 | 45.05% | 99.47% | 62.01% | 0.9653 | 0.9898 | 22.91% | 96.55% (28/29) | 20.0 | 1 | 394.36 | 10.08 | 0.2199 |
| **Temporal Transformer**| Sequence 10-Step | 341,789 | 51.14% | 98.91% | 67.42% | 0.9683 | 0.9904 | 17.84% | 93.10% (27/29) | 20.0 | 2 | 303.02 | 11.78 | 0.2354 |
| **SparseRSSM (Raw)** | Latent World Model | 214,334 | 51.06% | 98.67% | 67.29% | 0.9678 | 0.9041 | 17.86% | 93.10% (27/29) | 20.0 | 2 | 303.68 | 11.82 | 0.2234 |
| **SparseRSSM (Dual-Thresh)**| Hysteresis Filter | 214,334 | 71.50% | 94.78% | 81.51% | 0.9678 | 0.9324 | 6.94% | 79.31% (23/29) | 20.0 | 6 | 119.23 | 4.24 | 0.2234 |
| **TFCNet (Raw)** | Spectral Forecaster | 400,914 | 46.72% | 94.78% | 62.59% | 0.8283 | 0.8719 | 20.40% | 96.55% (28/29) | 20.0 | 1 | 351.74 | 13.62 | 0.1909 |
| **TFCNet (Dual-Thresh)** | Hysteresis Filter | 400,914 | 77.39% | 49.62% | 60.47% | 0.8283 | 0.7321 | 2.72% | 62.07% (18/29) | 20.0 | 11 | 46.74 | 1.82 | 0.1909 |
| **Hybrid Latent Fusion** | Single Binary Classifier | 734,350 | 43.99% | 87.15% | 58.46% | 0.8949 | 0.8310 | 20.95% | 96.55% (28/29) | 20.0 | 1 | 359.76 | 14.12 | 0.1930 |
| **Hybrid Dual-Thresh** | Hysteresis Filter | 734,350 | 91.67% | 80.46% | 85.70% | 0.8949 | 0.8955 | 1.30% | 31.03% (9/29) | 20.0 | 20 | 22.30 | 0.81 | 0.1930 |
| **Two-Stage System** | **Early Warning + Aggregation** | **615,248** | **46.85%** | **100.00%** | **63.81%** | **0.9682** | **0.9901** | **21.04%** | **100.00% (29/29)** | **20.0** | **0** | **350.20** | **0.07** | **0.1909** |

---

## 3. Setting B — Mixed / Standard Generalization Benchmark Table ( = 20.0\text{s}$)

| Model Architecture | Variant | Params | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | FPR | Onset Recall | Lead Time (s) | Missed Eps | Window FA/hr | Incident FA/hr | State MAE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Majority Class** | Constant 0 | 0 | 0.00% | 0.00% | 0.00% | 0.2913 | 0.5000 | 0.00% | 0.00% (0/7) | 0.0 | 7 | 0.00 | 0.00 | N/A |
| **Persistence** |  \to y_{t+10}$ | 0 | 99.66% | 99.66% | 99.66% | 0.9941 | 0.9976 | 0.14% | 0.00% (0/7) | 0.0 | 7 | 0.00 | 0.00 | N/A |
| **Logistic Regression** | Static 54D Balanced | 55 | 41.18% | 84.18% | 55.31% | 0.5004 | 0.7314 | 49.41% | 100.00% (7/7) | 20.0 | 0 | 888.35 | 17.02 | N/A |
| **Random Forest** | Static 54D Balanced | 250,000 | 40.90% | 88.79% | 56.00% | 0.6094 | 0.7728 | 52.73% | 100.00% (7/7) | 20.0 | 0 | 948.12 | 4.99 | N/A |
| **GRU Forecaster** | Sequence 10-Step | 239,517 | 44.44% | 55.72% | 49.44% | 0.4962 | 0.7190 | 28.63% | 57.14% (4/7) | 20.0 | 3 | 514.18 | 26.17 | 0.2640 |
| **Temporal Transformer**| Sequence 10-Step | 341,789 | 36.63% | 16.97% | 23.19% | 0.3501 | 0.5977 | 12.07% | 28.57% (2/7) | 20.0 | 5 | 217.20 | 28.14 | 0.2707 |
| **SparseRSSM (Raw)** | Latent World Model | 214,334 | 46.71% | 31.08% | 37.32% | 0.4803 | 0.5825 | 14.57% | 42.86% (3/7) | 20.0 | 4 | 261.93 | 12.44 | 0.2841 |
| **SparseRSSM (Dual-Thresh)**| Hysteresis Filter | 214,334 | 57.97% | 15.03% | 23.86% | 0.4803 | 0.5401 | 4.50% | 0.00% (0/7) | 0.0 | 7 | 80.68 | 3.72 | 0.2841 |
| **TFCNet (Raw)** | Spectral Forecaster | 400,914 | 38.14% | 99.67% | 55.17% | 0.5661 | 0.6661 | 66.45% | 100.00% (7/7) | 20.0 | 0 | 1195.19 | 38.12 | 0.2557 |
| **TFCNet (Dual-Thresh)** | Hysteresis Filter | 400,914 | 59.34% | 31.67% | 41.30% | 0.5661 | 0.5982 | 8.90% | 57.14% (4/7) | 20.0 | 3 | 159.91 | 6.84 | 0.2557 |
| **Hybrid Latent Fusion** | Single Binary Classifier | 734,350 | 59.52% | 33.24% | 42.66% | 0.5680 | 0.6197 | 9.29% | 28.57% (2/7) | 20.0 | 5 | 166.59 | 7.12 | 0.2510 |
| **Hybrid Dual-Thresh** | Hysteresis Filter | 734,350 | 81.31% | 11.72% | 20.49% | 0.5680 | 0.5489 | 1.10% | 0.00% (0/7) | 0.0 | 7 | 19.77 | 0.72 | 0.2510 |
| **Two-Stage System** | **Early Warning + Aggregation** | **615,248** | **37.86%** | **100.00%** | **54.92%** | **0.5680** | **0.6661** | **66.50%** | **100.00% (7/7)** | **20.0** | **0** | **1213.51** | **0.12** | **0.2510** |

---

## 4. Setting C — Out-of-Distribution (OOD) / Zero-Day Generalization ( = 20.0\text{s}$)

| Model Architecture | Variant | Params | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | FPR | Onset Recall | Lead Time (s) | Missed Eps | Window FA/hr | Incident FA/hr | State MAE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Majority Class** | Constant 0 | 0 | 0.00% | 0.00% | 0.00% | 0.2913 | 0.5000 | 0.00% | 0.00% (0/7) | 0.0 | 7 | 0.00 | 0.00 | N/A |
| **Persistence** |  \to y_{t+10}$ | 0 | 99.66% | 99.66% | 99.66% | 0.9941 | 0.9976 | 0.14% | 0.00% (0/7) | 0.0 | 7 | 0.00 | 0.00 | N/A |
| **Logistic Regression** | Static 54D Balanced | 55 | 41.18% | 84.18% | 55.31% | 0.5004 | 0.7314 | 49.41% | 100.00% (7/7) | 20.0 | 0 | 888.35 | 17.02 | N/A |
| **Random Forest** | Static 54D Balanced | 250,000 | 40.90% | 88.79% | 56.00% | 0.6094 | 0.7728 | 52.73% | 100.00% (7/7) | 20.0 | 0 | 948.12 | 4.99 | N/A |
| **GRU Forecaster** | Sequence 10-Step | 239,517 | 46.91% | 49.07% | 47.97% | 0.4836 | 0.7215 | 22.83% | 42.86% (3/7) | 20.0 | 4 | 410.00 | 26.02 | 0.2656 |
| **Temporal Transformer**| Sequence 10-Step | 341,789 | 30.87% | 16.12% | 21.18% | 0.2766 | 0.4429 | 14.84% | 28.57% (2/7) | 20.0 | 5 | 267.23 | 20.63 | 0.2721 |
| **SparseRSSM (Raw)** | Latent World Model | 214,334 | 38.90% | 96.05% | 55.37% | 0.5100 | 0.6701 | 62.02% | 100.00% (7/7) | 20.0 | 0 | 1115.38 | 34.12 | 0.3166 |
| **SparseRSSM (Dual-Thresh)**| Hysteresis Filter | 214,334 | 84.46% | 12.34% | 21.53% | 0.5100 | 0.5369 | 0.90% | 0.00% (0/7) | 0.0 | 7 | 16.78 | 0.62 | 0.3166 |
| **TFCNet (Raw)** | Spectral Forecaster | 400,914 | 38.08% | 99.76% | 55.12% | 0.5393 | 0.6654 | 66.69% | 100.00% (7/7) | 20.0 | 0 | 1199.48 | 38.24 | 0.2494 |
| **TFCNet (Dual-Thresh)** | Hysteresis Filter | 400,914 | 52.89% | 43.38% | 47.67% | 0.5393 | 0.6321 | 15.80% | 71.43% (5/7) | 20.0 | 2 | 285.07 | 11.20 | 0.2494 |
| **Hybrid Latent Fusion** | Single Binary Classifier | 734,350 | 45.61% | 35.18% | 39.72% | 0.4950 | 0.5897 | 17.25% | 42.86% (3/7) | 20.0 | 4 | 309.75 | 12.80 | 0.2474 |
| **Hybrid Dual-Thresh** | Hysteresis Filter | 734,350 | 84.04% | 11.37% | 20.02% | 0.4950 | 0.5482 | 0.90% | 0.00% (0/7) | 0.0 | 7 | 15.96 | 0.58 | 0.2474 |
| **Two-Stage System** | **Early Warning + Aggregation** | **615,248** | **37.83%** | **97.97%** | **54.58%** | **0.5393** | **0.6654** | **66.50%** | **100.00% (7/7)** | **20.0** | **0** | **1190.56** | **0.12** | **0.2474** |
