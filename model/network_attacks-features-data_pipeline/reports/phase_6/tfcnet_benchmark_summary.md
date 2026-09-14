# Phase 6: TFCNet Benchmark Results Across Settings A, B, and C

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. Master TFCNet Benchmark Table

| Metric Domain | Primary Metric | Setting A (Seen Attacks) | Setting B (Mixed Traffic) | Setting C (Zero-Day OOD) |
| :--- | :--- | :--- | :--- | :--- |
| **State Forecasting** | Overall State MAE | **0.190948** | **0.255738** | **0.249405** |
| | Overall State MSE | **0.315005** | **0.329055** | **0.324664** |
| | Horizon $k=1$ (2s) MAE | 0.142054 | 0.191639 | 0.191863 |
| | Horizon $k=10$ (20s) MAE | 0.213503 | 0.272397 | 0.264929 |
| **Occurrence Forecast ($t+10$)** | Calibrated Threshold $\tau^*$ | $\tau=0.26$ | $\tau=0.07$ | $\tau=0.1$ |
| | **Macro F1 Score** | **0.6259** | **0.5517** | **0.5512** |
| | Precision | 0.4672 | 0.3814 | 0.3808 |
| | Recall | 0.9478 | 0.9967 | 0.9976 |
| | PR-AUC | 0.8283 | 0.5661 | 0.5393 |
| | False Positive Rate (FPR) | 0.2040 | 0.6645 | 0.6669 |
| **Threat Family** | 7-Class Macro F1 | **0.3335** | **0.1384** | **0.1371** |
| **Onset Early Warning** | **Onset Event Recall** | **0.9655** | **1.0000** | **1.0000** |
| | Median Lead Time | **20.0s** | **20.0s** | **20.0s** |
| | False Alarms / Hour | **351.74 FA/hr** | **1195.19 FA/hr** | **1199.48 FA/hr** |

---

## 2. Scientific Architecture Overview (TFCNet)
- **Time-Domain Branch:** Multi-scale 1D dilated convolutions ($k \in \{1, 3, 5, \text{dilated}\}$) capture local micro-bursts and rate changes.
- **Frequency-Domain Branch:** Real-valued Fast Fourier Transform (RFFT) extracts periodic frequency spectral components (beaconing and scanning cycles).
- **iTransformer Backbone:** Inverted multi-head self-attention models correlations across all 54 continuous physical metric variates simultaneously.

_Generated automatically by `scripts/experiments/train_benchmark_tfcnet.py`._