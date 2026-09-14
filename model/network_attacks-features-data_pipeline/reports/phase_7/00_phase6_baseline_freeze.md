# Phase 6 Baseline Freeze Report

**SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data**  
**Repository:** `C:\CyberSecurityNetworkingAttackPredictionModel`  
**Branch:** `features/data_pipeline`  
**Commit Reference:** `9d53bf1`  
**Evaluation Horizon:** $H = 20\text{s}$ (10 future time-steps)  
**Input History:** Pure-benign 10-step lookback ($P=10$, zero attack traffic in history)

---

## 1. Executive Summary & Objective

Phase 6 demonstrated the feasibility of **Pre-Attack Onset Forecasting** using a temporal world model (`SparseRSSM`). By conditioning exclusively on pure-benign network traffic history ($t-9 \dots t$) and training with an exponential precursor loss weighting ($10\times$ multiplier within 60 seconds of onset), the model demonstrated that latent behavioral drift contains detectable predictive signals before physical malicious flows are recorded.

However, Phase 6 baseline evaluations revealed a critical operational limitation: **raw instantaneous window thresholding produces unsustainable false alarm rates** ($1,101.3\text{ FA/hr}$, $\text{FPR} = 61.26\%$) in an unconstrained environment.

This baseline freeze establishes the authoritative numbers from Phase 6, against which Phase 7's operational aggregation and behavioral attribution layers are evaluated.

---

## 2. Phase 6 Benchmark Results Freeze ($H=20\text{s}$)

| Model / System | Model Architecture | Operating Threshold | Window Precision | Window Recall | Window $F_1$ | Window FPR | False Alarms / hr | Event Recall | Events Detected | Median Lead Time | Mean Lead Time | State MAE |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Majority Baseline** | Rule-Based (Always 0) | 0.50 | 0.0000 | 0.0000 | 0.0000 | 0.00% | 0.00 | 0.0% | 0 / 7 | 0.0s | 0.0s | N/A |
| **Logistic Regression** | Linear (540-D Flat History) | 0.22 | 0.0024 | 0.2727 | 0.0047 | 13.99% | 251.48 | 42.86% | 3 / 7 | 6.0s | 10.0s | N/A |
| **Random Forest** | Non-Linear Ensemble (54-D State) | 0.04 | 0.0019 | 0.6182 | 0.0039 | 38.31% | 688.73 | 85.71% | 6 / 7 | 19.0s | 14.7s | N/A |
| **Phase 6 SparseRSSM (Champion E602)** | Temporal Recurrent State-Space Model | 0.07 | 0.0020 | 1.0000 | 0.0039 | 61.26% | 1,101.27 | **100.0%** | **7 / 7** | **20.0s** | **15.7s** | **0.2753** |

---

## 3. Multi-Horizon Scaling Analysis (Phase 6 Champion Model)

| Horizon ($H$) | Time-Steps ($K$) | Event Recall | Events Detected | Median Lead Time | Window FPR | False Alarms / hr | Window $F_1$ | PR-AUC | ROC-AUC | State MAE |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$H = 2\text{s}$** | 1 | 100.0% | 7 / 7 | 2.0s | 67.22% | 1,209.71 | 0.0005 | 0.0003 | 0.7323 | 0.2575 |
| **$H = 10\text{s}$** | 5 | 100.0% | 7 / 7 | 10.0s | 63.75% | 1,146.81 | 0.0021 | 0.0009 | 0.6496 | 0.2918 |
| **$H = 20\text{s}$** | 10 | **100.0%** | **7 / 7** | **20.0s** | **61.26%** | **1,101.27** | **0.0039** | **0.0013** | **0.5869** | **0.2753** |
| **$H = 60\text{s}$** | 30 | 28.57% | 2 / 7 | 32.0s | 14.89% | 267.13 | 0.0020 | 0.0023 | 0.3138 | 0.2643 |
| **$H = 120\text{s}$** | 60 | 71.43% | 5 / 7 | 66.0s | 18.18% | 325.05 | 0.0110 | 0.0054 | 0.4048 | 0.2512 |
| **$H = 300\text{s}$** | 150 | 71.43% | 5 / 7 | 168.0s (2.8m) | 10.42% | 184.39 | 0.0248 | 0.0112 | 0.3037 | 0.2503 |

---

## 4. Test Set Forensic Distribution (7 OOD Episodes)

All 7 test episodes in CSE-CIC-IDS2018 represent **Out-Of-Distribution (OOD)** attack families never seen during training:
1. **Infiltration (Wednesday-28-02-2018):**
   - Episode 1: Window 1256, Duration 58.1m, Prev Benign 41.9m
   - Episode 2: Window 17696, Duration 75.1m, Prev Benign 489.9m
2. **Infiltration (Thursday-01-03-2018):**
   - Episode 3: Window 1796, Duration 97.1m, Prev Benign 59.9m
   - Episode 4: Window 16106, Duration 58.1m, Prev Benign 379.9m
3. **Botnet (Friday-02-03-2018):**
   - Episode 5: Window 5241, Duration 0.2m, Prev Benign 0.4m
   - Episode 6: Window 16600, Duration 119.8m, Prev Benign 378.5m
   - Episode 7: Window 20205, Duration 46.3m, Prev Benign 0.4m

---

## 5. Phase 7 Strategic Imperatives

1. **Eliminate Raw Window Alert Noise:** Implement temporal alert aggregation (consecutive confirmations, rolling smoothing, hysteresis, and cooldown suppression) to reduce FA/hr from $>1000$ to operational levels ($<50\text{ FA/hr}$).
2. **Multi-Constraint Operating Points:** Calibrate decision boundaries strictly on validation split across explicit operational budgets ($\text{FPR} \le 2\%, 5\%, 10\%$).
3. **Forensic Root Cause Mining:** Isolate and profile pure-benign false-alarm windows to identify underlying physical network triggers.
4. **Behavioral Attribution & MITRE Mapping:** Build an evidence-based interpretation layer mapping forecasted state deviations $\Delta S_{t+K} = \hat{S}_{t+K} - S_t$ to MITRE ATT&CK techniques without data leakage or overclaiming.
