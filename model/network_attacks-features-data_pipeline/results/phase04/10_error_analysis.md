# Forensic Error Analysis: False Positives, False Negatives & Failure Modes

**Project:** SIH26153 — AI-Based Network Attack Forecasting
**Analyzed Baselines:** Static Logistic Regression, Random Forest, GRU, Temporal Transformer

## 1. Error Distribution & Confusion Analysis (Horizon K=1, +2.0s Lead Time)

Across all 64,728 test sequences (Days 7–9: Feb 28, Mar 01, Mar 02), attack prevalence is **29.13%** (18,855 attack-containing windows vs 45,873 benign windows).

### Comparison of Decision Operating Points

| Model Architecture | Test Accuracy | Test Precision | Test Recall | Test F1 | Test PR-AUC | Test ROC-AUC |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Majority Class Baseline** | 70.87% | 0.00% | 0.00% | 0.0000 | 0.6456 | 0.5000 |
| **Persistence (y_t -> y_{t+1})** | 99.98% | 99.96% | 99.96% | 0.9996 | 0.9997 | 0.9997 |
| **Logistic Regression (Static 54D)** | 72.88% | 62.01% | 17.80% | 0.2766 | 0.5038 | 0.7274 |
| **Logistic Regression (Balanced 54D)** | 75.46% | 87.87% | 18.29% | 0.3028 | 0.6352 | 0.7984 |
| **Random Forest (Static 54D)** | 74.51% | 77.03% | 17.80% | 0.2892 | 0.6140 | 0.8032 |
| **Random Forest (Flattened 540D)** | 74.60% | 81.51% | 16.55% | 0.2752 | 0.5888 | 0.7877 |
| **GRU (Full History 10-step, 54D)** | 71.71% | 67.43% | 5.60% | 0.1034 | 0.5055 | 0.7633 |
| **Transformer (Class Weighted 54D)** | 72.31% | 76.05% | 7.19% | 0.1314 | 0.4798 | 0.7152 |


## 2. Root-Cause Decomposition of Forecasting Errors

### A. Persistence Paradox in Dense Attack Sessions
- Persistence achieves near-perfect F1 (0.9996) because in the CSE-CIC-IDS2018 test set, Botnet ARES (Day 9) runs continuously for several consecutive hours (over 10,000 continuous windows).
- **Crucial Scientific Limitation**: While persistence is high during steady-state attack execution, it has **0.00% forecasting utility for attack onset transitions** (predicting the first malicious window before it starts).

### B. Attack Onset Transitions (Benign S_t -> Malicious S_{t+1})
- Across the 14 attack onsets in the test set, deterministic baselines fail to raise early alarms prior to the initial packet burst.
- **Cause**: In the 2 to 10 seconds preceding attack onset, the network traffic is 100% benign. Without a latent generative world model simulating probable adversary action spaces, linear and feedforward networks have zero mathematical signal to predict sudden volumetric explosions.

### C. False Positives during Attack Tail & Relaxation
- Approximately 40% of all False Positives occur immediately following an attack cessation (during the 10 to 30 seconds following attack termination).
- **Cause**: The 10-step lookback window ([S_{t-9}, ..., S_t]) contains lingering high-velocity state history, creating momentum inertia in recurrent cells.

### D. Low-Signal Infiltration Stealth
- Infiltration flows on Port 445 / SMB produce small packet counts (< 10 pkts/sec) that blend into normal internal enterprise file sharing.
- Supervised baselines suffer high false negative rates on Infiltration (F1 ~ 0.08 - 0.12) due to lack of unsupervised anomaly/stochastic latent tracking.
