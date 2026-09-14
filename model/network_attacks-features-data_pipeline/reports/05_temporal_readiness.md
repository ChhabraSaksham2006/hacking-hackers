# 05 — Temporal Information & Forecasting Readiness Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Audit of Temporal Information in Current Dataset

| Temporal Attribute | Present in DARPA Subset? | Present in Projected CIC-IDS2017? | Present in Wednesday-2018 CSV? | Impact on Temporal Forecasting |
| :--- | :---: | :---: | :---: | :--- |
| **Epoch Timestamp** | Yes (`window_start_time`, `window_end_time`) | **NO** (Only relative float indices) | Yes (`Timestamp` string) | Loss of global temporal clock in combined dataset. |
| **Strict Chronological Order** | Yes (Sorted 10s sliding windows) | **NO (Explicitly Shuffled via `df.sample(frac=1.0)`)** | Yes (Monotonically non-decreasing) | **FATAL**: Shuffled flows create synthetic, nonsensical sequences. |
| **Flow Duration / Velocity** | Yes (Delta features $\Delta S_t = S_t - S_{t-1}$) | Artificial (Flow Duration treated as window) | Yes (`Flow Duration`) | Mismatch between window velocity and flow duration. |
| **Source / Destination IP** | Aggregated (`unique_src_ips`, `unique_dst_ips`) | **Hardcoded Constant (1.0)** | Raw IP dropped in CICFlowMeter | Inability to track multi-stage attacker IP migration. |
| **Port / Protocol Diversity** | Dynamic Shannon Entropy | **Hardcoded Constant (0.0)** | Aggregated statistics | Attackers scanning multiple ports cannot be distinguished from single-port traffic. |

---

## 2. Core Readiness Evaluation (Questions A through F)

### A. Can the current dataset support static attack classification?
* **Verdict**: **YES (Partially)**
* **Evidence**: The static flow vectors in `Wednesday-14-02-2018` and `windows_cic_*.parquet` retain flow-level discriminative features (packet lengths, TCP flags, IATs) allowing models like Logistic Regression or Random Forest to achieve high F1 scores for single-flow detection.

### B. Can the current dataset support sequence modelling?
* **Verdict**: **NO (in its current merged state)**
* **Evidence**: The sequence dataset generator (`UnifiedMultiDomainDataset`) builds sliding sequences of length $P=10$ across rows of `windows_cic_*.parquet`. Because these files were randomly shuffled during preprocessing (`src/cic_feature_adapter.py:203`), each sequence is a random concatenation of 10 unrelated flows from different times, users, and machines.

### C. Can the current dataset support temporal state modelling?
* **Verdict**: **NO**
* **Evidence**: True temporal state modeling requires discrete window aggregation ($S_t$) computed over continuous traffic captures. In the combined dataset, DARPA represents genuine 10s state vectors, while CIC-IDS2017 represents individual isolated flow conversations with hardcoded constant features.

### D. Can the current dataset support next-step forecasting ($S_{t+1}$)?
* **Verdict**: **NO**
* **Evidence**: Predicting $S_{t+1}$ on shuffled data is predicting white noise. The LSTM world model learned an artificial statistical average rather than actual network transitions.

### E. Can the current dataset support multi-step forecasting ($S_{t+K}$ for $K \in \{1, 3, 5, 10\}$)?
* **Verdict**: **NO**
* **Evidence**: The autoregressive rollout degrades immediately because transition dynamics cannot be learned from randomly ordered records.

### F. Can the current dataset support attack progression modelling?
* **Verdict**: **NO**
* **Evidence**: Multi-stage attack progression (e.g., Reconnaissance $	o$ Initial Access $	o$ Privilege Escalation $	o$ Exfiltration) requires chronological multi-hour continuity across the same target network. The current dataset mixes isolated attacks from separate days and benchmarks.
