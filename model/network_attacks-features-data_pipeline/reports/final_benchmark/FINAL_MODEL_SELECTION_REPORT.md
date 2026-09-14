# FINAL MODEL SELECTION & BENCHMARK AUDIT REPORT
**SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data**  
**Smart India Hackathon 2026 | NTRO Benchmark Standards**

---

## 1. Executive Selection Summary

Under the authoritative benchmark evaluation across **Setting A (In-Distribution)**, **Setting B (Temporal Generalization)**, and **Setting C (Out-of-Distribution / Zero-Day Generalization)**, the **Two-Stage Early-Warning + Confirmation Architecture with Temporal Incident Aggregation** is certified as the **SINGLE BEST OVERALL MODEL**.

### The Multi-Objective Decision Rule
To qualify for operational SOC deployment under NTRO specifications, a forecasting system must satisfy:
1. **False Alarm Constraint:** $\text{Incident FA/hr} \le 10.0$ (Mean Time Between False Alarms $\ge 6$ minutes).
2. **Early Warning Constraint:** $\text{Event-Level Onset Recall} \ge 90.0\%$ with $\text{Median Lead Time} \ge 10.0\text{ seconds}$.
3. **Detection Optimization:** Maximize Precision, Recall, and $-score while minimizing Missed Episodes ($= 0$).

---

## 2. Multi-Objective Evaluation of All Candidate Architectures

| Architecture | Passes FA Constraint ($\le 10$ FA/hr)? | Passes Onset Constraint ($\ge 90\%$ Recall)? | Passes Horizon Constraint ($\ge 10\text{s}$ Lead)? | Setting A $ | Setting B $ | Setting C $ | Overall Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Majority Class** | YES (0.00) | NO (0.0%) | NO (0.0s) | 0.00% | 0.00% | 0.00% | **REJECTED** (Trivial non-detector) |
| **Persistence ( \to y_{t+10}$)** | YES (0.00) | NO (0.0%) | NO (0.0s) | 94.25% | 99.66% | 99.66% | **REJECTED** (0% early warning) |
| **Logistic Regression** | NO (17.02 B/C) | YES (96.6% - 100%) | YES (20.0s) | 53.12% | 55.31% | 55.31% | **REJECTED** (High false alarms) |
| **Random Forest** | YES (4.99 - 8.91) | YES (96.6% - 100%) | YES (20.0s) | 52.69% | 56.00% | 56.00% | **REJECTED** (Low precision/F1) |
| **GRU Forecaster** | NO (10.08 - 26.17) | NO (42.9% - 57.1% B/C)| YES (20.0s) | 62.01% | 49.44% | 47.97% | **REJECTED** (Onset collapse on B/C) |
| **Temporal Transformer**| NO (11.78 - 28.14) | NO (28.6% B/C) | YES (20.0s) | 67.42% | 23.19% | 21.18% | **REJECTED** (Severe OOD decay) |
| **SparseRSSM (Raw)** | NO (11.82 - 34.12) | NO (42.9% B) | YES (20.0s) | 67.29% | 37.32% | 55.37% | **REJECTED** (High alert rate) |
| **SparseRSSM (Dual-Thresh)**| YES (0.62 - 4.24) | NO (0.0% B/C) | NO (0.0s B/C) | 81.51% | 23.86% | 21.53% | **REJECTED** (Destroys onset recall) |
| **TFCNet (Raw)** | NO (13.62 - 38.24) | YES (96.6% - 100%) | YES (20.0s) | 62.59% | 55.17% | 55.12% | **REJECTED** (High alert rate) |
| **TFCNet (Dual-Thresh)** | YES (1.82 - 11.20) | NO (57.1% - 71.4% B/C)| YES (20.0s) | 60.47% | 41.30% | 47.67% | **REJECTED** (Sub-threshold onsets) |
| **Hybrid Latent Fusion** | YES (7.12 - 14.12) | NO (28.6% - 42.9% B/C)| YES (20.0s) | 58.46% | 42.66% | 39.72% | **REJECTED** (Poor onset capture) |
| **Hybrid Dual-Thresh** | YES (0.58 - 0.81) | NO (0.0% B/C) | NO (0.0s B/C) | 85.70% | 20.49% | 20.02% | **REJECTED** (Complete onset loss) |
| **Two-Stage System (Aggregated)**| **YES (0.07 - 0.12)**| **YES (100.00% ALL)**| **YES (20.0s)** | **99.99%** | **99.94%** | **98.92%** | **SELECTED AS WINNER** |

---

## 3. Definitive Best Model: Two-Stage Early-Warning Architecture

### Key Performance Accomplishments
1. **Universal 100% Onset Detection:** Detected 29/29 episodes in Setting A, 7/7 episodes in Setting B, and 7/7 episodes in Setting C with **0 missed episodes**.
2. **Maximum Lead Time:** Achieved full 20.0-second anticipatory early-warning horizon across all detected attack episodes.
3. **Unprecedented False Alarm Suppression:** Achieved **0.07 FA/hr** in Setting A and **0.12 FA/hr** in Settings B/C ($< 1\text{ false alarm every 8 hours}$), far outperforming the 10 FA/hr operational ceiling.
4. **Superior Window-Level Accuracy:** Maintained $\ge 99.89\%$ Precision, $\ge 97.97\%$ Recall, and $\ge 98.92\% F_1$ across all three benchmark settings.

---

## 4. Next Phase Recommendations

1. **Phase 8 (Explainable AI & Precursor Feature Attribution):**
   - Implement Integrated Gradients and Integrated Spectral Attribution on TFCNet + SparseRSSM to identify the exact top-5 feature contributors for every Stage 1 early warning alert.
2. **Phase 9 (MITRE ATT&CK Knowledge Graph Mapping):**
   - Map confirmed multi-step attack state trajectories to MITRE ATT&CK tactics (Reconnaissance $\to$ Initial Access $\to$ Discovery $\to$ Impact / Exfiltration) to provide actionable SOC playbooks.
