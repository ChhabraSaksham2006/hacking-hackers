# Phase 4.5 Forensic Audit: Report 19 — Out-of-Distribution (OOD) Generalization Forensic Analysis

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. The Attack Family Distribution Shift Matrix

| Dataset Partition | Days | Dominant Attack Families | Traffic Dynamics | MITRE Techniques |
|---|---|---|---|---|
| **Training** | Feb 14, 15, 16, 21, 22 | FTP/SSH BruteForce, DoS (Slowloris, Hulk, GoldenEye), DDoS (HOIC, LOIC) | High-volume connection floods, port saturation | T1110.001, T1498.001, T1499.003 |
| **Validation** | Feb 23 | Web Attacks (Brute-Web, XSS, SQL Injection) | Bursty, short-duration application attacks | T1110.001, T1190 |
| **Test (OOD)** | Feb 28, Mar 01, Mar 02 | Multi-stage Infiltration (Days 1 & 2), Botnet ARES C2 | Stealthy lateral movement, periodic C2 beaconing | T1210, T1071.001 |

## 2. Empirical OOD Performance Breakdown (Transformer Baseline)

| Attack Campaign | Horizon | Samples | Attack Prevalence | PR-AUC | ROC-AUC | Precision | Recall | $F_1$ Score |
|---|---|---|---|---|---|---|---|---|
| **Infiltration Day 1 (Feb 28)** | $K=1$ | 21,576 | 18.53% | 0.3609 | 0.7219 | 0.5664 | 0.0683 | 0.1219 |
| **Infiltration Day 2 (Mar 01)** | $K=1$ | 21,576 | 21.59% | 0.3130 | 0.6059 | 0.7067 | 0.0455 | 0.0855 |
| **Infiltration Combined** | $K=1$ | 43,152 | 20.06% | **0.3349** | 0.6696 | 0.6202 | 0.0560 | **0.1028** |
| **Botnet ARES (Mar 02)** | $K=1$ | 21,576 | 47.27% | **0.5620** | 0.6821 | **0.7939** | 0.0230 | 0.0448 |
| **Total Test OOD Partition** | $K=1$ | 64,728 | 29.13% | **0.4453** | 0.7184 | 0.6679 | 0.0382 | 0.0722 |

## 3. Forensic Root Cause: Why Botnet Transfers Better Than Infiltration

1. **Volumetric & Pacing Signatures:** Botnet ARES generates periodic C2 communication with elevated connection rates and distinctive port concentration. Because sequence models learned rate dynamics and port entropy shifts from DoS/DDoS, they achieve **79.39% precision** on Botnet zero-shot.
2. **Stealthy Infiltration Submergence:** Infiltration features low-amplitude internal scanning and reconnaissance flows that mimic normal background noise. Without stochastic latent state estimation, deterministic models fail to capture the subtle phase transition, yielding low recall (5.6%).
3. **Scientific Value:** This establishes the exact empirical baseline gap that the proposed **Recurrent State Space Model (RSSM)** must resolve through probabilistic latent world modeling.
