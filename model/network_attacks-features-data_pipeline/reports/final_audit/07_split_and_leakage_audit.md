# 07 — Train / Validation / Test Split & Leakage Audit

## 1. Split Partitioning & Attack Family Distribution

| Partition | Calendar Dates | Capture Sessions | Attack Families Present | Specific Attack Types | State Windows | Attack Preval. |
|---|---|---|---|---|---|---|
| **Train** | 14, 15, 16, 21, 22 Feb 2018 | 5 daily captures | BruteForce, DoS, DDoS, WebAttack | FTP/SSH Brute, DoS Hulk/GoldenEye/Slowloris/SlowHTTPTest, DDoS HOIC/LOIC, Web Brute | 102,112 | 10.79% |
| **Validation** | 23 Feb 2018 | 1 daily capture | WebAttack | Web BruteForce, XSS, SQL Injection | 21,595 | 5.97% |
| **Test (OOD)** | 28 Feb, 01 Mar, 02 Mar 2018 | 3 daily captures | Infiltration, Botnet | Multi-stage Infiltration (Dropbox foothold + lateral exploit), Botnet ARES C2 | 64,785 | 29.13% |

## 2. Evaluation Paradigm Classification

**Classification: OUT-OF-DISTRIBUTION (OOD) ATTACK-FAMILY & CHRONOLOGICAL TEMPORAL GENERALIZATION.**

- **Justification:**
  1. The test partition consists entirely of unseen attack families: **Infiltration** and **Botnet (ARES)**. Neither family appears anywhere in the training or validation sets.
  2. The split is strictly chronological (Train: Feb 14–22, Val: Feb 23, Test: Feb 28 – Mar 02).
  3. No random sequence shuffling or IID cross-validation is used.

## 3. Strict Leakage Verification Matrix

| Leakage Category | Audit Check | Code Evidence | Result |
|---|---|---|---|
| **Label Leakage** | Are label columns included in the 54-D state $S_t$? | `STATE_FEATURE_NAMES` contains only continuous physical telemetry; `is_attack`, `family_idx`, etc. are strictly isolated targets. | **PASS** |
| **Temporal / Future Leakage** | Do future flows enter current windows? | `np.searchsorted` strictly enforces $[t_{	ext{start}}, t_{	ext{end}})$. | **PASS** |
| **Scaler Contamination** | Is `StandardScaler` fitted on validation/test data? | `TemporalSequenceBuilder.fit_scaler(train_dfs)` fits strictly on `train_dfs`. | **PASS** |
| **Day Boundary Leakage** | Do sliding sequences cross daily session boundaries? | `extract_session_sequences` operates per-file with $[0, N_{	ext{windows}} - 1 - K]$. | **PASS** |
| **Imputation Leakage** | Are infinite rates imputed using test statistics? | `convert_raw_to_canonical_parquet.py` computes median from training set. | **PASS** |
| **Threshold Leakage** | Were model decision thresholds tuned on test labels? | LR/RF use validation threshold tuning (`find_optimal_threshold(val_y, val_probs)`). RSSM uses fixed 0.5. | **PASS** |
