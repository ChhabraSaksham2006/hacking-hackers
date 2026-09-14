import os

reports = {}

reports["01_repository_audit.md"] = """# 01 — Comprehensive Repository Forensic Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  
**Audited Repository**: `https://github.com/ArihantSrivastava2225/network_attacks`  
**Audit Date**: September 2026  
**Auditor**: Antigravity Autonomous Forensic Engine  

---

## 1. Executive Summary

A comprehensive forensic audit of the Git history, commit graph, source files, and dataset artifacts was conducted across all branches of `ArihantSrivastava2225/network_attacks`.

The repository contains three primary Git branches that represent fragmented and diverging attempts at solving SIH26153:
1. `main` (commit `6b422e7`): The bare initial commit containing only raw DARPA PCAP sample slices and rudimentary Jupyter notebooks.
2. `feature/world-model-dataset-darpaWithCICIDS` (commit `a03c477`): Contains a 47-dimensional multi-domain dataset pipeline attempting to merge 1998 DARPA PCAP temporal windows with 2017 CIC-IDS flow CSVs, alongside an LSTM-based world model.
3. `features/lakshay_ml` (commit `d03a94f`): Contains a standalone exploratory data analysis (EDA), anomaly audit, feature engineering, and Logistic Regression baseline pipeline built on a single day of CSE-CIC-IDS2018 (`Wednesday-14-02-2018`).

---

## 2. Branch Topology & Responsibility Mapping

| Branch Name | Latest Commit | Author & Date | Primary Purpose / Contents | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| `main` | `6b422e7` | Arihant Srivastava (Aug 29, 2026) | Initial commit: `DARPA_eval_b` PCAPs, `create_notebook.py`, `data_exploration.ipynb`. | Obsolete / Incomplete |
| `feature/world-model-dataset-darpaWithCICIDS` | `a03c477` | Arihant Srivastava (Sep 2, 2026) | 47-D State Vector engine, Parquet files (`combined_multidomain_dataset.parquet`), Dual-Head LSTM World Model (`world_model.py`), MITRE mapping. | Severely Flawed Pipeline (Shuffled flows, Hardcoded features, Unicode bug) |
| `features/lakshay_ml` | `d03a94f` | Lakshay (Sep 3, 2026) | Clean Scikit-Learn baseline pipeline, memory-efficient loader, 80-feature EDA, Logistic Regression baseline on 1M CSE-CIC-IDS2018 flows. | Methodologically Sound Baseline (Static Classification Only) |

---

## 3. Answers to Core Repository Inquiries

### Q1: What branch is considered the main/primary branch?
**`main`** is configured as the default GitHub branch, but it contains **only the initial skeletal commit** (`6b422e7`). It does not contain any of the finished ML pipelines or dataset transformations.

### Q2: What branch contains the latest ML work?
* **For Temporal World Modeling**: `feature/world-model-dataset-darpaWithCICIDS` (commit `a03c477`, Sep 2, 2026).
* **For Rigorous Baseline & EDA**: `features/lakshay_ml` (commit `d03a94f`, Sep 3, 2026).

### Q3: What branch contains the complete dataset?
`feature/world-model-dataset-darpaWithCICIDS` contains the 92.4 MB `combined_multidomain_dataset.parquet` (1,545,739 rows) and 13 individual Parquet files (5 DARPA Week 1 days + 8 CIC session parquets).

### Q4: What branch contains preprocessing?
* `feature/world-model-dataset-darpaWithCICIDS`: `src/temporal_aggregator.py`, `src/feature_extractor.py`, `src/cic_feature_adapter.py`, `src/build_dataset.py`.
* `features/lakshay_ml`: `src/preprocessing.py`, `src/data_loader.py`, `src/feature_engineering.py`.

### Q5: What branch contains MITRE mappings?
`feature/world-model-dataset-darpaWithCICIDS` (`src/mitre_mapping.py`, `src/cic_mapping.py`).

### Q6: What branch contains DARPA integration?
`feature/world-model-dataset-darpaWithCICIDS` (`src/build_dataset.py`, `src/temporal_aggregator.py`, `data/backup_darpa_week1/`).

### Q7: What branch contains trained models?
* `feature/world-model-dataset-darpaWithCICIDS`: `models/unified_world_model_best.pt` (1.2 MB PyTorch checkpoint) and `models/world_model_lstm_best.pt` (3.6 MB).
* `features/lakshay_ml`: `models/logistic_regression_pipeline.joblib` (10 KB Scikit-Learn pipeline).

### Q8: What branch contains reports/results?
* `features/lakshay_ml`: `reports/baseline_results.md`, `reports/eda_report.md`, `reports/feature_audit.csv`, and visualization heatmaps.
* `feature/world-model-dataset-darpaWithCICIDS`: `results/batch_thursday_test.json`, `results/live_stream_alerts.jsonl`.
"""

reports["02_dataset_provenance.md"] = """# 02 — Dataset Provenance Forensics & Kaggle Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Investigation of Kaggle Dataset `chethuhn/network-intrusion-dataset`

The team originally referenced `https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset`.

### Forensic Verdict on Kaggle Dataset:
* **True Identity**: **CIC-IDS-2017** (Canadian Institute for Cybersecurity, University of New Brunswick, 2017).
* **Is it CSE-CIC-IDS2018?**: **NO.** The files, timestamps, column names, and attack distributions match the 2017 benchmark, NOT the 2018 AWS CSE-CIC-IDS2018 dataset.
* **Number of Files**: 8 CSV files (`Friday-WorkingHours-Morning.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, `Monday-WorkingHours.pcap_ISCX.csv`, `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv`).
* **Total Rows**: 2,830,743 rows.
* **Columns**: 79 numerical features + 1 Label column (`CICFlowMeter-V1` format).
* **Citation**: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward generating a new intrusion detection dataset and intrusion traffic characterization*. ICISSP.

---

## 2. Provenance Matrix Across All Repository Artifacts

| File / Artifact | Source Dataset | Rows | Columns | Labels Present | True Timestamp? | Forensic Evidence |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| `data/csv/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | **CSE-CIC-IDS2018** | 1,048,575 | 80 | Benign (63.7%), FTP-BruteForce (18.4%), SSH-Bruteforce (17.9%) | Yes (`dd/MM/yyyy HH:mm:ss`) | Official CSE-CIC-IDS2018 Day 2 file; contains Patator brute force attacks from Feb 14, 2018. |
| `data/processed_cic/windows_cic_*.parquet` (8 files) | **CIC-IDS2017** (Subsampled) | 1,355,364 | 52 | 15 attack classes (DDoS, PortScan, Hulk, Patator, Web, Bot) | **DESTROYED** | Produced by `src/cic_feature_adapter.py` by sampling & **shuffling** CIC-IDS2017 CSVs. |
| `data/processed/windows_*_dt10s.parquet` (5 files) | **DARPA 1998 Week 1** | 190,375 | 104 | Normal (99.3%), U2R exploits (`ffb`, `fdformat`, `loadmodule`), DoS (`smurf`, `pod`, `teardrop`) | Yes (10s epoch windows) | Extracted directly from DARPA 1998 tcpdump/BSM PCAPs via Scapy. |
| `data/combined_multidomain_dataset.parquet` | **DARPA 1998 + CIC-IDS2017** | 1,545,739 | 107 | 23 mixed attack classes mapped to 5 stages | **CORRUPTED** | Direct concatenation of 10s DARPA windows + shuffled CIC-IDS2017 individual flow records. |
"""

reports["05_temporal_readiness.md"] = """# 05 — Temporal Information & Forecasting Readiness Audit
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
* **Evidence**: Multi-stage attack progression (e.g., Reconnaissance $\to$ Initial Access $\to$ Privilege Escalation $\to$ Exfiltration) requires chronological multi-hour continuity across the same target network. The current dataset mixes isolated attacks from separate days and benchmarks.
"""

reports["06_darpa_integration_audit.md"] = """# 06 — DARPA 1998 Week 1 Integration Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. DARPA 1998 Week 1 Forensic Breakdown

* **Dataset Origin**: 1998 DARPA / Lincoln Laboratory Intrusion Detection Evaluation.
* **Environment**: Simulated SunOS/Solaris 2.5 and Linux network from 1998.
* **Traffic Nature**: Synthetic background telnet, rsh, ftp, and smtp traffic generated by scripted user emulators.
* **Files Used**: Week 1 tcpdump PCAPs (`monday.pcap`, `tuesday.pcap`, `wednesday.pcap`, `thursday.pcap`, `friday.pcap`).
* **Total Generated Windows**: 190,375 sliding windows (10s window, 2s step size).
* **Attack Representation**:
  * Total Attack Windows: 343 out of 190,375 (0.18% attack prevalence).
  * Attacks: `ffb_clear` (124), `format_clear` (63), `load_clear` (45), `smurf` (23), `perl_clear` (19), `dict_simple` (13), `teardrop` (6), `pod` (6), `neptune` (5).

---

## 2. Integration Forensic Classification

### Classification: **F. INCORRECTLY MIXED WITH CIC DATA**

### Forensic Proof:
1. **Temporal Scale Mismatch**:
   * DARPA records represent **10-second aggregations** containing hundreds of packets across the entire network.
   * CIC-IDS2017 records represent **single bidirectional flow conversations** lasting fractions of a second.
2. **Artificial Constant Feature Projections**:
   To force CIC-IDS2017 into the 47-D DARPA schema, `src/cic_feature_adapter.py` hardcoded 18 features to constants:
   * `tcp_ratio = 1.0` (Hardcoded)
   * `udp_ratio = 0.0` (Hardcoded)
   * `icmp_ratio = 0.0` (Hardcoded)
   * `unique_src_ips = 1.0` (Hardcoded)
   * `unique_dst_ips = 1.0` (Hardcoded)
   * `port_entropy = 0.0` (Hardcoded)
   * `ttl_mean = 64.0` (Hardcoded)
   * `fragment_count = 0.0` (Hardcoded)
3. **Domain Shortcut Leakage**:
   A machine learning classifier or world model does not learn attack dynamics; it learns to separate **DARPA (where `unique_src_ips` varies and `ttl` has variance)** from **CIC (where `unique_src_ips` is strictly 1.0 and `ttl` is strictly 64.0)**.
"""

reports["07_mitre_mapping_audit.md"] = """# 07 — MITRE ATT&CK Mapping Quality Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Audit of the Existing 5-Stage Heuristic Taxonomy

The repository collapses network security events into 5 sequential stage codes (0 through 4):
* `Stage 0`: Benign Baseline
* `Stage 1`: Reconnaissance (TA0043)
* `Stage 2`: Initial Access (TA0001) / Credential Access (TA0006)
* `Stage 3`: Lateral Movement (TA0008) / Execution (TA0002)
* `Stage 4`: Denial of Service (Impact TA0040)

### Scientific Critique:
* **Tactics vs. Stages**: In real-world cyber campaigns, MITRE ATT&CK tactics are **objectives (WHY)**, not strict temporal sequence stages. An adversary can perform DoS as a diversion before initial access, or execute brute force credential guessing across multiple hosts internally.
* **Forced Linearity**: Forcing attacks into stages 0..4 creates artificial transition expectations ($1 \to 2 \to 3 \to 4$) that do not reflect genuine multi-path cyber campaigns.

---

## 2. Discovery of Critical Silent Encoding Bug

In `data/processed_cic/windows_cic_Thursday-WorkingHours-Morning-WebAttacks.parquet`:
* **Raw Labels Present**: `Web Attack  Brute Force` (1,507), `Web Attack  XSS` (652), `Web Attack  Sql Injection` (21).
* **Assigned Stage Codes in Parquet**: **`Stage 0: 102,180` (100% Benign)**.
* **Root Cause**: In `src/cic_mapping.py`, the mapping dictionary contained string literals with `\x96` and `-`, but the CSV was parsed with Unicode replacement characters (`\ufffd`). The dictionary lookup failed and defaulted to `return 0`.
* **Impact**: **2,180 web attack records were silently mislabeled as Benign Baseline traffic**.

---

## 3. Verified MITRE ATT&CK Forensic Mapping Hierarchy

| Observed Raw Label | Attack Family | Candidate Technique ID | Technique Name | MITRE Tactic | Mapping Confidence | Evidence / Source |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `FTP-Patator` / `FTP-BruteForce` | Credential Access | **T1110.001** | Password Guessing | Credential Access (TA0006) | **VERIFIED** | Automated port 21 dictionary authentication |
| `SSH-Patator` / `SSH-Bruteforce` | Credential Access | **T1110.001** | Password Guessing | Credential Access (TA0006) | **VERIFIED** | Automated port 22 dictionary authentication |
| `PortScan` / `portsweep` | Reconnaissance | **T1046** | Network Service Discovery | Discovery (TA0007) / Recon (TA0043) | **VERIFIED** | Systematic TCP SYN / connect scanning |
| `DoS Hulk` / `DDoS` | Denial of Service | **T1498.001** | Direct Network Flood | Impact (TA0040) | **STRONGLY_SUPPORTED** | High-volume HTTP/UDP volumetric flooding |
| `DoS slowloris` / `GoldenEye` | Application DoS | **T1499.003** | App Exhaustion Flood | Impact (TA0040) | **STRONGLY_SUPPORTED** | Connection pool & HTTP header starvation |
| `Heartbleed` | Exploitation | **T1212** | Exploitation for Credential Access | Credential Access (TA0006) | **VERIFIED** | OpenSSL TLS Heartbeat buffer over-read (CVE-2014-0160) |
| `Infiltration` | Lateral Movement | **T1210 / T1567** | Exploitation of Remote Services | Lateral Movement (TA0008) | **HEURISTIC** | Multi-stage victim compromise & payload download |
| `Bot` | C2 Communication | **T1071.001** | Web Protocols | Command and Control (TA0011) | **STRONGLY_SUPPORTED** | ARES HTTP botnet beaconing |
| `U2R-ffbconfig` / `fdformat` | Privilege Escalation | **T1068** | Exploitation for Privilege Escalation | Privilege Escalation (TA0004) | **STRONGLY_SUPPORTED** | Local buffer overflow execution on Solaris |
"""

reports["08_leakage_audit.md"] = """# 08 — Data Leakage & Evaluation Splitting Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Identified Data Leakage Vulnerabilities

### Leakage Vulnerability 1: Pre-Split Normalization Fitting
* **Location**: `src/dataset_unified_sequence.py:45-54`
* **Defect**: The `StandardScaler` is fitted on `concat_features` representing the **entire dataset across all sessions** before splitting into train and test subsets.
* **Consequence**: Test set statistics (mean and variance) leak directly into training inputs.

### Leakage Vulnerability 2: Flow Row Shuffling Before Sequence Generation
* **Location**: `src/cic_feature_adapter.py:203`
* **Defect**: `df_sampled = df_sampled.sample(frac=1.0, random_state=42)` randomly shuffles flow records before they are saved to Parquet. When `UnifiedMultiDomainDataset` takes sequential slices $[0 \dots 0.8]$ as train and $[0.8 \dots 1.0]$ as test, both splits contain identical mixtures of flows from the same capture session.
* **Consequence**: Test performance is artificially inflated because the test set contains flows that occurred concurrently with training flows.

### Leakage Vulnerability 3: Synthetic Sequence Formation
* **Location**: `src/dataset_unified_sequence.py:82-88`
* **Defect**: Sequence windows are constructed over pre-shuffled flow records. A sequence $[x_{t-9}, \dots, x_t]$ does not represent 10 consecutive seconds in the network, but 10 randomly sampled flows from arbitrary connections.

---

## 2. Recommended Leakage-Free Splitting Strategy

To ensure genuine temporal attack forecasting:
1. **Strict Chronological Splitting**:
   * **Train**: Days 1 to 6 (e.g. Wednesday 14 Feb to Tuesday 20 Feb 2018).
   * **Validation**: Day 7 (Wednesday 21 Feb 2018).
   * **Test**: Days 8 to 10 (Thursday 22 Feb to Friday 23 Feb 2018).
2. **Fit-Transform Isolation**: All scalers, imputers, and encoders must be fitted **strictly on the training partition**.
3. **Session-Level Isolation**: No sequence lookback or temporal state window may cross independent capture days.
"""

reports["10_data_quality_report.md"] = """# 10 — Data Quality, Anomaly & Distribution Report
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Comprehensive Anomaly & Quality Metrics

| Dataset Partition | Total Records | Missing / NaN Values | Infinite ($\pm \infty$) Values | Duplicate Rows | Zero-Variance Columns | Timestamp Integrity |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `CSE-CIC-IDS2018 (Wednesday)` | 1,048,575 | 2,277 (`Flow Byts/s`) | 5,371 (`Flow Byts/s`, `Flow Pkts/s`) | 296,673 (28.3%) | 10 columns | 5 records with negative duration & 1970 timestamps |
| `Projected CIC-IDS2017 (8 Parquets)` | 1,355,364 | 0 (Imputed) | 0 (Clamped) | 299,491 (22.1%) | 18 columns (Hardcoded) | Destroyed (Randomly shuffled) |
| `DARPA 1998 Week 1 (5 Parquets)` | 190,375 | 0 | 0 | 0 (0.0%) | 0 columns | Valid 10s monotonic sliding windows |
| `Combined Multidomain Parquet` | 1,545,739 | 0 | 0 | 299,491 (19.4%) | 0 columns | Incoherent (Mixed scales & destroyed order) |

---

## 2. Duplicate Flow Forensic Analysis

* In `windows_cic_Friday-WorkingHours-Afternoon-PortScan.parquet`, **63.67% of records are exact duplicates**.
* **Forensic Verdict**: These are **legitimate high-frequency network attack artifacts**. Port scanners (like Nmap) emit identical TCP SYN probe packets with identical window sizes, flags, and headers to consecutive destination ports.
* **Handling Decision**: Duplicates must **NOT be blindly deleted**, as deleting them destroys true packet arrival rates and connection velocity metrics essential for forecasting.
"""

reports["11_final_dataset_decision.md"] = """# 11 — Final Dataset Readiness Decision & Reconstruction Roadmap
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Final Dataset Readiness Decision

### EXACT STATUS:
# **STATUS G: CURRENT DATASET SHOULD NOT BE USED AS THE PRIMARY TRAINING DATASET**

---

## 2. Scientific & Empirical Justification

1. **Destruction of Temporal Continuity**: The CIC-IDS2017 flow dataset was randomly shuffled during preprocessing (`src/cic_feature_adapter.py`), destroying all temporal ordering. Sequences fed into the LSTM world model were synthetic random permutations.
2. **Artificial Feature Corruption**: 18 out of 47 features were hardcoded to constant values for the CIC data, making multi-domain learning an exercise in dataset fingerprinting rather than attack dynamics forecasting.
3. **Obsolete DARPA Environment**: DARPA 1998 represents a 28-year-old simulated SunOS network with 0.18% attack prevalence and obsolete exploits (`fdformat`, `loadmodule`), incapable of generalizing to modern cloud/enterprise networks.
4. **Silent Label Mislabling**: 2,180 web attack flows were mislabeled as Benign Baseline traffic due to a Unicode encoding mismatch in `cic_mapping.py`.

---

## 3. Canonical Dataset Architecture & Transition Plan

To build a research-grade temporal attack forecasting system:
1. **Primary Benchmark**: Adopt **NF-CSE-CIC-IDS2018-v2** (Sarhan et al., University of Queensland) or the full **CSE-CIC-IDS2018** official dataset.
2. **Temporal State Construction ($S_t$)**: Group continuous flows into discrete chronological time windows ($\Delta t = 5\text{s}, 10\text{s}, 30\text{s}$).
3. **Sequential Modeling**: Form true sliding trajectories $[S_{t-9}, \dots, S_t]$ to forecast future state $S_{t+K}$ and attack progression timelines.
4. **Two-Layer Decoupled MITRE Interpretation**:
   * Layer 1: Neural World Model predicts continuous network dynamics $S_{t+K}$.
   * Layer 2: Rule-based / probabilistic interpreter maps predicted anomalous behavior to MITRE ATT&CK techniques (T1046, T1110, T1498, T1190).
"""

for fname, content in reports.items():
    fpath = os.path.join("reports", fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"Written: {fpath}")

print("\nAll 8 markdown reports successfully generated in reports/")
