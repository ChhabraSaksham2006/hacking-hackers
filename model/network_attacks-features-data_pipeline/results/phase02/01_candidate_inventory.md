# 01 — Candidate Dataset Inventory & In-Depth Forensic Analysis
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Subsystem**: Dataset Selection & Forensic Architecture Verification  
**Evaluation Date**: September 2026  

---

## 1. Scope & Forensic Ground Rules

Following the audit verdict of **STATUS G** on the senior hybrid dataset (`combined_multidomain_dataset.parquet`), our goal is to select and construct a scientifically defensible dataset from scratch.

A temporal network attack forecasting system learns:
$$\text{History: } [S_{t-P+1}, \dots, S_t] \longrightarrow \text{Temporal Dynamics: } P(S_{t+K} \mid S_{\le t}) \longrightarrow \text{Forecast Horizon: } [S_{t+1}, \dots, S_{t+K}]$$

This demands:
1. Genuine, non-shuffled chronological continuity.
2. Authentic flow timestamps and valid inter-arrival dynamics.
3. Realistic attack diversity across multi-stage kill chains.
4. Clean feature distributions without hardcoded constant fingerprints.
5. High research credibility, reproducibility, and computational feasibility.

---

## 2. In-Depth Candidate Evaluations

### Candidate A: Official CSE-CIC-IDS2018 (Processed Traffic Data for ML)
* **Origin**: Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (UNB), 2018.
* **Hosting**: AWS Open Data Registry (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`) and UNB CIC.
* **Volume**: 16,233,002 network flows across 10 distinct capture days (~450 GB raw PCAP, ~8 GB CSV, ~1.8 GB Parquet).
* **Feature Schema**: 80 features extracted by `CICFlowMeter-V3` (`Dst Port`, `Protocol`, `Timestamp`, `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, packet length moments, inter-arrival time moments, flag counts, window statistics, subflow stats, active/idle periods).
* **Timestamps**: Explicit flow start timestamps formatted as `dd/MM/yyyy HH:mm:ss` (e.g., `14/02/2018 08:31:01`).
* **Scenario Architecture**:
  * Day 1 (14-02-2018): FTP-BruteForce, SSH-Bruteforce.
  * Day 2 (15-02-2018): DoS-GoldenEye, DoS-Slowloris.
  * Day 3 (16-02-2018): DoS-SlowHTTPTest, DoS-Hulk.
  * Day 4 (20-02-2018): DDoS-LOIC-HTTP.
  * Day 5 (21-02-2018): DDoS-LOIC-UDP, DDoS-HOIC.
  * Day 6 (22-02-2018): Brute Force Web, XSS, SQL Injection.
  * Day 7 (23-02-2018): Brute Force Web, XSS, SQL Injection.
  * Day 8 (28-02-2018): Infiltration (internal reconnaissance & payload staging).
  * Day 9 (01-03-2018): Infiltration (lateral movement & privilege escalation).
  * Day 10 (02-03-2018): Botnet (ARES C2 communication & internal scanning).
* **Forensic Evaluation**: **EXCELLENT**. Contains the complete multi-scenario attack progression timeline needed for longitudinal forecasting.

---

### Candidate B: NF-CSE-CIC-IDS2018-v2 (University of Queensland)
* **Origin**: Dr. Mohanad Sarhan, Dr. Siamak Layeghy, Dr. Marius Portmann (University of Queensland, 2022).
* **Hosting**: UQ eSpace (DOI: `10.48610/e9636b7`) and Kaggle Parquet release.
* **Volume**: 18,893,708 NetFlow records (16,635,567 Benign [88.05%], 2,258,141 Attack [11.95%]).
* **Feature Schema**: 43 standardized NetFlow features + `Attack` + `Label`.
  * Core attributes: `IPV4_SRC_ADDR`, `L4_SRC_PORT`, `IPV4_DST_ADDR`, `L4_DST_PORT`, `PROTOCOL`, `L7_PROTO`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`, `TCP_FLAGS`, `FLOW_DURATION_MILLISECONDS`, `MIN_TTL`, `MAX_TTL`, etc.
* **Timestamps**: Features are standardized on flow summary records. However, in the standard ML Parquet release, raw start/end timestamps are stripped to prevent trivial shortcut memorization.
* **Forensic Evaluation**: While exceptional for static NetFlow benchmarking, the removal of microsecond-level wall-clock timestamps in the pre-packaged Parquet files limits native sliding-window state aggregation ($S_t$) compared to raw chronological CSV processing. It serves as an **outstanding feature reference and secondary benchmark**.

---

### Candidate C: CSE-CIC-IDS2018 Improved (DistriNet / KU Leuven)
* **Origin**: Gints Engelen, Vera Rimmer, Wouter Joosen (DistriNet Research Unit, KU Leuven, 2021).
* **Focus**: Documenting and fixing systematic flaws in CICFlowMeter (miscalculated flow durations, faulty TCP flag tracking, inter-arrival time bugs, and mislabeled flows).
* **Corrections Provided**: Fixed PCAP-to-CSV re-extraction scripts (`CICFlowMeter-fixed`), patch manifests, and corrected label files for CIC-IDS2017 / CSE-CIC-IDS2018.
* **Forensic Evaluation**: Crucial validation source. The DistriNet audit proved that up to 7.5% of flows in the original CICFlowMeter extraction had labeling or duration anomalies (such as negative durations and missing packets). Preprocessing must implement DistriNet-style sanity filtering.

---

### Candidate D: Kaggle `chethuhn/network-intrusion-dataset` (CIC-IDS-2017)
* **Origin**: Uploaded by Chethuhn on Kaggle; verified to be **CIC-IDS-2017** (ISCX / UNB).
* **Volume**: 2,830,743 flows across 8 CSV files.
* **Feature Schema**: 79 features + `Label`.
* **Timestamps**: Stored as strings (`dd/MM/yyyy HH:mm:ss`). In the "MachineLearningCSV" version, IP addresses are omitted.
* **Forensic Evaluation**: **UNSUITABLE AS PRIMARY DATASET**, but **HIGHLY VALUABLE AS AN EXTERNAL ZERO-SHOT TEST BENCHMARK**. It contains similar attack families (PortScan, DoS, DDoS, Patator, Web Attacks) captured on a completely different 2017 testbed, enabling true out-of-distribution evaluation.

---

### Candidate E: Multi-Dataset CIC Collection (2017 + 2018 + DoS2017 + DDoS2019)
* **Origin**: Aggregated datasets from Canadian Institute for Cybersecurity.
* **Forensic Evaluation**: **REJECTED FOR PRIMARY TRAINING**. Merging datasets from different years (2017, 2018, 2019) without strict domain adaptation creates domain shortcut learning (the model classifies the testbed IP subnet / capture year rather than temporal attack dynamics).

---

### Candidate F: BigFlow-NIDS (Mendeley Data 2026)
* **Origin**: Mendeley Data repository (2026), harmonizing NetFlow across CSE-CIC-IDS2018, UNSW-NB15, and ToN-IoT.
* **Forensic Evaluation**: **REJECTED AS PRIMARY TRAINING DATASET**. Over-harmonized feature representations obscure subtle TCP flag timing dynamics necessary for attack lead-time forecasting.

---

### Candidate G: DARPA 1998 (Week 1 / Week 2)
* **Origin**: MIT Lincoln Laboratory / DARPA (1998).
* **Forensic Evaluation**: **COMPLETELY REJECTED**. 28-year-old synthetic SunOS/Solaris traffic, 0.18% attack prevalence, obsolete exploits (`fdformat`, `loadmodule`), and zero relevance to modern TCP/IP enterprise environments.
