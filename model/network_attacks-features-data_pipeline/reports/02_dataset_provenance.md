# 02 — Dataset Provenance Forensics & Kaggle Audit
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
