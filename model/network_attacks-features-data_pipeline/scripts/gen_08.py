doc = """# 08 — Final Dataset Selection Decision & Implementation Plan
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Executive Selection Decision

### 1.1 BEST PRIMARY DATASET:
# **Candidate A / C: Official CSE-CIC-IDS2018 (Processed Traffic Data for ML)** with DistriNet-Style Quality Filtering

### 1.2 SECONDARY / EXTERNAL GENERALIZATION DATASET:
# **Candidate D: Cleaned CIC-IDS-2017 (`chethuhn/network-intrusion-dataset`)** (Preserving Chronological Ordering)

### 1.3 DATASETS TO REJECT:
* **Candidate G (DARPA 1998)**: Completely obsolete 28-year-old SunOS synthetic traffic; 0.18% attack prevalence; corrupts modern network modeling.
* **Candidate E (Multi-Dataset CIC Collection)**: Uncurated concatenation creates severe domain fingerprinting.
* **Senior Hybrid Dataset (`combined_multidomain_dataset.parquet`)**: Formally retired (STATUS G).

---

## 2. Exact Files to Download & Acquire

From official AWS Open Data Registry (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`):

### Core Multi-Stage Attack Scenarios (Recommended Execution Set):
1. **`Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`** (Already present in local workspace: 1,048,575 flows; FTP-BruteForce & SSH-Bruteforce).
2. **`Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; DoS-GoldenEye & DoS-Slowloris).
3. **`Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; DoS-SlowHTTPTest & DoS-Hulk).
4. **`Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; DDoS-LOIC-UDP & DDoS-HOIC).
5. **`Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; Web Attacks: Brute Force, XSS, SQL Injection).
6. **`Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; Web Attacks continuation).
7. **`Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv`** (~613k flows; **Infiltration Phase 1: Foothold & Internal Reconnaissance**).
8. **`Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`** (~331k flows; **Infiltration Phase 2: Lateral Movement & Exfiltration**).
9. **`Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`** (~1.05M flows; **Botnet ARES C2 Communication**).

---

## 3. Storage & Download Specifications

* **Download Source**: AWS S3 (`--no-sign-request s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`).
* **Compressed Download Size**: ~1.5 GB total for the full 10-day CSV collection.
* **Uncompressed CSV Size**: ~8.2 GB.
* **Optimized Canonical Parquet Size**: **~1.8 GB** (using Snappy compression, optimal dtypes `float32`/`uint16`, and zero redundancy).
* **RAM Requirement**: Under 4.0 GB during streaming chunk-by-chunk processing.

---

## 4. End-to-End System Architecture

```
[Raw CSE-CIC-IDS2018 Daily CSVs]
              ↓
  [Chunked Memory-Efficient Loader]
              ↓
 [Data Hygiene: Sanity Filter (Fix negative duration, 0-div infs, clean duplicate headers)]
              ↓
 [Chronological Sorting & Non-Overlapping Daily Parquet Conversion]
              ↓
┌────────────────────────────────────────────────────────┐
│        DISCRETE TEMPORAL WINDOW AGGREGATOR             │
│   Converts flows into macro/subnet state vectors S_t   │
│   (Window Δt = 10s, Stride = 2s)                       │
│   - Flow volume, byte velocity, port entropy           │
│   - TCP flag ratios (SYN/ACK/RST/FIN)                  │
│   - IAT moments, window dynamics, active connection ct │
└────────────────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────────────────┐
│           LEAKAGE-FREE CHRONOLOGICAL SPLIT             │
│   - Train: Days 1 to 6 (14-02 to 22-02)                │
│   - Val:   Day 7 (23-02)                               │
│   - Test:  Days 8 to 10 (Infiltration & Botnet)        │
│   * StandardScaler & Imputer fitted STRICTLY on Train  │
└────────────────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────────────────┐
│           TEMPORAL TRANSFORMER WORLD MODEL             │
│   - Input: Historical trajectory [S_{t-9}, ..., S_t]   │
│   - Self-Attention Sequence Encoder                    │
│   - Latent Dynamics Transition Model: z_{t+K}          │
│   - Forecasting Head 1: Future Continuous State S_{t+K}│
│   - Forecasting Head 2: Anomaly / Attack Horizon Alert │
└────────────────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────────────────┐
│        DECOUPLED MITRE ATT&CK INTERPRETATION LAYER     │
│   Translates forecasted state anomalies into verified  │
│   Enterprise ATT&CK techniques (T1110, T1046, T1498...)│
│   with confidence intervals and observable evidence    │
└────────────────────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────────────────────┐
│        EXTERNAL GENERALIZATION VALIDATION              │
│   Evaluates zero-shot forecasting on clean CIC-IDS2017 │
└────────────────────────────────────────────────────────┘
```
"""

with open("reports/dataset_selection/08_final_dataset_recommendation.md", "w", encoding="utf-8") as f:
    f.write(doc.strip() + "\n")
print("Saved 08_final_dataset_recommendation.md")
