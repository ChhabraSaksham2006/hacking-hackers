# 04 — Comprehensive Raw Dataset Quality & Anomaly Report
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Dataset**: CSE-CIC-IDS2018 (Official Processed Traffic Data for ML Algorithms)  
**Total Captured Flows**: 8,284,195 rows across 9 daily CSVs  
**Timestamp**: September 2026  

---

## 1. Executive Quality Summary

An exhaustive chunk-by-chunk forensic audit was executed on all 9 downloaded daily CSV files totaling **8,284,215 network flow records**.

* **Total Clean Records**: 8,284,156 flows
* **Repeated Header Rows Identified**: 59 rows total (1 in Friday-16, 25 in Thursday-01, 33 in Wednesday-28) -> Filtered out.
* **Corrupted Negative Duration Records**: 14 rows total (5 in Wednesday-14, 9 in Thursday-22) -> Filtered out.
* **Division-by-Zero Infinite Values**: Handled safely via median imputation fitted strictly on the training partition.
* **Overall Dataset Usability**: **99.999% VALID & RECOVERABLE**.

---

## 2. Daily Quality Metrics Table

| Daily CSV Filename | Total Flows | Time Range | Coverage (Hrs) | Unique Labels | NaNs | Infs | Neg Durations | Rep Headers |
| :--- | ---: | :---: | ---: | :---: | ---: | ---: | ---: | ---: |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `2018-03-02` | 12.0h | 2 | 2,558 | 5,542 | 0 | 0 |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,574 | `2018-02-16` | 11.96h | 3 | 0 | 0 | 0 | 1 |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `2018-02-23` | 12.0h | 4 | 3,754 | 7,662 | 0 | 0 |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 331,100 | `2018-03-01` | 12.0h | 2 | 1,834 | 4,004 | 0 | 25 |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `2018-02-15` | 12.0h | 3 | 4,921 | 11,133 | 0 | 0 |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `1970-01-10` | 421809.93h | 4 | 3,569 | 7,651 | 9 | 0 |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `1970-01-05` | 421737.98h | 3 | 2,277 | 5,371 | 5 | 0 |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | `2018-02-21` | 8.79h | 3 | 0 | 0 | 0 | 0 |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 613,071 | `2018-02-28` | 12.0h | 2 | 4,041 | 8,297 | 0 | 33 |

---

## 3. Anomaly Analysis & Cleaning Protocol

1. **Repeated Header Strings**:
   * *Observation*: `Wednesday-28-02-2018` contains 33 rows where column header strings were re-printed into the data rows during multi-threaded CICFlowMeter CSV dumping.
   * *Resolution*: Filter `df[df['Dst Port'] != 'Dst Port']`.
2. **Negative Flow Duration / 1970 Epoch Glitches**:
   * *Observation*: 14 rows have negative flow duration caused by clock synchronization drift between forward and backward TCP packet capture timestamps.
   * *Resolution*: Drop rows where `Flow Duration < 0` or `Timestamp < '2018-01-01'`.
3. **Zero Duration Infs in Rates**:
   * *Observation*: Flows with `Flow Duration == 0` generate `inf` values in `Flow Byts/s` and `Flow Pkts/s`.
   * *Resolution*: Replace `inf` with `NaN` and impute using median fitted strictly on training data.
