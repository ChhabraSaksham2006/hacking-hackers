# Temporal State Aggregation & Dataset Verification Report

**Project:** SIH26153 — AI-Based Network Attack Forecasting
**Phase:** 3A — Temporal State Aggregation & Multi-Horizon Ground Truth Audit

## 1. Executive Summary

All 9 official CSE-CIC-IDS2018 daily captures have been successfully aggregated into continuous 54-dimensional behavioral macro-state representations ($S_t \in \mathbb{R}^{54}$) over 10.0-second sliding windows with 2.0-second stride (80% rolling overlap).

- **Total Ingested Flows:** 8,284,181
- **Total Aggregated State Steps:** 188,520
- **Total Attack Windows:** 31,197 (16.55%)
- **Total Benign Windows:** 157,323 (83.45%)
- **State Feature Dimension:** 54 continuous features (37 Base Moments + 17 First-Order Velocity Deltas)
- **Data Quality:** 0 missing values, 0 infinite values, 100% strictly monotonic timestamps.

## 2. Daily State Parquet Statistics

| processed_file                      |   windows |   attack_windows |   benign_windows | attack_percentage   |   nan_count |   inf_count | monotonic_time   | dominant_family   | dominant_mitre   | sha256_verified   |
|:------------------------------------|----------:|-----------------:|-----------------:|:--------------------|------------:|------------:|:-----------------|:------------------|:-----------------|:------------------|
| Friday-02-03-2018_states.parquet    |     21595 |            10218 |            11377 | 47.32%              |           0 |           0 | True             | Benign            | None             | True              |
| Friday-16-02-2018_states.parquet    |     21532 |             1486 |            20046 | 6.90%               |           0 |           0 | True             | Benign            | None             | True              |
| Friday-23-02-2018_states.parquet    |     21595 |             1289 |            20306 | 5.97%               |           0 |           0 | True             | Benign            | None             | True              |
| Thursday-01-03-2018_states.parquet  |     21595 |             4658 |            16937 | 21.57%              |           0 |           0 | True             | Benign            | None             | True              |
| Thursday-15-02-2018_states.parquet  |     21595 |             1702 |            19893 | 7.88%               |           0 |           0 | True             | Benign            | None             | True              |
| Thursday-22-02-2018_states.parquet  |     21595 |              809 |            20786 | 3.75%               |           0 |           0 | True             | Benign            | None             | True              |
| Wednesday-14-02-2018_states.parquet |     21595 |             5647 |            15948 | 26.15%              |           0 |           0 | True             | Benign            | None             | True              |
| Wednesday-21-02-2018_states.parquet |     15823 |             1390 |            14433 | 8.78%               |           0 |           0 | True             | Benign            | None             | True              |
| Wednesday-28-02-2018_states.parquet |     21595 |             3998 |            17597 | 18.51%              |           0 |           0 | True             | Benign            | None             | True              |

## 3. Chronological Train / Validation / Test Sequence Partitioning

| Partition | Daily Sessions Included | State Windows | Valid Sequences ($P=10, K \le 10$) | Attack Sequences | Primary Attack Types |
|---|---|---|---|---|---|
| **Train** | Days 1–5 (14-02, 15-02, 16-02, 21-02, 22-02) | 102,140 | 102,045 | 11,025 (10.8%) | FTP/SSH Brute Force, DoS Hulk/SlowHTTPTest/Slowloris/GoldenEye, DDoS HOIC/LOIC, Web Attacks |
| **Validation** | Day 6 (23-02) | 21,595 | 21,576 | 1,289 (6.0%) | Web Attacks (Brute Force Web, XSS, SQL Injection) |
| **Test** | Days 7–9 (28-02, 01-03, 02-03) | 64,785 | 64,728 | 18,855 (29.1%) | Multi-stage Infiltration (2 Days) & Botnet ARES C2 (Zero-shot evaluation) |


## 4. Verification Verdict

**STATUS A — DATASET READY FOR TEMPORAL MODELING.**
The state aggregation pipeline is fully verified, mathematically sound, free of leakage, and ready for baseline ML and Transformer world model training.
