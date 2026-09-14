# Authoritative Dataset & Provenance Audit
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Phase:** 5.5 | **Dataset:** CSE-CIC-IDS2018 | **Date:** 2026-09-08

---

### 1. Canonical Dataset Specification
The canonical dataset selected and audited is official **CSE-CIC-IDS2018**.
All processing flows through:
Raw CSVs -> Cleaned Canonical Parquets -> Temporal State Windows (10s window, 2s stride) -> Chronological Split.

### 2. Daily State Parquet Inventories
Every session corresponds strictly to one calendar day of network capture without cross-day leakage.

| Session ID | File Name | Total Windows | Attack Windows | Benign Windows | Attack % | Dominant Classes |
|---|---|---|---|---|---|---|
| Wednesday-14-02-2018 | Wednesday-14-02-2018_states.parquet | 21,595 | 5,647 | 15,948 | 26.1% | FTP-BruteForce, SSH-Bruteforce |
| Thursday-15-02-2018 | Thursday-15-02-2018_states.parquet | 21,595 | 1,702 | 19,893 | 7.9% | DoS-GoldenEye, DoS-Slowloris |
| Friday-16-02-2018 | Friday-16-02-2018_states.parquet | 21,532 | 1,486 | 20,046 | 6.9% | DoS-SlowHTTPTest, DoS-Hulk |
| Wednesday-21-02-2018 | Wednesday-21-02-2018_states.parquet | 15,823 | 1,390 | 14,433 | 8.8% | DDoS-LOIC-UDP, DDoS-HOIC |
| Thursday-22-02-2018 | Thursday-22-02-2018_states.parquet | 21,595 | 809 | 20,786 | 3.7% | WebAttack (Brute Force, XSS, SQLi) |
| Friday-23-02-2018 (VAL) | Friday-23-02-2018_states.parquet | 21,595 | 1,289 | 20,306 | 6.0% | WebAttack (Brute Force, XSS, SQLi) |
| Wednesday-28-02-2018 (TEST) | Wednesday-28-02-2018_states.parquet | 21,595 | 3,998 | 17,597 | 18.5% | Infiltration |
| Thursday-01-03-2018 (TEST) | Thursday-01-03-2018_states.parquet | 21,595 | 4,658 | 16,937 | 21.6% | Infiltration |
| Friday-02-03-2018 (TEST) | Friday-02-03-2018_states.parquet | 21,595 | 10,218 | 11,377 | 47.3% | Botnet |

Total Windows Across All 9 Sessions: **188,520 windows**.

### 3. Chronological Sequence Counts
For lookback $P=10$ and maximum evaluation horizon $K_{\text{max}}=50$:
- **Train (5 Days):** 101,845 sequences | 11,001 attack (10.8%) | 90,844 benign | pos_weight = 8.26
- **Validation (1 Day):** 21,536 sequences | 1,289 attack (6.0%) | 20,247 benign | pos_weight = 15.71
- **Test (3 Days):** 64,608 sequences | 18,815 attack (29.1%) | 45,793 benign | pos_weight = 2.43

### 4. Reconciliation of Historical Discrepancies
- **Discrepancy 1 (Sequence Counts):** Earlier reports mentioned ~63,858 test sequences when $K_{\text{max}}=300$ was used because $300$ horizon steps consume $300$ border windows ($21,595 - 10 - 300 + 1 = 21,286$ per day). When $K_{\text{max}}=50$, each full test day yields $21,595 - 9 - 50 = 21,536$ sequences ($3 \times 21,536 = 64,608$). Both numbers are mathematically correct under their respective $K_{\text{max}}$ boundaries.
- **Discrepancy 2 (Infinity & NaN Filtering):** Infinite flow rates in raw CICFlowMeter CSVs (caused by zero flow duration) were cleaned during canonical ingestion; NaN values in temporal windowing are strictly zero-imputed prior to scaling.
- **Discrepancy 3 (DARPA Hybrid Artifacts):** Older DARPA references in legacy branches are isolated; the active pipeline is 100% CSE-CIC-IDS2018.
