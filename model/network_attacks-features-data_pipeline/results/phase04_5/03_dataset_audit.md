# 03 — Comprehensive Dataset Audit

## 1. Dataset Identification & Provenance

- **Dataset Name:** Communications Security Establishment & Canadian Institute for Cybersecurity IDS 2018 (CSE-CIC-IDS2018).
- **Official Source:** AWS Open Data Registry (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`).
- **Data Generator:** CICFlowMeter-V3.
- **Local Interim Parquet Path:** `data/interim/cse_cic_ids2018/`.
- **Local State Parquet Path:** `data/processed/temporal_states/`.
- **Total Capture Sessions:** 9 daily capture files.

## 2. Table — Dataset Inventory

| Session File | Date | Raw Rows | Cleaned Rows | Dropped Rows | Infinite Values | Raw Duplicates | Attack Windows | Benign Windows | Total Windows | Attack % |
|---|---|---|---|---|---|---|---|---|---|---|
| `Wednesday-14-02-2018` | 14/02/2018 | 1,048,575 | 1,048,570 | 5 (neg dur) | 5,371 | 225,628 | 5,647 | 15,948 | 21,595 | 26.15% |
| `Thursday-15-02-2018` | 15/02/2018 | 1,048,575 | 1,048,575 | 0 | 11,133 | 2,421 | 1,702 | 19,893 | 21,595 | 7.88% |
| `Friday-16-02-2018` | 16/02/2018 | 1,048,575 | 1,048,574 | 1 (header) | 0 | 147,586 | 1,486 | 20,046 | 21,532 | 6.90% |
| `Wednesday-21-02-2018` | 21/02/2018 | 1,048,575 | 1,048,575 | 0 | 0 | 17,557 | 1,390 | 14,433 | 15,823 | 8.78% |
| `Thursday-22-02-2018` | 22/02/2018 | 1,048,575 | 1,048,566 | 9 (neg dur) | 7,651 | 3,278 | 809 | 20,786 | 21,595 | 3.75% |
| `Friday-23-02-2018` | 23/02/2018 | 1,048,575 | 1,048,575 | 0 | 7,662 | 2,614 | 1,289 | 20,306 | 21,595 | 5.97% |
| `Wednesday-28-02-2018` | 28/02/2018 | 613,104 | 613,071 | 33 (header) | 8,297 | 6,089 | 3,998 | 17,597 | 21,595 | 18.51% |
| `Thursday-01-03-2018` | 01/03/2018 | 331,125 | 331,100 | 25 (header) | 4,004 | 73 | 4,658 | 16,937 | 21,595 | 21.57% |
| `Friday-02-03-2018` | 02/03/2018 | 1,048,575 | 1,048,575 | 0 | 5,542 | 5,459 | 10,218 | 11,377 | 21,595 | 47.32% |
| **TOTAL** | **9 Days** | **8,284,254** | **8,284,181** | **73** | **49,660** | **410,705** | **31,197** | **157,323** | **188,520** | **16.55%** |

## 3. Data Cleaning & Imputation Policies

1. **Header Duplication Policy:** 59 repeated header lines across 3 CSV dumps were identified and removed.
2. **Malformed Flow Policy:** 14 records with negative flow duration (`Flow Duration < 0`) were dropped.
3. **Infinite Rate Policy:** 49,660 flows with `Flow Bytes/s == inf` or `Flow Packets/s == inf` (caused by zero-duration micro-flows) were imputed using median values computed strictly from training partitions.
4. **Duplicate Flow Policy:** 410,705 duplicate flow records were retained because in network telemetry, identical TCP ACK/keepalive packets naturally recur; deduplicating would destroy physical traffic volume metrics.
5. **Timestamp Cleaning Policy:** Timestamps parsed with format `dd/MM/yyyy HH:mm:ss` and strictly sorted chronologically within daily captures. No cross-day shuffling.
