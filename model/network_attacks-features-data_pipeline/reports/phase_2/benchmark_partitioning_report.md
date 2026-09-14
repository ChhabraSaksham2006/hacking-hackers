# Benchmark Dataset Partitioning & Anti-Leakage Verification Audit

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. Executive Summary & Verification Matrix

| Setting | Total Seqs | Train Seqs | Val Seqs | Test Seqs | Test Attack Seqs | Test Onset Precursors | Episodes (Train/Val/Test) | Anti-Leakage Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Setting A** | 123,447 | 85,048 | 8,941 | 29,458 | 4,678 | 290 | 256 / 53 / 52 | **PASSED (0.00% Leakage)** |
| **Setting B** | 188,349 | 102,045 | 21,576 | 64,728 | 18,855 | 70 | 171 / 194 / 8 | **PASSED (0.00% Leakage)** |
| **Setting C** | 188,349 | 102,045 | 21,576 | 64,728 | 18,855 | 70 | 171 / 194 / 8 | **PASSED (0.00% Leakage)** |

---

## 2. Setting Specifications & Ground Truth Verification

### Setting A: Seen Attack Generalization
- **Purpose:** Measures the capability of models to learn repeating pre-attack physical telemetry signatures and forecast subsequent attack bursts for recurring known threat families.
- **Train Partition:** 85,048 sequences (256 episodes across BruteForce, DoS, DDoS, WebAttacks).
- **Val Partition:** 8,941 sequences (53 episodes). Used strictly for threshold calibration and model checkpoint selection.
- **Test Partition:** 29,458 sequences (52 episodes, 290 onset precursors).
- **Temporal Isolation:** Full temporal embargo buffers (>= 20 windows / 40s) enforced at all within-day partition cuts.

### Setting B: Mixed Generalization
- **Purpose:** Simulates realistic enterprise deployment where an intrusion forecasting model is trained on early enterprise captures and evaluated against subsequent live days with mixed benign and new threat patterns.
- **Train Partition:** 102,045 sequences (Days 1–5 complete captures).
- **Val Partition:** 21,576 sequences (Day 6 Web Attacks).
- **Test Partition:** 64,728 sequences (Days 7–9: Infiltration, Botnet, Benign).

### Setting C: Strict Out-of-Distribution / Zero-Day Generalization
- **Purpose:** Rigorous zero-day threat evaluation. The model has zero training exposure to Infiltration or Botnet dynamics and must forecast onsets via generalized anomalous trajectory deviation or universal precursor dynamics.
- **Train Partition:** 102,045 sequences (Days 1–5).
- **Val Partition:** 21,576 sequences (Day 6).
- **Test Partition:** 64,728 sequences (Days 7–9 Infiltration & Botnet).
- **Isolated Zero-Day Test Onsets:** 7 onsets (70 onset precursor sequence windows).

---

## 3. Anti-Leakage Proof & Invariants

1. **Zero Window Overlap:** Raw window index intersection between train, val, and test is empty.
2. **Zero Episode Fragmentation:** Every attack episode is assigned in its entirety to exactly one partition.
3. **Zero Normalization Contamination:** Scalers will be computed exclusively on Training sequence windows.
4. **Zero Threshold Lookahead:** All classification operating points (decision thresholds) must be calibrated solely on Validation sequences.

_Generated automatically by `scripts/preprocessing/build_benchmark_splits.py`._