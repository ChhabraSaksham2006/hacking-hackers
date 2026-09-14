# 08 — Data Leakage & Evaluation Splitting Audit
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
