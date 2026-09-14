# 04 — Data Pipeline Audit

## 1. End-to-End Pipeline Flow

```text
RAW CSV (AWS S3)
   │
   ▼
1. INGESTION & HASH VERIFICATION (`download_official_s3.py`)
   │
   ▼
2. CLEANING & CANONICALIZATION (`convert_raw_to_canonical_parquet.py`)
   - Remove 59 repeated headers
   - Drop 14 negative duration flows
   - Impute 49,660 infinite rates via train medians
   - Chronological sort by Timestamp
   │
   ▼
3. CANONICAL PARQUET (8,284,181 flows, 80 features)
   │
   ▼
4. VECTORIZED TEMPORAL STATE AGGREGATION (`state_aggregator.py`)
   - Rolling W=10s windows, stride Delta t=2s (80% overlap)
   - Left-closed, right-open: [t_start, t_end) via searchsorted
   - Generate 37 base continuous features + 17 first-order deltas
   - Compute multi-horizon ground truth targets (K in 1..300)
   │
   ▼
5. TEMPORAL STATE PARQUET (188,520 states, 54-D S_t)
   │
   ▼
6. CHRONOLOGICAL DATASET SPLIT (`dataset_builder.py`)
   - Train: Days 1–5 (102,112 states)
   - Val:   Day 6 (21,595 states)
   - Test:  Days 7–9 (64,785 states)
   │
   ▼
7. NORMALIZATION (`StandardScaler`)
   - Fitted STRICTLY on Train states only
   - Applied to Validation and Test
   │
   ▼
8. SLIDING LOOKBACK SEQUENCE CONSTRUCTION (P=10 steps = 28s lookback)
   - Bounded strictly within daily captures (NO cross-day sequences)
   │
   ▼
9. MODEL EXECUTION & EVALUATION
```

## 2. Step-by-Step Leakage Risk Assessment

| Pipeline Step | Input | Output | Code Location | Transformation | Leakage Risk | Verification Status |
|---|---|---|---|---|---|---|
| **Canonicalization** | Raw CSVs | Clean Parquets | `convert_raw_to_canonical_parquet.py` | Deduplicate headers, impute infs | **NONE**: Median computed on train | PASS |
| **Window Slicing** | Flow rows | Window slices | `state_aggregator.py` | `searchsorted` on timestamp | **NONE**: Causal window boundaries | PASS |
| **Feature Aggregation**| Flow telemetry | 54-D State | `state_aggregator.py` | Vectorized sums & statistics | **NONE**: Labels excluded from features | PASS |
| **Delta Computation** | Current & prev state | Delta features | `state_aggregator.py` | $S_t - S_{t-1}$ with day reset | **NONE**: Uses only historical state | PASS |
| **Split Partitioning** | 9 daily sessions | Train/Val/Test | `dataset_builder.py` | Split by full calendar days | **NONE**: Disjoint calendar days | PASS |
| **Feature Scaling** | Raw state tensors | Normalized states | `TemporalSequenceBuilder.fit_scaler` | `StandardScaler.fit(train_only)` | **NONE**: Scaler never sees Val/Test | PASS |
| **Sequence Framing** | State vectors | (N, P=10, 54) tensors | `dataset_builder.py` | Sliding window inside day | **NONE**: Truncated at day boundaries | PASS |
