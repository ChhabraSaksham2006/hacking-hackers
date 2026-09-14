# 08 — Feature Selection & Behavioral Subset Recommendation
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Feature Reduction Rationale (80 -> Curated 54 Subset)

* **Original Schema**: 80 columns extracted by CICFlowMeter-V3.
* **Columns Dropped (24 Columns)**:
  1. **8 Zero-Variance Columns**: `Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Byts/b Avg`, `Fwd Pkts/b Avg`, `Fwd Blk Rate Avg`, `Bwd Byts/b Avg`, `Bwd Pkts/b Avg`, `Bwd Blk Rate Avg`.
  2. **6 Exact Multicollinear Redundancies ($r = 1.0$)**: `Subflow Fwd Pkts`, `Subflow Fwd Byts`, `Subflow Bwd Pkts`, `Subflow Bwd Byts`, `Fwd Header Len`, `Bwd Header Len`.
  3. **2 Metadata / Targets**: `Timestamp`, `Label` (isolated from input tensors).
  4. **8 Redundant Summary Moments**: Duplicate packet length averages.
* **Curated 54-Feature Behavioral Core Set**: Retains all essential packet moments, rate velocities, TCP flag distributions, window sizes, and inter-arrival time moments needed for robust temporal state aggregation ($S_t$).
