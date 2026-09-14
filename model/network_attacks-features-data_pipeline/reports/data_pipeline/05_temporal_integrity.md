# 05 — Temporal Integrity & Chronological Sequencing Audit
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Temporal Integrity Findings

* **Timestamp Granularity**: 1-second wall-clock resolution (`dd/MM/yyyy HH:mm:ss`).
* **Intra-Day Monotonicity**:
  * Raw CSVs contain flows recorded at the moment of flow termination. Because flows of different durations (e.g. 5ms vs 30s) terminate at different times, flow start timestamps exhibit interleaved arrivals.
  * **Sorting Policy**: Within each business-day session, records must be **sorted strictly by Flow Start Timestamp** before window aggregation.
* **Inter-Day Continuity**:
  * Days represent distinct 12-hour operational periods (01:00 to 13:00 UTC).
  * **Day Boundary Policy**: Sequence lookback windows $[S_{t-P+1}, \dots, S_t]$ must **NEVER cross overnight day boundaries**.

---

## 2. Temporal State Windowing Formulation

Rather than feeding raw individual flows directly into the Transformer, flows occurring within discrete continuous windows $W_t = [t \cdot \Delta t, (t+1) \cdot \Delta t)$ are aggregated into macro-state vectors $S_t \in \mathbb{R}^D$:

$$\Delta t = 10	ext{ seconds}, \quad 	ext{stride } s = 2	ext{ seconds}$$

This produces continuous, smooth network trajectories capturing volume, velocity, port entropy, flag ratios, and connection pacing over time.
