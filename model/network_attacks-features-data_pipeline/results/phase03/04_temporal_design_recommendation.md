# 04 — Temporal State Representation Final Design Recommendation
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Definitive Design Recommendation

```
========================================================================================
                 FINAL TEMPORAL STATE SPECIFICATION FOR SIH26153
========================================================================================
  WINDOW DURATION (Δt) : 10.0 SECONDS
  STRIDE (s)           : 2.0 SECONDS (80% Overlapping Sliding Rolling States)
  STATE DIMENSION (D)  : 54 CONTINUOUS BEHAVIORAL FEATURES (Design C)
  LOOKBACK HORIZON (P) : 10 STEPS (Past 28 seconds of network history: [S_{t-9}...S_t])
  FORECAST HORIZONS (K): K = 1 (2s ahead), K = 3 (6s ahead), K = 5 (10s ahead), K = 10 (20s ahead)
========================================================================================
```

---

## 2. Scientific & Empirical Justification

### 2.1 Why Window Duration $\Delta t = 10.0	ext{s}$?
1. **Statistical Stability**: At $\Delta t = 10	ext{s}$, windows contain an average of **1,079 flows** (median 241 flows), ensuring sample variance, entropy, and flag ratios are statistically robust.
2. **Minimal Empty Window Sparsity**: Empty window rate is only **2.55%** across active business hours (compared to 76% at $\Delta t = 1	ext{s}$).
3. **Burst Fidelity**: 10 seconds is short enough to capture high-velocity micro-bursts (e.g. 3-minute DoS Hulk attacks are resolved across 20 non-overlapping or 100 rolling windows).

### 2.2 Why Stride $s = 2.0	ext{s}$?
1. **High-Frequency Alert Refresh**: Produces a refreshed network state every 2 seconds, providing operational SOC analysts with real-time early warning telemetry.
2. **Smooth Trajectory Continuity**: 80% overlap creates smooth temporal gradients for the Temporal Transformer positional encodings, avoiding abrupt discontinuous jumps between adjacent time steps.

### 2.3 Handling of Edge Cases
* **Empty Windows ($N_t = 0$)**: Flow counts, rates, and bytes are assigned `0.0`. Entropy and ratios are assigned `0.0`. Velocity deltas are computed relative to previous state.
* **Categorical Variables**:
  * Protocol is represented via continuous distribution ratios ($	ext{TCP}_\%, 	ext{UDP}_\%, 	ext{ICMP}_\%$).
  * Destination ports are represented via Shannon Port Entropy $H(	ext{Port})$ and targeted authentication port ratios.
* **Day Boundaries**: Lookback sequences $[S_{t-P+1}, \dots, S_t]$ **strictly terminate at day boundaries**, preventing artificial transitions between separate days.
