# Forensic Audit: First-Order Velocity Delta Features (Delta S_t)

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Delta Formulation

For each of the 17 continuous volume, rate, and entropy metrics:
$$\Delta S_t = S_t - S_{t-1} \quad \text{for } t \ge 1$$
$$\Delta S_0 = 0.0 \quad \text{for } t = 0$$

## 2. Session Boundary Verification

Because each of the 9 days represents an independent daily capture session, computing $\Delta S_0 = S_0^{\text{day } d} - S_{N-1}^{\text{day } d-1}$ would create artificial cross-day jumps. The pipeline explicitly enforces $\Delta S_0 = 0.0$ at the start of every daily session.

## 3. Results
- Total Delta Features: 17
- Cross-day Leakage: 0 occurrences
- Historical Consistency: 100% verified
