# Phase 4.5 Forensic Audit: Report 18 — Continuous State Forecasting ($S_{t+K} \in \mathbb{R}^{54}$) Analysis

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Why Future Network State Prediction is Scientifically Superior to Binary Classification

Binary classification ($y_{t+K} \in \{0, 1\}$) suffers from the attack continuation artifact where persistence dominates. In contrast, **predicting the future continuous behavioral state vector $S_{t+K} \in \mathbb{R}^{54}$** forces the model to learn the true physical dynamics of network telemetry:
- Byte & packet rates
- Port targeting entropy
- TCP flag ratios & handshake health
- Directional asymmetry
- Flow pacing & inter-arrival times

## 2. Continuous State Forecasting Benchmark Scorecard

| Forecaster Model | Horizon $K=1$ (+2s) MAE | $K=3$ (+6s) MAE | $K=5$ (+10s) MAE | $K=10$ (+20s) MAE | $K=1$ RMSE | $K=10$ RMSE |
|---|---|---|---|---|---|---|
| State Persistence ($S_{t+K} = S_t$) | 0.1924 | 0.2743 | 0.3342 | 0.3243 | 0.7909 | 1.0368 |
| GRU (Full History 54-D) | 0.2263 | 0.2524 | 0.2666 | 0.2711 | 0.6728 | 0.7827 |
| Transformer (Full History 54-D) | 0.2316 | 0.2546 | 0.2701 | 0.2759 | 0.7027 | 0.8069 |
| GRU (Base Features 37-D) | 0.1645 | 0.2084 | 0.2383 | 0.2495 | 0.4812 | 0.6775 |

## 3. Feature Group Error Decomposition (Persistence Baseline)

|   horizon_k |   lead_sec |   state_persistence_mae_overall |   state_persistence_rmse_overall |   Volume_Density |   Velocity_Rates |   Protocol_Mix |   Port_Targeting |   TCP_Flags_Health |   Directionality |   Packet_Moments |   IAT_Lifetime |   Velocity_Deltas |
|------------:|-----------:|--------------------------------:|---------------------------------:|-----------------:|-----------------:|---------------:|-----------------:|-------------------:|-----------------:|-----------------:|---------------:|------------------:|
|           1 |          2 |                          0.1924 |                           0.7909 |           0.0192 |           0.0192 |         0.0993 |           0.0903 |             0.0982 |           0.1048 |           0.0861 |         0.0724 |            0.4367 |
|           3 |          6 |                          0.2743 |                           0.9374 |           0.0504 |           0.0504 |         0.2202 |           0.1857 |             0.2155 |           0.2374 |           0.1781 |         0.1409 |            0.4946 |
|           5 |         10 |                          0.3342 |                           1.1157 |           0.0748 |           0.0748 |         0.3035 |           0.2453 |             0.2922 |           0.3359 |           0.2374 |         0.1857 |            0.5486 |
|          10 |         20 |                          0.3243 |                           1.0368 |           0.0834 |           0.0834 |         0.3246 |           0.2623 |             0.3146 |           0.3634 |           0.2477 |         0.1933 |            0.4815 |

## 4. Predictability Spectrum

- **Highly Predictable Groups (MAE < 0.10):** Volume/Density (0.019 - 0.083), Velocity Rates (0.019 - 0.083), IAT Moments (0.072 - 0.193).
- **Moderately Predictable Groups (MAE 0.10 - 0.35):** Protocol Mix (0.099 - 0.325), Port Targeting (0.090 - 0.262), TCP Flags (0.098 - 0.315), Directionality (0.105 - 0.363).
- **High-Variance / Difficult Group (MAE > 0.43):** Velocity Deltas (0.437 - 0.549) due to high-frequency second-order fluctuations.
