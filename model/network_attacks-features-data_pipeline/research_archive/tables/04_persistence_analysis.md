# 04 — Forensics of the Persistence Paradox

| Horizon $K$ | Lead Time | Continuation Task $F_1$ | Continuation Recall | Pre-Onset Transition Recall | Pre-Onset Early Warning $F_1$ | Median Lead Time |
|---|---|---|---|---|---|---|
| **$K=1$** | 2.0s | **0.9996** | **99.96%** | **0.00%** (0/7) | **0.0000** | 0.0s |
| **$K=10$** | 20.0s | **0.9965** | **99.65%** | **0.00%** (0/7) | **0.0000** | 0.0s |
| **$K=50$** | 100.0s | **0.9861** | **98.61%** | **0.00%** (0/7) | **0.0000** | 0.0s |
| **$K=100$** | 200.0s | **0.9634** | **96.34%** | **0.00%** (0/7) | **0.0000** | 0.0s |
| **$K=300$** | 600.0s | **0.9186** | **91.86%** | **0.00%** (0/7) | **0.0000** | 0.0s |

### Interpretation

This table exposes the 'Persistence Paradox'. In datasets with multi-hour contiguous attack episodes (such as Botnet and Infiltration), persistence forecasters achieve near-perfect window classification F1 scores purely by predicting continuation of already active attacks. When evaluated on genuine pre-attack onset transitions ($y_t=0 	o y_{t+K}=1$), persistence recall drops to exactly 0.00%. Persistence provides zero advance warning.
