# 13 — Forecast Horizon & Temporal Scaling Analysis

## 1. Horizon to Real-Time Mapping

Because the temporal state sequence operates with stride $\Delta t = 2.0	ext{ seconds}$, each step $K$ maps linearly to real-world forecast lead time:
$$	ext{Lead Time} = K 	imes 2.0	ext{ seconds}$$

| Horizon Index ($K$) | Real-World Lead Time | Context / Window Scale |
|---|---|---|
| $K = 1$ | **2.0 seconds** | Immediate next state transition |
| $K = 3$ | **6.0 seconds** | Short-term local progression |
| $K = 5$ | **10.0 seconds** | 1 full window length ahead |
| $K = 10$ | **20.0 seconds** | 2 full window lengths ahead |
| $K = 25$ | **50.0 seconds** | ~1 minute early warning |
| $K = 50$ | **100.0 seconds** | 1.67 minutes early warning |
| $K = 100$ | **200.0 seconds** | 3.33 minutes early warning |
| $K = 200$ | **400.0 seconds** | 6.67 minutes early warning |
| $K = 250$ | **500.0 seconds** | 8.33 minutes early warning |
| $K = 300$ | **600.0 seconds** | **10.00 minutes** early warning |

## 2. Multi-Horizon Performance Across Models

| $K$ | Seconds | Persistence F1 | RF F1 (Static 54D) | Dense RSSM F1 | Top-50 RSSM F1 | Top-10 RSSM F1 |
|---|---|---|---|---|---|---|
| 1 | 2.0s | **0.9996** | 0.2892 | 0.5540 | 0.5509 | 0.5295 |
| 50 | 100.0s | **0.9860** | 0.6139 | 0.5569 | 0.5580 | 0.0064 |
| 100 | 200.0s | **0.9726** | 0.5581 | 0.5542 | 0.5548 | 0.0000 |
| 200 | 400.0s | **0.9455** | 0.3031 | 0.5563 | N/A | N/A |
| 250 | 500.0s | **0.9321** | 0.4870 | 0.5528 | N/A | N/A |
| 300 | 600.0s | **0.9186** | 0.4425 | 0.5576 | N/A | N/A |

## 3. Key Observations & Horizon Regime Winners

1. **Short Horizon ($K=1$, 2s):** Winner is **Persistence (F1 = 0.9996)**. High persistence is driven by contiguous attack duration.
2. **Medium Horizon ($K=50$, 100s):** Winner among ML models is **Random Forest (F1 = 0.6139)**.
3. **Long Horizon ($K=100..300$, 200s–600s):** Persistence remains dominant (0.9726 $	o$ 0.9186). Dense RSSM exhibits an artificially flat F1 (~0.554) across all $K$ because its attack head is untrained and acts as an aggressive near-constant predictor.
