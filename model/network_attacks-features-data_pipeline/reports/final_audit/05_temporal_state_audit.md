# 05 — Temporal State Construction Audit

## 1. Mathematical Specification & Window Parameters

- **Window Duration ($W$):** 10.0 seconds.
- **Window Stride ($\Delta t$):** 2.0 seconds.
- **Window Overlap:** 80.0% ($rac{W - \Delta t}{W} = rac{10 - 2}{10} = 0.80$).
- **Boundary Semantics:** Left-closed, right-open $[t_{	ext{start}}, t_{	ext{end}})$ implemented via `np.searchsorted(ts, [w_start, w_end], side='left')`.
- **Empty Window Policy:** Zero-imputed continuous representation ($0$ flow count, $0$ rates, $0$ ratios).
- **Day Boundary Policy:** Strict truncation; sequences NEVER span across midnight or between separate daily files.
- **Sequence Lookback ($P$):** 10 steps ($t-9, t-8, \dots, t$).
- **Historical Temporal Span:** $(P - 1) 	imes \Delta t + W = 9 	imes 2.0	ext{s} + 10.0	ext{s} = 28.0	ext{ seconds}$.

## 2. Sequence Sample Counts & Horizon Truncation

Because a valid sequence anchor $t$ must have $P-1$ historical steps and $K_{\max}$ future steps available within the same daily file:
$$	ext{Valid Anchors} \in [P-1, N_{	ext{windows}} - 1 - K_{\max}]$$
The number of sequences per partition depends on the $K_{\max}$ used during sequence construction:

| Benchmark Setup | $K_{\max}$ | Train Sequences | Val Sequences | Test Sequences | Total Sequences |
|---|---|---|---|---|---|
| **Phase 4 Baselines (Fixed $K_{\max}=300$)** | 300 | 100,612 | 21,295 | 63,858 | 185,765 |
| **Phase 4 Standard ($K_{\max}=10$)** | 10 | 102,062 | 21,585 | 64,755 | 188,402 |
| **Sparse RSSM Runner ($K=1$)** | 1 | 102,107 | 21,594 | 64,755 | 188,456 |
| **Sparse RSSM Runner ($K=100$)** | 100 | 101,612 | 21,495 | 64,458 | 187,565 |
| **Sparse RSSM Runner ($K=200$)** | 200 | 101,112 | 21,395 | 64,158 | 186,665 |
| **Sparse RSSM Runner ($K=250$)** | 250 | 100,862 | 21,345 | 64,008 | 186,215 |
| **Sparse RSSM Runner ($K=300$)** | 300 | 100,612 | 21,295 | 63,858 | 185,765 |

> [!WARNING]
> In `run_sparse_rssm.py`, `load_data(..., max_h=K)` was called with `max_h=K` rather than a fixed global $K_{\max}=300$. Consequently, RSSM runs at $K=1$ evaluated on 64,755 test rows, whereas $K=300$ evaluated on 63,858 test rows.
