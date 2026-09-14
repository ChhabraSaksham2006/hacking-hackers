# 24 — Final Research Assessment

## 1. Overall Research Classification

**Classification: C — MAJOR METHODOLOGICAL PROBLEM / RESULTS NOT YET SCIENTIFICALLY TRUSTWORTHY.**

### Rationale:
1. **Untrained Attack Head:** The primary claim of network attack forecasting cannot be scientifically validated under current artifacts because the attack classification head was never included in the RSSM training loss.
2. **Continuation vs Onset Confounding:** High test attack F1 scores are dominated by multi-hour attack episode continuation rather than genuine early-warning onset detection.
3. **Sample Size Discrepancy:** Dynamic truncation in `run_sparse_rssm.py` evaluated models on slightly different row counts across horizons $K$.

## 2. Top 10 Things We Now Know (Definitively Established)

1. **Exact Git Synchronization:** Local repository is 100% synchronized with `origin/features/llm_pipeline` at commit `90f9624`.
2. **Canonical Data Scale:** The dataset comprises 8,284,181 canonical flow records and 188,520 temporal state vectors across 9 days.
3. **Temporal Construction:** Rolling 10.0s windows with 2.0s stride (80% overlap) yield 54 continuous features (37 base + 17 first-order velocity deltas).
4. **Leakage-Free Foundation:** Disjoint calendar day splits, train-only `StandardScaler` fitting, and causal window slicing are verified.
5. **Continuous Rollout Mechanism:** `SparseRSSM.rollout()` implements genuine recursive autonomous latent rollout with per-step state target supervision.
6. **Untrained Head Root Cause:** `SparseRSSM.loss()` only computes reconstruction and future state MSE, leaving attack classification heads at random initialization.
7. **RSSM Aggressive Decision Rule:** RSSM predicts attacks on 71%–76% of test samples, causing high recall (~99%) but high false positive rates (~64%–66%).
8. **Persistence Mechanism:** Persistence F1 (0.9186–0.9996) is driven by long contiguous attack episodes ($P(Y_{t+1}=1|Y_t=1) = 99.96\%$).
9. **Persistence Pre-Onset Failure:** Persistence achieves exactly 0.0000 F1 on pure pre-onset transitions ($Y_t=0 	o Y_{t+K}=1$).
10. **Sparse Latent Stability:** Top-50 gating maintains stable state MSE, while Top-10 (13 dims) is numerically unstable over long rollouts ($K=100$).

## 3. Top 10 Things We Still Do Not Know (Open Research Questions)

1. **What is RSSM attack F1 when the attack head is properly trained with BCE loss?**
2. **Can a trained RSSM outperform Random Forest on long horizons ($K=100..300$)?**
3. **What is the genuine pre-onset lead time and F1 of RSSM on pure benign-to-attack transitions?**
4. **Does continuous latent rollout provide superior state trajectory forecasting compared to direct autoregressive Transformers?**
5. **What is the optimal loss weighting $\lambda$ between continuous state MSE and discrete attack classification BCE?**
6. **Can Top-K sparsity prevent representation collapse when trained with joint multi-task loss?**
7. **How does RSSM perform on non-overlapping windows ($\Delta t = 10	ext{s}$) where autocorrelation is minimized?**
8. **What are the per-family detection latencies for Infiltration versus Botnet attacks?**
9. **Can learned latent coordinate masks provide verifiable MITRE ATT&CK stage interpretability?**
10. **How does threshold calibration on validation data affect RSSM false positive rates when the head is trained?**
