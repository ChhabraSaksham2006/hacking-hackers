# 10 — Sparse Recurrent State-Space Model (Sparse RSSM) Audit

## 1. Sparsity Formulation & Straight-Through Top-K Routing

- **Module Implementation:** `StraightThroughTopK` in `src/models/sparse_rssm.py` and `TopKSparseLatent` in `src/models/sparse_latent.py`.
- **Target Tensor:** Sparsity is applied to the **128-dimensional dense latent vector $z$** produced by the encoder and the transition model.
- **Top-K Selection Mechanism:** Coordinate magnitude gating ($|z|_i$).
  $$k = \max(1, 	ext{round}(128 	imes 	ext{sparsity\_ratio}))$$
  $$	ext{Top-}k	ext{ Indices} = 	ext{argtopk}(|z|, k)$$
- **Forward Pass:** Non-selected coordinates are zeroed out (hard binary mask).
- **Backward Pass:** Straight-Through Estimator (STE):
  $$\hat{z} = z + (z_{	ext{hard}} - z).	ext{detach}()$$
  Gradients $rac{\partial \mathcal{L}}{\partial \hat{z}}$ pass directly back to $z$ without attenuation.
- **Sparsity Variants:**
  - **Dense Control ($	ext{ratio} = 1.0$):** 128 of 128 coordinates active (100%).
  - **Top-50 ($	ext{ratio} = 0.50$):** Exactly 64 of 128 coordinates active (50%).
  - **Top-10 ($	ext{ratio} = 0.10$):** Exactly 13 of 128 coordinates active (10.15%).
  - **Top-05 ($	ext{ratio} = 0.05$):** Exactly 6 of 128 coordinates active (4.68%).

## 2. Answers to Specific Sparsity Forensic Questions

1. **What tensor is sparsified?** The 128-D latent representation $z$.
2. **Top-K selection basis?** Absolute magnitude $|z_i|$ of each latent coordinate.
3. **Differentiability?** Forward pass is non-differentiable hard gating; backward pass uses straight-through gradient estimation.
4. **Is sparsity fixed or dynamic?** Dynamic; the active coordinate mask changes at every timestep and differs for every sample.
5. **Are dimensions permanently pruned?** No; all 128 coordinates remain in memory and can activate depending on input dynamics.
6. **Timing of sparsification?** Applied immediately before recurrent memory update ($h_t = 	ext{GRUCell}(\hat{z}_t, h_{t-1})$) and world transition input ($r_t = [\hat{z}_t \,;\, h_t]$). Continuous state decoding occurs from dense $z$ before gating.
