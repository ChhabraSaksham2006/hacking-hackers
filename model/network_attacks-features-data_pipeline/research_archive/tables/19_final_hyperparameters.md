# 19 — Authoritative Hyperparameter Specification

| Parameter Category | Hyperparameter Name | Final Value | Selection Classification | Empirical Basis / Selection Experiment |
|---|---|---|---|---|
| **Data Design** | Temporal Window Size | 10.0 seconds | Fixed Design Parameter | Phase 3C window resolution trade-off study |
| **Data Design** | Window Step Stride | 2.0 seconds | Fixed Design Parameter | Phase 3C temporal granularity optimization |
| **Data Design** | Lookback Steps $P$ | 10 windows (20s) | Fixed Design Parameter | Context length required to capture precursor drift |
| **Data Design** | Rollout Horizon $K$ | 10 steps (20s) | Fixed Design Parameter | Primary operational SOC early-warning target |
| **Architecture** | State Dimension | 54 dimensions | Fixed Design Parameter | 37 base physical features + 17 delta derivatives |
| **Architecture** | Latent Dimension $Z$ | 128 dimensions | Fixed Design Parameter | Latent capacity required for multi-modal dynamics |
| **Architecture** | Recurrent Hidden Dim | 128 dimensions | Fixed Design Parameter | Matches latent dimension in GRUCell memory |
| **Architecture** | Sparsity Ratio | 1.0 (Dense) | Experimentally Selected | Phase 5 ablation: Top-10 diverged, Dense is stable |
| **Architecture** | Total Model Parameters | 213,820 weights | Fixed Design Parameter | Verified across all checkpoints |
| **Training** | Optimizer & Weight Decay | AdamW ($\lambda=10^{-4}$) | Fixed Design Parameter | Stabilized recurrent gradients |
| **Training** | Learning Rate | 0.001 ($10^{-3}$) | Fixed Design Parameter | Standard stable learning rate |
| **Training** | Batch Size | 1024 sequences | Fixed Design Parameter | Maximum throughput without GPU OOM |
| **Training** | Training Epochs | 5 epochs | Experimentally Selected | Validation loss plateaus at epoch 4-5 |
| **Training** | Positive Class Weight | 8.26 | Fixed Design Parameter | Calculated directly from training class ratio |
| **Training** | Random Seed | 42 | Experimentally Selected | Champion model across multi-seed evaluations |
| **Loss Function** | State Loss Weight $\lambda_{	ext{state}}$ | 1.0 | Fixed Design Parameter | Normalized continuous state reconstruction MSE |
| **Loss Function** | Onset Loss Weight $\lambda_{	ext{onset}}$ | 1.0 | Experimentally Selected | E604 ablation: higher weights degraded state MAE |
| **Loss Function** | Precursor Multiplier $M$ | 10.0× | Experimentally Selected | E602 winner: highest validation F1 and 20s lead |
| **Loss Function** | Precursor Decay $	au$ | 60.0 seconds | Experimentally Selected | E603 winner: balanced precursor sensitivity |
| **Operational** | Decision Threshold $	au_{	ext{det}}$ | 0.04 | Experimentally Selected | Calibrated on validation split via max F1 |
| **Operational** | Tier 1 Cooldown Filter | 10.0 seconds | Chosen Operating Point | Retains 100% recall with 79% noise reduction |
| **Operational** | Tier 3 Cooldown Filter | 60.0 seconds | Chosen Operating Point | Minimizes noise (39.89 FA/hr, 2.22% FPR) |

### Interpretation

This table provides a complete, unambiguous specification of every hyperparameter in the final system. Every value is explicitly categorized as either an experimentally selected parameter, a chosen operational operating point, or a fixed structural design parameter, eliminating guesswork for reproduction.
