# Final Authoritative Hyperparameter Specification

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Authoritative Architectural, Training, and Operational Hyperparameters**

---

## 1. Master Hyperparameter Table

| Hyperparameter Category | Hyperparameter Name | Canonical Variable | Final Value | Classification | Empirical Basis & Selection Experiment |
|---|---|---|---|---|---|
| **Data Ingestion** | Source Dataset | `dataset_name` | CSE-CIC-IDS2018 | Fixed Design Parameter | Established in Phase 2; complete modern attack taxonomy |
| **Data Ingestion** | Canonical State Dimension | `state_dim` ($D$) | 54 dimensions | Fixed Design Parameter | Phase 3A: 37 base + 17 delta features |
| **Data Ingestion** | Base Physical Features | `base_features` | 37 dimensions | Fixed Design Parameter | Grouped into 8 domain clusters |
| **Data Ingestion** | Temporal Delta Features | `delta_features` | 17 dimensions | Fixed Design Parameter | First-order differences $\Delta S_t = S_t - S_{t-1}$ |
| **Data Ingestion** | Temporal Window Duration | `window_seconds` | 10.0 seconds | Fixed Design Parameter | Phase 3C window resolution trade-off study |
| **Data Ingestion** | Window Step Stride | `stride_seconds` | 2.0 seconds | Fixed Design Parameter | Phase 3C temporal granularity optimization |
| **Data Ingestion** | Lookback Steps | $P$ | 10 windows | Fixed Design Parameter | Context length (20s history) required for precursor tracking |
| **Data Ingestion** | Rollout Horizon Steps | $K$ | 10 steps | Fixed Design Parameter | Lookahead steps for primary 20-second forecast ($10 \times 2.0\text{s}$) |
| **Data Ingestion** | Primary Forecast Horizon | $H$ | 20.0 seconds | Fixed Design Parameter | Primary operational SOC early-warning target |
| **Data Ingestion** | History Condition | `pure_benign` | Strict ($\max y_{t-9:t} = 0$) | Fixed Design Parameter | Phase 6 onset formulation: zero attack flows in lookback |
| **Data Ingestion** | State Normalization | `StandardScaler` | Zero-mean, unit-variance | Fixed Design Parameter | Fitted strictly on 5 training days (zero test leakage) |
| **Data Ingestion** | Missing / NaN Handling | `nan_handling` | Forward-fill then zero | Fixed Design Parameter | Clean handling of quiet network periods |
| **Architecture** | Model Class | `model_class` | `SparseRSSM` | Fixed Design Parameter | Recurrent state-space world model (`src/models/sparse_rssm.py`) |
| **Architecture** | Latent Dimension | `latent_dim` ($Z$) | 128 dimensions | Fixed Design Parameter | Latent capacity required for multi-modal dynamics |
| **Architecture** | Recurrent Hidden Dim | `hidden_dim` ($H$) | 128 dimensions | Fixed Design Parameter | Matches latent dimension in `GRUCell` memory core |
| **Architecture** | Encoder Structure | `encoder` | MLP (54→128→128→128) | Fixed Design Parameter | Linear + LayerNorm + GELU + Linear + GELU + Linear |
| **Architecture** | Decoder Structure | `state_decoder`| MLP (128→128→54) | Fixed Design Parameter | Linear + GELU + Linear continuous state rollout |
| **Architecture** | Recurrent Core | `gru` | PyTorch `GRUCell(128, 128)`| Fixed Design Parameter | Single-step recurrent world memory transition |
| **Architecture** | Transition Network | `transition` | MLP (256→128→128) | Fixed Design Parameter | Rollout transition from concatenated $[z_t, h_t]$ |
| **Architecture** | Attack Prediction Head | `attack_head` | Linear (256→1) | Fixed Design Parameter | Predicts binary onset logit per rollout step |
| **Architecture** | Multi-Head Attention | `use_attention` | `False` | Fixed Design Parameter | Standard recurrent dynamics without attention complexity |
| **Architecture** | Sparsity Ratio | `sparsity_ratio` | 1.0 (Dense) | Experimentally Selected | Phase 5 ablation: Top-10 diverged, Dense is stable |
| **Architecture** | Total Parameter Count | `num_params` | 213,820 parameters | Fixed Design Parameter | Verified across all checkpoints |
| **Training Pipeline**| Optimizer | `optimizer` | AdamW | Fixed Design Parameter | `torch.optim.AdamW` with decoupled weight decay |
| **Training Pipeline**| Learning Rate | `lr` | 0.001 ($10^{-3}$) | Fixed Design Parameter | Standard stable Adam learning rate |
| **Training Pipeline**| Weight Decay | `weight_decay` | 0.0001 ($10^{-4}$) | Fixed Design Parameter | L2 regularization on recurrent weights |
| **Training Pipeline**| Gradient Clipping | `grad_clip` | 1.0 (max norm) | Fixed Design Parameter | Prevents gradient explosion in recurrent rollouts |
| **Training Pipeline**| Batch Size | `batch_size` | 1024 sequences | Fixed Design Parameter | Stable batch gradient estimation |
| **Training Pipeline**| Training Epochs | `epochs` | 5 epochs | Experimentally Selected | Training loss plateaus at epoch 4–5 |
| **Training Pipeline**| Positive Class Weight | `pos_weight` | 8.26 | Fixed Design Parameter | Calculated directly from training split class ratio |
| **Training Pipeline**| Random Seed | `seed` | 42 | Experimentally Selected | Champion model across multi-seed evaluations |
| **Loss Formulation** | State Loss Weight | $\lambda_{\text{state}}$ | 1.0 | Fixed Design Parameter | Normalized continuous state reconstruction MSE |
| **Loss Formulation** | Attack Loss Weight | $\lambda_{\text{onset}}$ | 1.0 | Experimentally Selected | E604 ablation: higher weights degraded continuous state MAE |
| **Loss Formulation** | Precursor Multiplier | $M$ | 10.0× | Experimentally Selected | E602 winner: highest validation F1 and 20s lead time |
| **Loss Formulation** | Precursor Decay | $\tau$ | 60.0 seconds | Experimentally Selected | E603 winner: balanced precursor sensitivity |
| **Operational Policy**| Decision Threshold | $\tau_{\text{det}}$ | 0.04 | Experimentally Selected | Calibrated on validation split via max F1 |
| **Operational Policy**| Tier 1 Aggregation | `cooldown_10s` | 10.0s Cooldown | Chosen Operating Point | Retains 100% recall (7/7) with 79% noise reduction |
| **Operational Policy**| Tier 2 Aggregation | `cooldown_30s` | 30.0s Cooldown | Chosen Operating Point | Balanced: 71.43% recall (5/7) with 78.95 FA/hr |
| **Operational Policy**| Tier 3 Aggregation | `cooldown_60s` | 60.0s Cooldown | Chosen Operating Point | Low-noise: 57.14% recall (4/7) with 39.89 FA/hr |
| **Operational Policy**| Champion Aggregator | `consec2_cool60`| Consec-2 + 60s Cool | Chosen Operating Point | Minimal noise (39.57 FA/hr, 2.20% FPR, 28.57% recall) |

---

## 2. Parameter Category Descriptions

1. **Fixed Design Parameters:** Structural system requirements determined early in the project lifecycle (such as the 54-D state definition, 10s window/2s stride, 128 latent dimensions, and pos_weight=8.26).
2. **Experimentally Selected Parameters:** Values chosen directly based on comparative validation split performance during formal ablation sweeps (such as precursor multiplier 10x from E602, decay window 60s from E603, and decision threshold 0.04 from Phase 7 validation calibration).
3. **Chosen Operating Points:** Post-processing policy configurations selected to satisfy specific operational SOC operational constraints (such as the Tier 1 10s cooldown for maximum sensitivity vs Tier 3 60s cooldown for minimal alert volume).
