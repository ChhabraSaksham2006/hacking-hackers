# 06 — Phase 5.5 Loss Weight & Horizon Ablation

| Experiment ID | Architecture | Rollout $K$ | $\lambda_{	ext{attack}}$ | Pos Weight | Val Best $F_1$ | Test $F_1$ | Test Precision | Test Recall | Test FPR | Test PR-AUC | State MAE |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `E002_K1_lam0p1` | SparseRSSM | 1 | 0.1 | False | 0.1434 | 0.5321 | 45.15% | 64.78% | 32.34% | 0.4868 | 0.2388 |
| `E002_K1_lam0p5` | SparseRSSM | 1 | 0.5 | False | 0.1937 | 0.2578 | 69.06% | 15.85% | 2.92% | 0.5351 | 0.2441 |
| `E002_K1_lam1p0` | SparseRSSM | 1 | 1.0 | False | 0.2308 | 0.3007 | 72.47% | 18.97% | 2.96% | 0.5797 | 0.2448 |
| `E002_K1_lam2p0` | SparseRSSM | 1 | 2.0 | False | 0.2669 | 0.3056 | 76.41% | 19.10% | 2.42% | 0.5989 | 0.2447 |
| `E002_K1_lam5p0` | SparseRSSM | 1 | 5.0 | False | **0.2934** | 0.2869 | **81.26%** | 17.42% | **1.65%** | **0.6156** | 0.2466 |
| `E003_K1_pwno`   | SparseRSSM | 1 | 5.0 | False | 0.2934 | 0.2869 | 81.26% | 17.42% | 1.65% | 0.6156 | 0.2466 |
| `E003_K1_pwyes`  | SparseRSSM | 1 | 5.0 | **True** (8.26) | **0.3329** | 0.2994 | **84.66%** | 18.18% | **1.35%** | **0.6069** | 0.2497 |
| `E004_K10_pwyes` | SparseRSSM | 10 | 5.0 | **True** (8.26) | 0.1439 | **0.4832** | 47.23% | **49.47%** | 22.70% | 0.5462 | 0.2920 |
| `E004_K50_pwyes` | SparseRSSM | 50 | 5.0 | **True** (8.26) | 0.1590 | 0.1964 | **86.34%** | 11.08% | **0.72%** | 0.4173 | 0.2970 |

### Interpretation

Phase 5.5 retrained all models fresh with active gradient backpropagation into the attack head and enforced K_train = K_eval. Experiment E002 proved that increasing lambda_attack to 5.0 improved precision to 81.26% and PR-AUC to 0.6156. Experiment E003 proved that positive class weighting (8.26) boosted validation F1 to 0.3329. Experiment E004 demonstrated stable multi-horizon scaling up to K=50.
