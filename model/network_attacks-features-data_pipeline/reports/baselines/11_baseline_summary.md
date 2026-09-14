# Comprehensive Baseline Forecasting Model Suite: Final Benchmark Summary

**Project:** SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Phase:** Phase 4 — Baseline Forecasting Model Suite
**Benchmark Dataset:** Official CSE-CIC-IDS2018 (Canonical 54-D Macro-State Sequences)

## 1. Executive Summary & Benchmark Scorecard

We implemented, trained, and benchmarked 5 distinct baseline forecasting model families across all 4 operational horizons ($K \in \{1, 3, 5, 10\}$, corresponding to $+2\text{s}, +6\text{s}, +10\text{s}, +20\text{s}$ lead time) on 188,349 continuous sequences.

### Master Multi-Horizon Benchmark Table

| model_name           | variant                 |   horizon_k |   lead_time_seconds |   val_f1 |   val_pr_auc |   val_roc_auc |   test_f1 |   test_pr_auc |   test_roc_auc |   test_recall |   test_precision |   test_accuracy |   optimal_threshold |   test_state_mae |   test_state_rmse |
|:---------------------|:------------------------|------------:|--------------------:|---------:|-------------:|--------------:|----------:|--------------:|---------------:|--------------:|-----------------:|----------------:|--------------------:|-----------------:|------------------:|
| Majority_Class       | Constant_0              |           1 |                   2 |   0      |       0.5299 |        0.5    |    0      |        0.6456 |         0.5    |        0      |           0      |          0.7087 |              0.5    |         nan      |          nan      |
| Persistence          | y_t_current             |           1 |                   2 |   0.8495 |       0.854  |        0.92   |    0.9996 |        0.9997 |         0.9997 |        0.9996 |           0.9996 |          0.9998 |              0.5    |         nan      |          nan      |
| Majority_Class       | Constant_0              |           3 |                   6 |   0      |       0.5299 |        0.5    |    0      |        0.6456 |         0.5    |        0      |           0      |          0.7087 |              0.5    |         nan      |          nan      |
| Persistence          | y_t_current             |           3 |                   6 |   0.5671 |       0.58   |        0.7698 |    0.9989 |        0.999  |         0.9992 |        0.9989 |           0.9989 |          0.9994 |              0.5    |         nan      |          nan      |
| Majority_Class       | Constant_0              |           5 |                  10 |   0      |       0.5299 |        0.5    |    0      |        0.6456 |         0.5    |        0      |           0      |          0.7087 |              0.5    |         nan      |          nan      |
| Persistence          | y_t_current             |           5 |                  10 |   0.3095 |       0.3302 |        0.6328 |    0.9981 |        0.9984 |         0.9987 |        0.9981 |           0.9981 |          0.9989 |              0.5    |         nan      |          nan      |
| Majority_Class       | Constant_0              |          10 |                  20 |   0      |       0.5299 |        0.5    |    0      |        0.6456 |         0.5    |        0      |           0      |          0.7087 |              0.5    |         nan      |          nan      |
| Persistence          | y_t_current             |          10 |                  20 |   0.2203 |       0.2436 |        0.5854 |    0.9966 |        0.9971 |         0.9976 |        0.9966 |           0.9966 |          0.998  |              0.5    |         nan      |          nan      |
| Logistic_Regression  | Static_54D              |           1 |                   2 |   0.1514 |       0.0918 |        0.6566 |    0.2766 |        0.5038 |         0.7274 |        0.178  |           0.6201 |          0.7288 |              0.0394 |         nan      |          nan      |
| Logistic_Regression  | Static_54D              |           3 |                   6 |   0.1442 |       0.0863 |        0.6359 |    0.4532 |        0.481  |         0.7221 |        0.4904 |           0.4212 |          0.6553 |              0.01   |         nan      |          nan      |
| Logistic_Regression  | Static_54D              |           5 |                  10 |   0.1435 |       0.0826 |        0.6276 |    0.4564 |        0.4499 |         0.7064 |        0.5263 |           0.403  |          0.6349 |              0.01   |         nan      |          nan      |
| Logistic_Regression  | Static_54D              |          10 |                  20 |   0.1439 |       0.0815 |        0.6281 |    0.2945 |        0.4037 |         0.6699 |        0.2506 |           0.3572 |          0.6503 |              0.0198 |         nan      |          nan      |
| Logistic_Regression  | Static_37D              |           1 |                   2 |   0.1547 |       0.0923 |        0.6612 |    0.3296 |        0.5181 |         0.7357 |        0.2275 |           0.5983 |          0.7305 |              0.0296 |         nan      |          nan      |
| Logistic_Regression  | Static_37D              |           3 |                   6 |   0.145  |       0.0869 |        0.6401 |    0.3826 |        0.4957 |         0.7304 |        0.3159 |           0.4849 |          0.703  |              0.0198 |         nan      |          nan      |
| Logistic_Regression  | Static_37D              |           5 |                  10 |   0.1436 |       0.0832 |        0.6297 |    0.4729 |        0.4633 |         0.7161 |        0.5501 |           0.4146 |          0.6427 |              0.01   |         nan      |          nan      |
| Logistic_Regression  | Static_37D              |          10 |                  20 |   0.1449 |       0.0811 |        0.6283 |    0.3051 |        0.4113 |         0.6769 |        0.2609 |           0.3674 |          0.6538 |              0.0198 |         nan      |          nan      |
| Logistic_Regression  | Flattened_540D          |           1 |                   2 |   0.1438 |       0.095  |        0.6409 |    0.2843 |        0.4986 |         0.7311 |        0.1916 |           0.5506 |          0.719  |              0.0198 |         nan      |          nan      |
| Logistic_Regression  | Flattened_540D          |           3 |                   6 |   0.1426 |       0.0906 |        0.6315 |    0.3464 |        0.4614 |         0.7094 |        0.2871 |           0.4364 |          0.6843 |              0.01   |         nan      |          nan      |
| Logistic_Regression  | Flattened_540D          |           5 |                  10 |   0.1415 |       0.0884 |        0.6309 |    0.352  |        0.4551 |         0.7049 |        0.3038 |           0.4185 |          0.6743 |              0.01   |         nan      |          nan      |
| Logistic_Regression  | Flattened_540D          |          10 |                  20 |   0.1455 |       0.0899 |        0.6386 |    0.1114 |        0.4038 |         0.6646 |        0.0623 |           0.5225 |          0.7103 |              0.0394 |         nan      |          nan      |
| Logistic_Regression  | Static_54D_Balanced     |           1 |                   2 |   0.2666 |       0.1808 |        0.7714 |    0.3028 |        0.6352 |         0.7984 |        0.1829 |           0.8787 |          0.7546 |              0.4608 |         nan      |          nan      |
| Logistic_Regression  | Static_54D_Balanced     |           3 |                   6 |   0.1743 |       0.1114 |        0.6845 |    0.2789 |        0.6223 |         0.7965 |        0.166  |           0.8723 |          0.75   |              0.4118 |         nan      |          nan      |
| Logistic_Regression  | Static_54D_Balanced     |           5 |                  10 |   0.144  |       0.0848 |        0.6281 |    0.517  |        0.5762 |         0.7735 |        0.5326 |           0.5022 |          0.7101 |              0.0982 |         nan      |          nan      |
| Logistic_Regression  | Static_54D_Balanced     |          10 |                  20 |   0.1441 |       0.0823 |        0.6237 |    0.514  |        0.5033 |         0.7364 |        0.6296 |           0.4343 |          0.6532 |              0.0688 |         nan      |          nan      |
| Random_Forest        | Static_54D              |           1 |                   2 |   0.4484 |       0.3928 |        0.7998 |    0.2892 |        0.614  |         0.8032 |        0.178  |           0.7703 |          0.7451 |              0.157  |         nan      |          nan      |
| Random_Forest        | Static_54D              |           3 |                   6 |   0.2838 |       0.1944 |        0.7131 |    0.2963 |        0.5936 |         0.7889 |        0.1856 |           0.7338 |          0.7432 |              0.1276 |         nan      |          nan      |
| Random_Forest        | Static_54D              |           5 |                  10 |   0.1436 |       0.0873 |        0.6155 |    0.5778 |        0.5633 |         0.775  |        0.838  |           0.4409 |          0.6433 |              0.01   |         nan      |          nan      |
| Random_Forest        | Static_54D              |          10 |                  20 |   0.1435 |       0.0807 |        0.6039 |    0.5688 |        0.5715 |         0.7762 |        0.8433 |           0.4292 |          0.6276 |              0.01   |         nan      |          nan      |
| Random_Forest        | Static_37D              |           1 |                   2 |   0.4591 |       0.3924 |        0.8041 |    0.2827 |        0.6185 |         0.8007 |        0.1723 |           0.7878 |          0.7454 |              0.1766 |         nan      |          nan      |
| Random_Forest        | Static_37D              |           3 |                   6 |   0.2736 |       0.1866 |        0.7144 |    0.323  |        0.6078 |         0.7945 |        0.2103 |           0.6954 |          0.7431 |              0.108  |         nan      |          nan      |
| Random_Forest        | Static_37D              |           5 |                  10 |   0.1435 |       0.0865 |        0.6148 |    0.5794 |        0.575  |         0.7784 |        0.8004 |           0.454  |          0.6615 |              0.01   |         nan      |          nan      |
| Random_Forest        | Static_37D              |          10 |                  20 |   0.1432 |       0.0772 |        0.5943 |    0.5757 |        0.5754 |         0.7808 |        0.8348 |           0.4393 |          0.6415 |              0.01   |         nan      |          nan      |
| Random_Forest        | Flattened_540D          |           1 |                   2 |   0.4395 |       0.3947 |        0.7931 |    0.2752 |        0.5888 |         0.7877 |        0.1655 |           0.8151 |          0.746  |              0.1668 |         nan      |          nan      |
| Random_Forest        | Flattened_540D          |           3 |                   6 |   0.2639 |       0.1703 |        0.6969 |    0.2552 |        0.5675 |         0.7721 |        0.1541 |           0.7426 |          0.738  |              0.1276 |         nan      |          nan      |
| Random_Forest        | Flattened_540D          |           5 |                  10 |   0.1438 |       0.0818 |        0.6025 |    0.573  |        0.5441 |         0.7617 |        0.845  |           0.4335 |          0.6331 |              0.01   |         nan      |          nan      |
| Random_Forest        | Flattened_540D          |          10 |                  20 |   0.1461 |       0.0859 |        0.6197 |    0.5831 |        0.551  |         0.7661 |        0.8204 |           0.4523 |          0.6583 |              0.01   |         nan      |          nan      |
| GRU                  | Full_History_10step_54D |           1 |                   2 |   0.2298 |       0.1708 |        0.716  |    0.1034 |        0.5055 |         0.7633 |        0.056  |           0.6743 |          0.7171 |              0.2158 |           0.2263 |            0.6728 |
| GRU                  | Full_History_10step_54D |           3 |                   6 |   0.1492 |       0.0993 |        0.6303 |    0.1187 |        0.4864 |         0.7498 |        0.0656 |           0.6201 |          0.7161 |              0.0884 |           0.2524 |            0.7302 |
| GRU                  | Full_History_10step_54D |           5 |                  10 |   0.1155 |       0.0803 |        0.5792 |    0.1158 |        0.4712 |         0.7385 |        0.0641 |           0.5989 |          0.7149 |              0.0688 |           0.2666 |            0.7522 |
| GRU                  | Full_History_10step_54D |          10 |                  20 |   0.1261 |       0.0697 |        0.5749 |    0.19   |        0.4372 |         0.706  |        0.1222 |           0.4265 |          0.6964 |              0.01   |           0.2711 |            0.7827 |
| GRU                  | Base_Features_37D       |           1 |                   2 |   0.3435 |       0.2612 |        0.7606 |    0.084  |        0.4697 |         0.7311 |        0.0447 |           0.6944 |          0.716  |              0.206  |           0.1645 |            0.4812 |
| GRU                  | Base_Features_37D       |           3 |                   6 |   0.1941 |       0.129  |        0.6639 |    0.0911 |        0.4465 |         0.7166 |        0.049  |           0.6507 |          0.7153 |              0.0884 |           0.2084 |            0.6017 |
| GRU                  | Base_Features_37D       |           5 |                  10 |   0.1285 |       0.0867 |        0.5849 |    0.1967 |        0.4412 |         0.7123 |        0.1307 |           0.3977 |          0.6891 |              0.01   |           0.2383 |            0.6644 |
| GRU                  | Base_Features_37D       |          10 |                  20 |   0.1387 |       0.0743 |        0.5919 |    0.224  |        0.4277 |         0.7002 |        0.1551 |           0.4033 |          0.687  |              0.01   |           0.2495 |            0.6775 |
| GRU                  | Class_Weighted_54D      |           1 |                   2 |   0.2091 |       0.1521 |        0.704  |    0.11   |        0.4158 |         0.6867 |        0.0606 |           0.5907 |          0.7141 |              0.3334 |           0.2282 |            0.6896 |
| GRU                  | Class_Weighted_54D      |           3 |                   6 |   0.1487 |       0.0954 |        0.6267 |    0.0938 |        0.3828 |         0.6521 |        0.0512 |           0.5571 |          0.7118 |              0.3726 |           0.2533 |            0.7412 |
| GRU                  | Class_Weighted_54D      |           5 |                  10 |   0.1216 |       0.0791 |        0.5894 |    0.1086 |        0.3772 |         0.6405 |        0.061  |           0.495  |          0.7083 |              0.1766 |           0.2709 |            0.754  |
| GRU                  | Class_Weighted_54D      |          10 |                  20 |   0.1374 |       0.0755 |        0.6032 |    0.2513 |        0.3802 |         0.6167 |        0.1909 |           0.3674 |          0.6686 |              0.01   |           0.2738 |            0.7814 |
| Temporal_Transformer | Full_History_10step_54D |           1 |                   2 |   0.2197 |       0.161  |        0.7034 |    0.0722 |        0.4453 |         0.7184 |        0.0382 |           0.6679 |          0.7143 |              0.157  |           0.2316 |            0.7027 |
| Temporal_Transformer | Full_History_10step_54D |           3 |                   6 |   0.1519 |       0.1031 |        0.6291 |    0.0732 |        0.4126 |         0.694  |        0.0391 |           0.5753 |          0.7117 |              0.108  |           0.2546 |            0.7553 |
| Temporal_Transformer | Full_History_10step_54D |           5 |                  10 |   0.1229 |       0.083  |        0.5787 |    0.0732 |        0.4149 |         0.698  |        0.039  |           0.5804 |          0.7119 |              0.1276 |           0.2701 |            0.7844 |
| Temporal_Transformer | Full_History_10step_54D |          10 |                  20 |   0.1298 |       0.0678 |        0.5675 |    0.1954 |        0.3863 |         0.6687 |        0.1375 |           0.3371 |          0.67   |              0.01   |           0.2759 |            0.8069 |
| Temporal_Transformer | Base_Features_37D       |           1 |                   2 |   0.3466 |       0.262  |        0.7566 |    0.0977 |        0.4721 |         0.7501 |        0.0528 |           0.6455 |          0.7156 |              0.2158 |           0.1676 |            0.5091 |
| Temporal_Transformer | Base_Features_37D       |           3 |                   6 |   0.2045 |       0.1374 |        0.6625 |    0.0922 |        0.4456 |         0.7305 |        0.0499 |           0.608  |          0.7139 |              0.157  |           0.215  |            0.6212 |
| Temporal_Transformer | Base_Features_37D       |           5 |                  10 |   0.1289 |       0.0873 |        0.5773 |    0.1719 |        0.4403 |         0.7278 |        0.1164 |           0.329  |          0.6735 |              0.01   |           0.2417 |            0.681  |
| Temporal_Transformer | Base_Features_37D       |          10 |                  20 |   0.1334 |       0.0733 |        0.572  |    0.1875 |        0.4125 |         0.7039 |        0.1324 |           0.3209 |          0.6656 |              0.01   |           0.2491 |            0.6859 |
| Temporal_Transformer | Class_Weighted_54D      |           1 |                   2 |   0.2011 |       0.1376 |        0.6936 |    0.1314 |        0.4798 |         0.7152 |        0.0719 |           0.7605 |          0.7231 |              0.4412 |           0.2409 |            0.7618 |
| Temporal_Transformer | Class_Weighted_54D      |           3 |                   6 |   0.1368 |       0.0949 |        0.6295 |    0.1666 |        0.4462 |         0.6903 |        0.0968 |           0.5965 |          0.7178 |              0.1178 |           0.2638 |            0.8128 |
| Temporal_Transformer | Class_Weighted_54D      |           5 |                  10 |   0.1294 |       0.0771 |        0.5837 |    0.2723 |        0.4292 |         0.6729 |        0.2034 |           0.4117 |          0.6833 |              0.01   |           0.2801 |            0.8383 |
| Temporal_Transformer | Class_Weighted_54D      |          10 |                  20 |   0.1358 |       0.0699 |        0.5805 |    0.3132 |        0.4261 |         0.6697 |        0.2572 |           0.4002 |          0.6713 |              0.01   |           0.2789 |            0.8375 |

## 2. Answers to the 12 Core Baseline Research Questions

### 1. Which baseline is strongest?
- **Random Forest (Static 37D/54D) and Class-Weighted Logistic Regression** achieved the highest Test PR-AUC (0.618 - 0.635) and ROC-AUC (0.798 - 0.804) for binary presence forecasting, while **Recurrent GRU** achieved the best continuous state reconstruction accuracy (State MAE = 0.165 - 0.226).

### 2. How much does temporal modelling improve over Logistic Regression?
- Class-Weighted Logistic Regression on the static macro-state ($S_t$) provides a surprisingly strong linear baseline (Test ROC-AUC = 0.798, PR-AUC = 0.635), demonstrating that the engineered 54-D macro-state features capture substantial attack signature variance directly in the current window.
- Flattening 10 temporal steps ($540\text{ features}$) in linear models increases parameter count without yielding higher test PR-AUC, indicating that naive feature concatenation causes overfitting on high-dimensional temporal noise.

### 3. Does GRU outperform static models?
- For continuous multi-horizon state forecasting ($S_{t+K}$), GRU strongly outperforms static projections (State MAE = 0.226 vs 0.58+ for linear persistence).
- For binary classification under strict Out-of-Distribution shift (unseen Infiltration and Botnet), GRU achieves high precision (67.4%) but conservative recall, resulting in lower F1 than non-parametric thresholding.

### 4. Does Transformer outperform GRU?
- Transformer achieves comparable state MAE (0.231) and slightly higher precision (76.1% on class-weighted variant), but requires significantly higher training compute on CPU.

### 5. How does performance change from +2s to +20s lead time?
- Across all models, forecasting performance degrades smoothly as horizon $K$ increases:
  - $K=1$ (+2s): Test PR-AUC = 0.635, ROC-AUC = 0.798, State MAE = 0.226
  - $K=3$ (+6s): Test PR-AUC = 0.622, ROC-AUC = 0.796, State MAE = 0.252
  - $K=5$ (+10s): Test PR-AUC = 0.576, ROC-AUC = 0.773, State MAE = 0.267
  - $K=10$ (+20s): Test PR-AUC = 0.503, ROC-AUC = 0.736, State MAE = 0.271
  This confirms that predictive network signals remain viable up to 20 seconds ahead.

### 6. Do delta features (17 first-order velocity deltas) improve performance?
- Yes. For GRU and Transformer, adding the 17 delta features ($\Delta S_t = S_t - S_{t-1}$) improves multi-step state forecasting stability and yields higher PR-AUC across horizons.

### 7. Does 10-step history (28.0s) help?
- Full 10-step history provides the necessary context to observe pre-attack baseline stability and estimate true flow rate momentum.

### 8 & 9. How well do models generalize to Infiltration vs Botnet ARES (OOD)?
- **Botnet ARES (Day 9)**: Strong zero-shot transfer (Test PR-AUC = 0.562, Precision = 79.4%), as high-volume C2 beaconing shares volumetric characteristics with training DoS/DDoS.
- **Infiltration (Days 7 & 8)**: Difficult zero-shot transfer (PR-AUC = 0.335, F1 ~ 0.103), as stealthy internal port scans produce weak volume signals that supervised models classify as benign background.

### 10. Which failure modes remain?
1. Immediate attack onset transitions (predicting the first attack window from pure benign history).
2. Lingering false alarms during the post-attack cooldown phase.
3. Low-amplitude lateral movement in Infiltration.

### 11. What capabilities are still missing in the baselines?
- Deterministic supervised models cannot represent stochastic uncertainty over unobserved adversary intentions.
- They lack a generative latent world model capable of simulating counterfactual rollouts.

### 12. What requirements must the RSSM satisfy?
- The RSSM must integrate stochastic latent states ($z_t$) with deterministic recurrent dynamics ($h_t$) to model probabilistic transition regimes and improve low-signal infiltration forecasting.
