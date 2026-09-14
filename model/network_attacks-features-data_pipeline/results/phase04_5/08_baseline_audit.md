# 08 — Baseline Models Audit

## 1. Implemented Baseline Model Suite

| Model Name | Model Class | Input Format | Optimization / Training | Loss Function | Horizon Support | Decision Threshold Policy | Output Representation |
|---|---|---|---|---|---|---|---|
| **Majority Forecaster** | `MajorityForecaster` | None | None (Empirical baseline) | None | All $K$ | Always 0 (Benign) | Binary $y=0$ |
| **Persistence Forecaster** | `PersistenceForecaster` | Current label $y_t$ | None (Identity mapping) | None | All $K$ | Always $y_{t+K} = y_t$ | Binary $y_{t+K}$ |
| **Logistic Regression** | `LogisticRegressionForecaster` | Static 54D / Static 37D / Flat 540D | Scikit-Learn L-BFGS, max_iter=500 | Logistic Loss (BCE) | Per-$K$ direct retrain | Max Validation F1 | Predicted prob & class |
| **Random Forest** | `RandomForestForecaster` | Static 54D / Static 37D / Flat 540D | 100 Trees, max_depth=15, split=10 | Gini Impurity | Per-$K$ direct retrain | Max Validation F1 | Predicted prob & class |
| **Temporal GRU** | `TemporalGRUForecaster` | Sequences $(B, P=10, 54)$ | PyTorch AdamW, lr=1e-3, 10 epochs | Multi-head BCE + MSE | Multi-head direct | Max Validation F1 | Probabilities & continuous state |
| **Temporal Transformer** | `TemporalTransformerForecaster` | Sequences $(B, P=10, 54)$ | PyTorch AdamW, lr=1e-3, 10 epochs | Multi-head BCE + MSE | Multi-head direct | Max Validation F1 | Probabilities & continuous state |

## 2. Master Baseline Performance Comparison Table

| Model | Variant | $K$ | Lead Time | Attack F1 | Precision | Recall | FPR | PR-AUC | ROC-AUC | Optimal Thresh | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Majority** | Constant 0 | 1 | 2.0s | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.2913 | 0.5000 | 0.50 | Zero positive predictions |
| **Majority** | Constant 0 | 100 | 200.0s | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.2911 | 0.5000 | 0.50 | Zero positive predictions |
| **Persistence** | $y_t$ | 1 | 2.0s | **0.9996** | 0.9996 | 0.9996 | 0.0002 | 0.9996 | 0.9997 | 0.50 | Continuation dominated |
| **Persistence** | $y_t$ | 50 | 100.0s | **0.9860** | 0.9860 | 0.9860 | 0.0058 | 0.9860 | 0.9901 | 0.50 | Continuation dominated |
| **Persistence** | $y_t$ | 100 | 200.0s | **0.9726** | 0.9726 | 0.9726 | 0.0112 | 0.9766 | 0.9807 | 0.50 | Continuation dominated |
| **Persistence** | $y_t$ | 200 | 400.0s | **0.9455** | 0.9455 | 0.9455 | 0.0228 | 0.9455 | 0.9614 | 0.50 | Continuation dominated |
| **Persistence** | $y_t$ | 300 | 600.0s | **0.9186** | 0.9186 | 0.9186 | 0.0337 | 0.9186 | 0.9424 | 0.50 | Continuation dominated |
| **Logistic Reg.** | Static 54D | 1 | 2.0s | 0.2766 | 0.6201 | 0.1780 | 0.0315 | 0.5038 | 0.7274 | 0.62 | Validation selected thresh |
| **Logistic Reg.** | Static 54D | 50 | 100.0s | 0.1770 | 0.4528 | 0.1100 | N/A | N/A | N/A | 0.48 | Direct retrain |
| **Logistic Reg.** | Static 54D | 100 | 200.0s | 0.2969 | 0.3155 | 0.2804 | N/A | N/A | N/A | 0.54 | Direct retrain |
| **Random Forest** | Static 54D | 1 | 2.0s | 0.2892 | 0.7703 | 0.1780 | 0.0153 | 0.6140 | 0.8032 | 0.71 | High precision |
| **Random Forest** | Static 54D | 50 | 100.0s | 0.6139 | 0.5682 | 0.6676 | N/A | N/A | N/A | 0.41 | Direct retrain |
| **Random Forest** | Static 54D | 100 | 200.0s | 0.5581 | 0.4022 | 0.9114 | N/A | N/A | N/A | 0.26 | High recall at K=100 |
| **Random Forest** | Static 54D | 200 | 400.0s | 0.3031 | 0.5812 | 0.2050 | N/A | N/A | N/A | 0.59 | Direct retrain |
| **Random Forest** | Static 54D | 300 | 600.0s | 0.4425 | 0.5510 | 0.3697 | N/A | N/A | N/A | 0.48 | Direct retrain |
| **GRU** | Full 10step 54D | 1 | 2.0s | 0.1090 | 0.7261 | 0.0589 | N/A | 0.5289 | 0.7773 | 0.45 | Underfitting attack class |
| **GRU** | Full 10step 54D | 10 | 20.0s | 0.2456 | 0.4433 | 0.1699 | N/A | 0.4525 | 0.7181 | 0.38 | Direct sequence model |
| **Transformer** | Full 10step 54D | 1 | 2.0s | 0.0684 | 0.7380 | 0.0359 | N/A | 0.4711 | 0.7426 | 0.52 | Severe class imbalance |
| **Transformer** | Full 10step 54D | 100 | 200.0s | 0.3274 | 0.3654 | 0.2965 | N/A | 0.3724 | 0.6316 | 0.01 | Threshold collapsed |
