# 12 — Master Metrics Inventory

Master metrics table compiled across all completed experiments, logs, and artifacts.

| Model | Variant | Task | K | Forecast Horizon | Split | Attack F1 | Precision | Recall | FPR | State MAE | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Persistence** | y_t | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.9996 | 0.9996 | 0.9996 | 0.0002 | 0.1924 | Identity baseline; continuation dominated |
| **Persistence** | y_t | Binary_Attack_Forecasting | 3 | 6.0s | Test (OOD) | 0.9881 | 0.9881 | 0.9881 | 0.0024 | 0.2743 | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 5 | 10.0s | Test (OOD) | 0.965 | 0.965 | 0.965 | 0.0069 | 0.3342 | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 10 | 20.0s | Test (OOD) | 0.9307 | 0.9307 | 0.9307 | 0.0138 | 0.3243 | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.986 | 0.986 | 0.986 | 0.0058 | N/A | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.9726 | 0.9726 | 0.9726 | 0.0112 | N/A | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 200 | 400.0s | Test (OOD) | 0.9455 | 0.9455 | 0.9455 | 0.0228 | N/A | Identity baseline |
| **Persistence** | y_t | Binary_Attack_Forecasting | 300 | 600.0s | Test (OOD) | 0.9186 | 0.9186 | 0.9186 | 0.0337 | N/A | Identity baseline |
| **Majority** | Constant 0 | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.0 | 0.0 | 0.0 | 0.0 | N/A | Zero positive baseline |
| **Majority** | Constant 0 | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.0 | 0.0 | 0.0 | 0.0 | N/A | Zero positive baseline |
| **Logistic_Regression** | Static 54D | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.2766 | 0.6201 | 0.178 | 0.0315 | N/A | Val optimal thresh: 0.62 |
| **Logistic_Regression** | Static 54D | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.177 | 0.4528 | 0.11 | N/A | N/A | Direct per-K model |
| **Logistic_Regression** | Static 54D | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.2969 | 0.3155 | 0.2804 | N/A | N/A | Direct per-K model |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.2892 | 0.7703 | 0.178 | 0.0153 | N/A | Val optimal thresh: 0.71 |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.6139 | 0.5682 | 0.6676 | N/A | N/A | Direct per-K model |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.5581 | 0.4022 | 0.9114 | N/A | N/A | Val optimal thresh: 0.26 |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 200 | 400.0s | Test (OOD) | 0.3031 | 0.5812 | 0.205 | N/A | N/A | Direct per-K model |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 250 | 500.0s | Test (OOD) | 0.487 | 0.5369 | 0.4456 | N/A | N/A | Direct per-K model |
| **Random_Forest** | Static 54D | Binary_Attack_Forecasting | 300 | 600.0s | Test (OOD) | 0.4425 | 0.551 | 0.3697 | N/A | N/A | Direct per-K model |
| **GRU** | Full 10step 54D | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.109 | 0.7261 | 0.0589 | N/A | N/A | Sequence baseline |
| **Transformer** | Full 10step 54D | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.0684 | 0.738 | 0.0359 | N/A | N/A | Sequence baseline |
| **Transformer** | Full 10step 54D | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.3274 | 0.3654 | 0.2965 | N/A | 0.288 | Val optimal thresh: 0.01 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.554 | 0.3896 | 0.9584 | 0.6171 | N/A | Untrained attack head; val state MSE 0.3607 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.5569 | 0.3871 | 0.9924 | 0.6456 | N/A | Untrained attack head; val state MSE 0.5930 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.5542 | 0.3833 | 1.0 | 0.6608 | N/A | Untrained attack head; val state MSE 0.6087 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 200 | 400.0s | Test (OOD) | 0.5563 | 0.3853 | 1.0 | 0.6545 | N/A | Untrained attack head; val state MSE 0.6171 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 250 | 500.0s | Test (OOD) | 0.5528 | 0.3822 | 0.9989 | 0.6622 | N/A | Untrained attack head; val state MSE 0.6215 |
| **Dense_RSSM** | Dense 128D | Binary_Attack_Forecasting | 300 | 600.0s | Test (OOD) | 0.5576 | 0.3887 | 0.9858 | 0.6355 | N/A | Untrained attack head; val state MSE 0.6279 |
| **Sparse_RSSM** | Top-50 (64D) | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.5509 | 0.3817 | 0.9899 | 0.6593 | N/A | Untrained attack head; val state MSE 0.4006 |
| **Sparse_RSSM** | Top-50 (64D) | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.558 | 0.3945 | 0.953 | 0.6009 | N/A | Untrained attack head; val state MSE 0.5951 |
| **Sparse_RSSM** | Top-50 (64D) | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.5548 | 0.3841 | 0.9986 | 0.6575 | N/A | Untrained attack head; val state MSE 0.6117 |
| **Sparse_RSSM** | Top-10 (13D) | Binary_Attack_Forecasting | 1 | 2.0s | Test (OOD) | 0.5295 | 0.4169 | 0.7252 | 0.4169 | N/A | Untrained attack head; val state MSE 0.4115 |
| **Sparse_RSSM** | Top-10 (13D) | Binary_Attack_Forecasting | 50 | 100.0s | Test (OOD) | 0.0064 | 0.2947 | 0.0032 | 0.0032 | N/A | Severely degraded; val state MSE 0.6127 |
| **Sparse_RSSM** | Top-10 (13D) | Binary_Attack_Forecasting | 100 | 200.0s | Test (OOD) | 0.0 | 0.0 | 0.0 | 0.0 | N/A | Training diverged; val state MSE 1e+99 |
