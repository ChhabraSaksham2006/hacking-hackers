# TFCNet Optimization & Ablation Study

## Scientific Comparison: Baseline Phase 6 vs. Optimized TFCNet

| Setting | Model Variant | State MAE | Binary F1 | Precision | Recall | PR-AUC | Onset Recall | FA / Hour |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Setting A** | Phase 6 Baseline | 0.1909 | 0.6259 | 0.4672 | 0.9478 | 0.8283 | 0.9655 | 351.7 |
| | **Optimized TFCNet** | **0.2048** | **0.5312** | **0.3623** | **0.9951** | **0.9049** | **0.9655** | **579.5** |
| **Setting B** | Phase 6 Baseline | 0.2557 | 0.5517 | 0.3814 | 0.9967 | 0.5661 | 1.0000 | 1195.2 |
| | **Optimized TFCNet** | **0.2384** | **0.5498** | **0.3793** | **0.9989** | **0.4989** | **1.0000** | **1208.3** |
| **Setting C** | Phase 6 Baseline | 0.2494 | 0.5512 | 0.3808 | 0.9976 | 0.5393 | 1.0000 | 1199.5 |
| | **Optimized TFCNet** | **0.2435** | **0.0024** | **0.0950** | **0.0012** | **0.4347** | **0.0000** | **8.6** |