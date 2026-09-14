# SparseRSSM Optimization & Ablation Study

## Scientific Comparison: Baseline Phase 5 vs. Optimized Model

| Setting | Model Variant | State MAE | Binary F1 | Precision | Recall | PR-AUC | Onset Recall | FA / Hour |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Setting A** | Phase 5 Baseline | 0.2234 | 0.6729 | 0.5106 | 0.9867 | 0.9678 | 0.9310 | 303.7 |
| | **Optimized Model** | **0.2247** | **0.6758** | **0.5136** | **0.9876** | **0.9708** | **0.9655** | **300.8** |
| **Setting B** | Phase 5 Baseline | 0.2841 | 0.3732 | 0.4671 | 0.3108 | 0.4803 | 0.4286 | 261.9 |
| | **Optimized Model** | **0.2826** | **0.2830** | **0.6124** | **0.1840** | **0.5363** | **0.1429** | **86.1** |
| **Setting C** | Phase 5 Baseline | 0.3166 | 0.5537 | 0.3890 | 0.9605 | 0.5100 | 1.0000 | 1115.4 |
| | **Optimized Model** | **0.2953** | **0.4294** | **0.6909** | **0.3115** | **0.6150** | **0.1429** | **102.6** |