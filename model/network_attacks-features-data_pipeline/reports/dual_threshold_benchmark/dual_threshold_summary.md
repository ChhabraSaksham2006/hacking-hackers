# Dual-Threshold Dynamic Trajectory Detection Benchmark

## Multi-Objective Optimization: Precision, Recall, and False Alarm Control

| Setting | Model | Tau High | Tau Low | Precision | Recall | F1 Score | Onset Recall | Lead Time | FA / Hour |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Setting A** | **SparseRSSM (Dual-Threshold)** | 0.9 | 0.35 | **0.7150** | **0.9478** | **0.8151** | **0.7931** | **20.0s** | **119.23 FA/hr** |
| **Setting A** | **TFCNet (Dual-Threshold)** | 0.9 | 0.35 | **0.7739** | **0.4962** | **0.6047** | **0.6207** | **20.0s** | **46.74 FA/hr** |
| **Setting B** | **SparseRSSM (Dual-Threshold)** | 0.8 | 0.25 | **0.5797** | **0.1503** | **0.2386** | **0.0000** | **0.0s** | **80.68 FA/hr** |
| **Setting B** | **TFCNet (Dual-Threshold)** | 0.8 | 0.25 | **0.5934** | **0.3167** | **0.4130** | **0.5714** | **20.0s** | **159.91 FA/hr** |
| **Setting C** | **SparseRSSM (Dual-Threshold)** | 0.7 | 0.25 | **0.8446** | **0.1234** | **0.2153** | **0.0000** | **0.0s** | **16.78 FA/hr** |
| **Setting C** | **TFCNet (Dual-Threshold)** | 0.7 | 0.25 | **0.5289** | **0.4338** | **0.4767** | **0.7143** | **20.0s** | **285.07 FA/hr** |