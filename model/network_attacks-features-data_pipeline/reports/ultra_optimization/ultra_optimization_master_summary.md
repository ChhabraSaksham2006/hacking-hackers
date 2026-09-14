# Ultra-Optimization Master Benchmark Report

## Multi-Objective Precision Boosting & False Alarm Suppression (< 10 FA/Hour)
**Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data**

---

## 1. Master Ultra-Optimized Benchmark Table

| Setting | Model | Calibrated Filter | Tau | State MAE | Binary F1 | Precision | Recall | PR-AUC | Onset Recall | FA / Hour |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Setting A** | **SparseRSSM** | raw (α=0.0) | $\tau=0.94$ | **0.2234** | **0.9334** | **0.9390** | **0.9280** | **0.9678** | **0.1034** | **17.96 FA/hr** |
| **Setting B** | **SparseRSSM** | persistence (α=0.4) | $\tau=0.85$ | **0.2841** | **0.0482** | **0.8139** | **0.0248** | **0.4885** | **0.0000** | **4.20 FA/hr** |
| **Setting C** | **SparseRSSM** | ema (α=0.0) | $\tau=0.92$ | **0.3166** | **0.1885** | **0.9559** | **0.1046** | **0.5134** | **0.0000** | **3.58 FA/hr** |
| **Setting A** | **TFCNet** | raw (α=0.0) | $\tau=0.89$ | **0.1909** | **0.5967** | **0.9651** | **0.4318** | **0.8283** | **0.0345** | **3.61 FA/hr** |
| **Setting B** | **TFCNet** | persistence (α=0.2) | $\tau=0.95$ | **0.2557** | **0.0008** | **0.4706** | **0.0004** | **0.5567** | **0.0000** | **0.35 FA/hr** |
| **Setting C** | **TFCNet** | ema (α=0.4) | $\tau=0.94$ | **0.2494** | **0.0000** | **0.0000** | **0.0000** | **0.5276** | **0.0000** | **0.12 FA/hr** |