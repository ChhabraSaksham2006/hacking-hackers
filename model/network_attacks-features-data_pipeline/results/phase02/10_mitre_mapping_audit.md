# 10 — Independent MITRE ATT&CK Mapping & Decoupled Interpretation Architecture
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Architectural Separation

* **Forecasting Layer**: The Neural World Model predicts continuous future telemetry dynamics $S_{t+K} \in \mathbb{R}^D$ and anomalous transition probabilities.
* **Interpretation Layer**: The decoupled rule engine in `src/mitre/` matches predicted state dynamics (port entropy, packet velocity, flag ratios, IAT jitter) to verified MITRE ATT&CK techniques with measurable confidence intervals.
