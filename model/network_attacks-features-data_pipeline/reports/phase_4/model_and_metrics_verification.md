# Phase 4: Model Architecture Hardening & Standardized Evaluation Suite Audit

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. SparseRSSM Architecture Specification

- **Model Class:** `SparseRSSM` ([`src/models/sparse_rssm.py`](file:///C:/CyberSecurityNetworkingAttackPredictionModel/src/models/sparse_rssm.py))
- **State Dimension:** $D = 54$ continuous physical features
- **Latent Dimension:** $L = 128$
- **Recurrent Hidden Dimension:** $H = 128$
- **Canonical Sparsity Mode:** Dense mode (`sparsity_ratio = 1.0`) with Straight-Through Top-K operator
- **Total Trainable Parameters:** 214,334
- **Multi-Task Heads:**
  * State Decoder: $\hat{S}_{t+k} \in \mathbb{R}^{54}$
  * Threat Family Head: $\hat{\mathbf{c}}_{t+k} \in \mathbb{R}^{7}$
  * Attack Occurrence Head: $\hat{p}_{t+k} \in \mathbb{R}^{1}$
- **Forward/Backward Verification:** **PASSED (All parameter gradients confirmed)**

---

## 2. Standardized Multi-Task Evaluation Metric Suite

The evaluation suite ([`src/evaluation/benchmark_metrics.py`](file:///C:/CyberSecurityNetworkingAttackPredictionModel/src/evaluation/benchmark_metrics.py)) executes mathematical metric evaluations across 4 core domains:

| Domain | Primary Metrics | Purpose & Methodology |
| :--- | :--- | :--- |
| **1. Continuous State Rollout** | Overall MAE, MSE, Per-Step MAE ($k \in \{1, 3, 5, 10\}$) | Measures future physical telemetry trajectory tracking accuracy. |
| **2. Attack Occurrence Forecasting** | Precision, Recall, Macro F1, PR-AUC, ROC-AUC, FPR | Evaluates binary intrusion forecasting at $t+K$ ($20$s ahead). |
| **3. Threat Family Classification** | 7-Class Macro F1, Weighted F1, Per-Family Breakdown | Classifies impending threat family (DoS, DDoS, BruteForce, Web, Infiltration, Botnet). |
| **4. Onset Early Warning** | Onset Event Recall, Median Lead Time ($\Delta t$), FA/hr, MTBFA | Quantifies actionable advance warning prior to attack initiation. |

---

## 3. Anti-Leakage Calibration Protocols

1. **Segregated Threshold Calibration:** Decision threshold $\tau^*$ is calibrated exclusively via grid search on Validation probabilities.
2. **Precursor Isolation:** Onset early warning metrics evaluate strictly true negative-to-positive transition events during benign pre-attack windows.
3. **Physical State Preservation:** State errors are evaluated in normalized latent space and unscaled physical units.

_Generated automatically by `scripts/verification/verify_phase4_metrics.py`._