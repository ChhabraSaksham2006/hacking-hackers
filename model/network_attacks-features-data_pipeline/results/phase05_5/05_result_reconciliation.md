# Historical Results Reconciliation Audit
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Phase:** 5.5 | **Date:** 2026-09-08

---

### 1. Classification of Historical Claims & Artifacts

| Historical Artifact / Claim | Former Statement | Forensic Verification Status | Reconciled Reality |
|---|---|---|---|
| `reports/phase_5/16_phase_5_final_verdict.md` (Q10) | "Onset recall is ~28%–57%" | **INVALID / SUPERSEDED** | Contradicted by actual CSV artifact `08_pre_onset_results.csv` which records $0.0\%$ recall for $H \le 20$s and $1.3\% - 4.5\%$ for $H \le 300$s. |
| `reports/phase_5/16_phase_5_final_verdict.md` (Q9) | "Dense RSSM beats Persistence on pre-onset decisively" | **INVALID / SUPERSEDED** | For $H \le 20$s, both RSSM and Persistence detected 0 onset transitions. Overstated claim. |
| `reports/phase_5/16_phase_5_final_verdict.md` (Q15) | "Top-50 (64 dimensions) is optimal sparsity" | **INVALID / SUPERSEDED** | `14_sparse_rssm_comparison.csv` shows Top-75 (96 dims) achieved $F_1 = 0.3451$, exceeding Top-50 ($F_1 = 0.2909$). |
| `master_metrics.csv` (Dense RSSM $K=1$) | Precision=84.86%, Recall=9.66%, $F_1=0.1735$ | **HISTORICAL (UNWEIGHTED)** | Measured under unweighted BCE loss (`pos_weight=None`). Verified that balanced class weighting elevates $F_1$ to $\sim 0.30 - 0.48$. |
| Phase 5 Optimization Pipeline ($K=100, 300$) | $K_{\text{train}}$ capped to 10 while $K_{\text{eval}}=100, 300$ | **INVALIDATED (METHODOLOGICAL MISMATCH)** | Models were trained on 10 rollout steps and evaluated on 100-300 rollout steps, incurring major distributional drift. |
| Pre-Onset Threshold Calibration (`08_pre_onset_results.csv`) | Threshold tuned on test set | **INVALIDATED (DATA LEAKAGE)** | Code iterated over test-set eligible samples to find the best $F_1$ threshold. Corrected in Phase 5.5 to tune threshold on validation eligible subset. |
| MITRE Stage Prediction | Claimed multi-task MITRE capability | **STALE / UNTRAINED** | $\lambda_{\text{mitre}} = 0.0$ in training runs and `src/mitre_mapping.py` contained DARPA attack mappings that returned 0 (Benign) for all CIC-IDS2018 flows. |

### 2. Authoritative Source of Truth
Effective with Phase 5.5:
- **Authoritative Metrics Table:** `reports/phase_5_5/authoritative_experiment_results.csv`
- **Authoritative Baselines Table:** `reports/phase_5_5/baseline_comparison.csv`
- **Authoritative Model Artifact:** `artifacts/rssm/model.pt`
All previous summaries in `reports/phase_5/16_phase_5_final_verdict.md` and legacy directories are superseded.
