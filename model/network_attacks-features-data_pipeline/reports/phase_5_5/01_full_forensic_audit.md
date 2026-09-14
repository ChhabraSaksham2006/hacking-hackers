# Phase 5.5 — Full Forensic Audit Report
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Generated:** 2026-09-08 | **Branch:** features/llm_pipeline | **Commit:** 6d20a8e

---

## Audit Methodology

Every file in the execution path was read directly from source. Results compared
against actual CSV artifacts and live data queries. Previous reports NOT used
as authoritative references.

---

## CRITICAL ISSUES

### CRIT-01: False Claims in `16_phase_5_final_verdict.md`
- Report claims: "genuine pre-onset recall ~28-57%"
- **Actual** `08_pre_onset_results.csv`: 0.0% for H<=20s, 1.3-4.5% for H<=300s
- Report claims: "RSSM beats Persistence on pre-onset — YES decisively"
- **Actual**: both achieve 0 onset detections for H<=20s
- Report claims: "Top-50 is optimal"
- **Actual** `14_sparse_rssm_comparison.csv`: Top-75 F1=0.3451 > Top-50 F1=0.2909
- **Status:** MUST BE SUPERSEDED

### CRIT-02: K_train vs K_eval Mismatch for K=100, K=300
```python
k_train_eff = min(k, 10) if k_train is None else k_train
```
K=100 and K=300 models trained with k_train=10. Evaluated at 100/300 steps.
- **Affects Previous Metrics:** YES — K=100, K=300 results are from K=10-trained models
- **Status:** REQUIRES_REPRODUCTION with k_train=k

### CRIT-03: K=1,10,50 Checkpoints May Be Pre-Fix (Untrained Attack Head)
Checkpoint reuse logic loads existing .pt files without verifying creation date.
K=1,10,50 checkpoints existed BEFORE commit 6d20a8e (the attack head fix).
- **Affects Previous Metrics:** K=1 F1=0.1735 may be from untrained attack head
- **Status:** REQUIRES_REPRODUCTION — all K must be retrained post-fix

### CRIT-04: Pre-Onset Threshold Selected on Test Set (Data Leakage)
```python
# In evaluate_pre_onset_forecasting():
for t in [0.05, 0.10, ...]:
    m = compute_binary_metrics_at_threshold(y_onset, pred_risk, threshold=t)
    if m['f1'] > best_f1: best_m = m  # y_onset IS the test set
```
- **Status:** MUST FIX — threshold must be from validation eligible subset

---

## HIGH ISSUES

### HIGH-01: No Positive Class Weighting in BCEWithLogitsLoss
- Train attack rate ~10.7%. pos_weight=None throughout all experiments.
- Result: high precision (~84%), near-zero recall (~9%)
- **Status:** MUST TEST in Phase 5.5 experiment E002

### HIGH-02: MITRE Mapping Uses DARPA Labels Only
- `src/mitre_mapping.py` contains KDD-99 labels (neptune, smurf, etc.)
- CIC-IDS2018 labels (BruteForce, DoS, Botnet) are absent
- `get_mitre_stage_code()` returns 0 (Benign) for ALL CIC attacks
- **Status:** DEFERRED to Phase 7

### HIGH-03: icmp_ratio Constant in One Training Day
- Feature index 8, `icmp_ratio`, has zero variance in Wed-14-02-2018
- After scaling: constant feature contributes no information
- **Status:** VALIDATED — not a code bug, feature is valid but non-informative

### HIGH-04: Event-Centered Analysis Uses Unscaled Features
- `run_event_centered_forensic_analysis()` constructs sequences from raw_dfs
  without applying StandardScaler
- Event trajectory predictions are unreliable
- **Status:** BUG in analysis code (not main metrics)

---

## MEDIUM ISSUES

### MED-01: Orphaned Dead-Code Modules
- `src/models/heads.py`, `src/models/transition.py`, `src/models/sparse_latent.py`
- Never imported by any active experiment script
- **Status:** LEGACY — will be archived

### MED-02: trainer.py Not Used by RSSM
- `src/training/trainer.py` is for GRU/Transformer baselines
- RSSM trains inline in run_phase5_optimized.py
- **Status:** LEGACY for baselines only

### MED-03: Config Horizon List Incomplete
- `configs/temporal.yaml` lists K=[1..200] but experiments use K=300
- **Status:** INCONSISTENCY (config not read by experiment scripts)

---

## OK — Verified Correct

| Item | Description | Status |
|---|---|---|
| OK-01 | Chronological split | VALIDATED |
| OK-02 | Scaler fitted on train only | VALIDATED |
| OK-03 | No cross-day boundary sequences | VALIDATED |
| OK-04 | State features are future-free (54-D) | VALIDATED |
| OK-05 | Gradient clipping applied | VALIDATED |
| OK-06 | Target construction alignment (t+k) | VALIDATED |
| OK-07 | Attack BCE gradients non-zero post-fix | VALIDATED (post-6d20a8e) |
| OK-08 | Row counts match manifest | VALIDATED |
| OK-09 | No NaN/Inf in state features | VALIDATED |
| OK-10 | Persistence phenomenon quantified | VALIDATED |

---

## Persistence Phenomenon (TEST SET — Measured)

```
k=1:   P(y+1=1|y=1)=0.9996, P(y+1=1|y=0)=0.0002, onsets=7,   cont=18,866
k=10:  P(y+10=1|y=1)=0.9966, P(y+10=1|y=0)=0.0014, onsets=65, cont=18,799
k=50:  P(y+50=1|y=1)=0.9861, P(y+50=1|y=0)=0.0057, onsets=261, cont=18,563
k=150: P(y+150=1|y=1)=0.9594, P(y+150=1|y=0)=0.0167, onsets=761, cont=17,963
```

These numbers quantify why continuation F1 is dominated by Persistence,
and why pre-onset recall is near-zero (very few genuine transition samples exist).

---

## Summary: Issues by Severity

| Severity | Count | Must Fix Before Experiments |
|---|---|---|
| CRITICAL | 4 | YES — all must be addressed |
| HIGH | 4 | 2 must fix, 2 deferred |
| MEDIUM | 3 | No (cleanup only) |
| LOW | 4 | No (cleanup later) |
| OK | 10 | N/A |
