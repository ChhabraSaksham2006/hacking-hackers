# Phase 4.5 — Comprehensive Forensic Audit (SparseRSSM)

## 1. Phase Identifier
Phase 4.5 | Commit: `d80ef1f` | Branch: `features/data_pipeline`

## 2. Objective
Perform a comprehensive, 24-section forensic audit of the SparseRSSM model, the 54-D temporal dataset, baselines, and all evaluation protocols. Identify all critical bugs before proceeding with model improvement.

## 3. Dataset
Same as Phase 3/4: CSE-CIC-IDS2018 54-D temporal states.

## 4. Input Features
54-D temporal state. P=10 lookback.

## 5. Model Architecture
SparseRSSM (inspected, not retrained in this phase).

## 6. Experiments Run
24-section forensic audit (see `reports/final_audit/`):
- Git sync and branch audit
- Repository inventory
- Dataset audit (flow counts, session coverage)
- Data pipeline correctness
- Feature lineage and ordering
- Leakage audit
- Baseline re-analysis
- Dense RSSM audit
- Sparse RSSM audit
- Training configuration audit
- Master metrics tabulation
- Horizon analysis
- **Persistence forensics (Persistence Paradox discovered)**
- Onset forecasting (initial evaluation)
- Future-state forecasting
- OOD analysis (Infiltration, Botnet as OOD)
- MITRE audit (heuristic mapping)
- Reproducibility audit
- Executive summary

## 7. Important Changes From Previous Phase
Discovery of three critical issues documented below.

## 8. Results

### 3 Critical Forensic Discoveries

1. **CRIT-01: Untrained Attack Head**
   - `SparseRSSM.loss()` prior to commit `6d20a8e` did NOT include attack BCE loss
   - Attack head was randomly initialized and untrained
   - At threshold 0.5, produced ~75% false positive rate (aggressive random predictor)
   - **STATUS: Fixed in commit `6d20a8e`**

2. **CRIT-02: Persistence Paradox**
   - Attack sessions in CIC-IDS2018 are 6–12 hour contiguous blocks (e.g., Botnet 720 min, Infiltration 535 min)
   - Only 7 attack onsets vs 18,867 continuation positives in test set
   - Persistence achieves F1=0.9996 by exploiting temporal autocorrelation
   - On pre-onset transitions: Persistence F1 = 0.0000 (useless for early warning)
   - **STATUS: Documented; correct task = pre-onset detection**

3. **CRIT-03: K_train vs K_eval Mismatch**
   - Phase 5 training used implicit `min(k, 10)` cap during rollout
   - Models evaluated at K=100/300 were trained with max K=10 rollout
   - Creates 10x–30x extrapolation gap
   - **STATUS: Fixed in Phase 5.5 by enforcing K_train = K_eval**

## 9. Conclusion
Phase 4.5 established that all previous results (Phase 5) were **invalid** due to the three critical bugs. All models must be retrained from scratch with corrected code.

## 10. Important Artifacts
- `reports/final_audit/00_git_sync.md` through `reports/final_audit/24_final_research_assessment.md` — Complete 24-section forensic audit
- `reports/final_audit/master_metrics.csv` — Tabulated metrics across all models

## 11. Git Commit
`d80ef1f` — "feat(audit): complete Phase 4.5 comprehensive forensic audit and add temporal state parquets"

## 12. Scientific Status
**ACTIVE** as historical forensic evidence. All critical findings were corrected in Phase 5.5.

## 13. Known Issues / Bugs
All three critical bugs (CRIT-01/02/03) documented and scheduled for Phase 5.5 correction.

## 14. Open Questions at End of Phase
After fixing the three critical bugs, can the SparseRSSM achieve genuine pre-onset early warning?

## 15. Transition to Next Phase
Phase 5.5 (Forensic Correction & Stabilization). Phase 5 (pre-audit RSSM benchmark) is superseded.

## 16. Files Modified
`reports/final_audit/` (24 files created), `reports/phase_4_5/`

## 17. Reproducibility Status
Audit reports preserved in `reports/final_audit/`. Critical bug fixes traceable to commit `6d20a8e`.
