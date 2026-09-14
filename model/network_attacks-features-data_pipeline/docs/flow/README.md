# Research Flow Documentation

## SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data

**Dataset:** CSE-CIC-IDS2018  
**Branch:** `features/data_pipeline` (authoritative)  
**Final Commit:** `d2c7da5`  
**Status:** RESEARCH FROZEN

---

## Overview

This directory contains the phase-by-phase research flow documentation for the complete project lifecycle. Each file documents one research phase with a standardized structure covering objectives, methods, experiments, results, and artifacts.

## Phase Index

| File | Phase | Title |
|------|-------|-------|
| [phase-01.md](phase-01.md) | 1 | Initial DARPA+CIC Dataset Exploration & LSTM World Model |
| [phase-02.md](phase-02.md) | 2 | EDA, Anomaly Audit, Logistic Regression Baseline |
| [phase-03.md](phase-03.md) | 3 | 54-D Temporal State Aggregation & Dataset Forensic Audit |
| [phase-04.md](phase-04.md) | 4 | Baseline Forecasting Suite Benchmark |
| [phase-04-5.md](phase-04-5.md) | 4.5 | Comprehensive Forensic Audit (SparseRSSM) |
| [phase-05.md](phase-05.md) | 5 | SparseRSSM Multi-Horizon Benchmark (PRE-BUG) |
| [phase-05-5.md](phase-05-5.md) | 5.5 | Forensic Audit, Correction & Stabilization |
| [phase-06.md](phase-06.md) | 6 | Pre-Attack Onset Forecasting & Early Warning |
| [phase-07.md](phase-07.md) | 7 | Operational Early-Warning Optimization & Behavioral Attribution |

## Branch Status

| Branch | Status | Notes |
|--------|--------|-------|
| `features/data_pipeline` | **AUTHORITATIVE** | Phases 5.5 → 7 committed |
| `features/llm_pipeline` | Historical | Contains Phase 4.5 audit reports only (commit `6d20a8e`). Does NOT contain Phase 6 or 7 work. Safe to preserve, do not merge. |
| `features/lakshay_ml` | Legacy | Earlier ML experiments |
| `feature/data-pipeline` | Legacy | Older branch variant |
| `feature/world-model-dataset-darpaWithCICIDS` | Legacy | Phase 1 DARPA+CIC work |
| `main` | Historical baseline | Initial commit only |

## Critical Scientific Caveats (Do Not Override)

1. **MITRE attribution is heuristic/deterministic** — it is NOT a trained MITRE classifier.
2. **Persistence baseline achieves F1≈1.0 on continuation task** — this is a known dataset artifact (multi-hour attack episodes), NOT a model capability.
3. **Phase 6 multi-seed discrepancy:** Phase 6 CSV (`authoritative_onset_results.csv`) reports all seeds achieving 100% event recall. Phase 7 re-evaluation (`09_multiseed_results.csv`) shows seed 123 achieves only 71.43% (5/7) under the same raw threshold protocol. The Phase 7 numbers reflect independent re-runs with the same model weights from a different evaluation harness. **The authoritative seed-42 result (100% recall, 7/7) is confirmed by both phases.**
4. **Phase 5 verdict (`16_phase_5_final_verdict.md`) is SUPERSEDED** by Phase 5.5, which identified the K_train/K_eval mismatch and untrained attack head bugs.
5. **FPR-constrained operating points (fpr_le_02/05/10)** all collapse to threshold=0.99 → zero recall. The operationally useful operating point is the 10s cooldown aggregator (100% recall, 229 FA/hr).
