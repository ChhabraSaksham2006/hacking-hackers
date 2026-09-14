# 17 — Out-of-Distribution (OOD) & Unseen Attack Family Analysis

## 1. OOD Experimental Setup

The test split contains two distinct attack families that were never seen during training or validation:
1. **Infiltration (Days 7 & 8: 28-02-2018 & 01-03-2018):** Low-and-slow multi-stage payload execution and lateral movement.
2. **Botnet (Day 9: 02-03-2018):** ARES command-and-control beaconing and scanning.

## 2. Per-Family Forensic Metrics

From the Phase 4 baseline error analysis (`reports/baselines/10_error_analysis.md`) and per-day state logs:

| Attack Family | Test Day | Attack Prevalence | Random Forest Detection Rate | Persistence Detection Rate | Primary Failure Mode |
|---|---|---|---|---|---|
| **Infiltration (Day 1)** | 28-02-2018 | 18.51% | ~22.4% | 99.8% (continuation) | Low volumetric signature; traffic mimics background HTTP. |
| **Infiltration (Day 2)** | 01-03-2018 | 21.57% | ~19.8% | 99.7% (continuation) | Subtle port entropy shift missed by static classifiers. |
| **Botnet (ARES)** | 02-03-2018 | 47.32% | ~71.2% | 99.9% (continuation) | High-volume beaconing detected by byte rate and connection rates. |

## 3. OOD Generalization Assessment

- Supervised static models (LR, RF) trained on DoS/BruteForce fail to generalize effectively to low-volume Infiltration attacks (Recall < 25%).
- Botnet attacks exhibit stronger volumetric signatures, yielding higher detection rates (~71%).
- RSSM per-family breakdown was not logged separately in `results_final_selected_k`.
