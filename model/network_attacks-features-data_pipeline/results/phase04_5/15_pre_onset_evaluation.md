# Phase 4.5 Forensic Audit: Report 15 — Pure Pre-Onset Forecasting Evaluation

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Pure Pre-Onset Evaluation Protocol

In this evaluation protocol, all samples where the current state or history contains any attack activity ($y_t=1$ or $y_{t-i}=1$) are filtered out. Models are evaluated **strictly** on their ability to anticipate an upcoming attack transition from purely benign network telemetry.

## 2. Pre-Onset Dataset Distribution & Imbalance Matrix

| partition         |   horizon_k |   lead_sec |   pure_benign_history_samples |   positive_onset_events |   negative_benign_events |   onset_prevalence_pct |   persistence_pred_positives |   persistence_onset_recall |   persistence_onset_precision |   persistence_onset_f1 |
|:------------------|------------:|-----------:|------------------------------:|------------------------:|-------------------------:|-----------------------:|-----------------------------:|---------------------------:|------------------------------:|-----------------------:|
| VAL               |           1 |          2 |                         18807 |                     140 |                    18667 |                 0.7444 |                            0 |                          0 |                             0 |                      0 |
| VAL               |           3 |          6 |                         18805 |                     401 |                    18404 |                 2.1324 |                            0 |                          0 |                             0 |                      0 |
| VAL               |           5 |         10 |                         18803 |                     635 |                    18168 |                 3.3771 |                            0 |                          0 |                             0 |                      0 |
| VAL               |          10 |         20 |                         18798 |                     694 |                    18104 |                 3.6919 |                            0 |                          0 |                             0 |                      0 |
| TEST_INFILTRATION |           1 |          2 |                         34478 |                       4 |                    34474 |                 0.0116 |                            0 |                          0 |                             0 |                      0 |
| TEST_INFILTRATION |           3 |          6 |                         34474 |                      12 |                    34462 |                 0.0348 |                            0 |                          0 |                             0 |                      0 |
| TEST_INFILTRATION |           5 |         10 |                         34470 |                      20 |                    34450 |                 0.058  |                            0 |                          0 |                             0 |                      0 |
| TEST_INFILTRATION |          10 |         20 |                         34460 |                      40 |                    34420 |                 0.1161 |                            0 |                          0 |                             0 |                      0 |
| TEST_BOTNET       |           1 |          2 |                         11350 |                       3 |                    11347 |                 0.0264 |                            0 |                          0 |                             0 |                      0 |
| TEST_BOTNET       |           3 |          6 |                         11350 |                       8 |                    11342 |                 0.0705 |                            0 |                          0 |                             0 |                      0 |
| TEST_BOTNET       |           5 |         10 |                         11350 |                      10 |                    11340 |                 0.0881 |                            0 |                          0 |                             0 |                      0 |
| TEST_BOTNET       |          10 |         20 |                         11350 |                      12 |                    11338 |                 0.1057 |                            0 |                          0 |                             0 |                      0 |
| TEST_ALL          |           1 |          2 |                         45828 |                       7 |                    45821 |                 0.0153 |                            0 |                          0 |                             0 |                      0 |
| TEST_ALL          |           3 |          6 |                         45824 |                      20 |                    45804 |                 0.0436 |                            0 |                          0 |                             0 |                      0 |
| TEST_ALL          |           5 |         10 |                         45820 |                      30 |                    45790 |                 0.0655 |                            0 |                          0 |                             0 |                      0 |
| TEST_ALL          |          10 |         20 |                         45810 |                      52 |                    45758 |                 0.1135 |                            0 |                          0 |                             0 |                      0 |

## 3. Baseline Pre-Onset Behavior Analysis

1. **Persistence Failure:** Persistence predicts $\hat{y}_{t+K} = y_t = 0$ for 100% of pre-onset windows. Consequently, Persistence achieves **0.00% Recall and 0.00% $F_1$** on genuine attack onsets.
2. **Extreme Class Imbalance:** In the Test partition, true positive onset events represent only **0.0153% of pre-onset windows at $K=1$** (7 out of 45,828) and **0.1135% at $K=10$** (52 out of 45,810).
3. **Supervised Model Limitations:** Because supervised discriminative baselines (Random Forest, GRU, Transformer) were trained on datasets dominated by attack continuations, their learned decision boundaries prioritize continuation signatures. Under pure pre-onset conditions, subtle pre-attack reconnaissance is frequently overshadowed by benign background variance.
4. **World-Model Motivation:** This provides empirical justification for a generative world model (RSSM) capable of modeling subtle latent trajectory shifts prior to attack onset.
