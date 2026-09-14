# World Model Forensic Research Audit

Audit scope: existing source code, existing data construction, existing checkpoints, saved probabilities, logs, and reports. No training, fine-tuning, checkpoint generation, dataset modification, or model/training-code modification was performed. The only new artifacts are this report and `WORLD_MODEL_FORENSIC_RESULTS.csv`.

## 1. Executive summary

The current Dense RSSM results do **not** establish that the RSSM learned a useful long-horizon attack predictor.

The recursive state rollout itself is present and the state targets used during RSSM training are distinct (`x[t+1]` through `x[t+K]`). However, the reported RSSM attack metrics are not valid evidence of learned attack forecasting because the attack head is never included in the training loss. `SparseRSSM.loss()` contains only reconstruction MSE and future-state MSE; it omits attack loss and stage loss. The attack logits used for F1/precision/recall/FPR therefore come from an untrained randomly initialized head.

The flat RSSM F1 is consequently unsurprising. The saved predictions are aggressively positive: 71.65% to 76.01% of test samples are predicted as attacks at threshold 0.5, while the true attack prevalence is approximately 29.1%. RSSM recall is near one, but FPR is 63.6%–66.2%. This is high recall from an aggressive/near-constant attack predictor, not demonstrated early-warning forecasting.

There is a second major comparison problem: each RSSM K run constructs a different number of samples because `run_sparse_rssm.py` truncates each day using `max_horizon=K`. The final LR/RF benchmark constructs all horizons with a fixed maximum horizon of 300. RSSM K=1 has 64,755 test samples, RSSM K=300 has 63,858, while the baselines use 63,858 for every selected K. Thus the comparisons are not exactly on the same test rows except at K=300.

The data pipeline has several positive properties: chronological day-level split, train-only scaling, no obvious label-derived state features, no cross-day windows, and correct causal state aggregation. But the 80% overlapping windows create very strong within-day temporal dependence, and test attacks are long contiguous episodes. The existing persistence baseline is therefore extremely strong: F1 is 0.9996 at K=1 and remains 0.9186 at K=300 on the current test construction. RSSM is far below persistence at every audited K.

**Verdict: the continuous state rollout implementation is structurally recursive, but the published RSSM attack results are not scientifically valid as evidence of a trained attack head or robust long-horizon attack prediction.**

## 2. Repository and architecture findings

Primary files inspected:

- `src/models/sparse_rssm.py`
- `scripts/experiments/run_sparse_rssm.py`
- `scripts/experiments/run_final_long_horizon_benchmark.py`
- `src/temporal/dataset_builder.py`
- `src/temporal/state_aggregator.py`
- `scripts/experiments/run_baseline_suite.py`
- `src/evaluation/metrics.py`
- `src/models/baselines/persistence.py`
- `results_final_selected_k/`
- existing `reports/temporal_audit/` and `reports/phase_4_5/` artifacts

The RSSM has the requested basic structural pieces:

- 54-D input and decoder output assertions.
- MLP encoder.
- Dense latent `z`.
- One shared `state_decoder` used for reconstruction and future states.
- Optional attention module.
- Straight-through Top-K module.
- GRUCell memory.
- MLP transition.
- Recursive state rollout.

The rollout loop is genuinely recursive: after each transition it decodes the new dense latent, sparsifies that new latent, updates the hidden state, and uses the updated representation for the next transition. K therefore changes the number of recursive state steps executed.

Important omissions in the training objective:

```python
total = mse(out['x_recon'], x)
state_losses = [mse(p, y) for p, y in zip(out['states'], targets)]
total = total + sum(state_losses)
```

There is no attack cross-entropy/BCE term, no stage loss, and no transition latent loss. The attack and stage heads are therefore not trained by this runner. The user-visible attack metrics are computed from an untrained attack head.

## 3. Data and sequence findings

### Split and scaling

The split is chronological by daily capture:

- Train: 14, 15, 16, 21, 22 February.
- Validation: 23 February.
- Test: 28 February, 1 March, 2 March.

The `TemporalSequenceBuilder` fits `StandardScaler` only on training data and applies it to validation/test. This is a positive finding.

### Window construction

The state aggregator uses 10-second windows with 2-second stride, producing 80% overlap. The RSSM consumes 10 state vectors (`t-9` through `t`). The windows are constructed independently per daily file, preventing cross-day sequences in the inspected runners.

Overlap is not itself leakage, but it creates high autocorrelation and many highly related samples. Existing project audit artifacts report lag-1 byte-rate autocorrelation around 0.899 for the 2-second stride. Raw duplicate flow rows are retained by design; this is a data characteristic, not evidence of train/test leakage.

### Feature lineage

The 54 state features are continuous flow aggregates and first-order deltas. `is_attack`, `attack_fraction`, family fields, and target fields are separate columns and are not in `STATE_FEATURE_NAMES`. The inspected aggregator computes deltas from the current and previous state and resets the first delta at each daily session. No direct label-derived feature was found in the 54-D model input.

### RSSM/baseline sample mismatch

This is a serious experimental-control problem. `run_sparse_rssm.py` calls `load_data(..., max_h=k)` separately for each K. Consequently, each K drops a different number of terminal windows. The saved RSSM test-array sizes are:

| RSSM K | Test samples |
|---:|---:|
| 1 | 64,755 |
| 100 | 64,458 |
| 200 | 64,158 |
| 250 | 64,008 |
| 300 | 63,858 |

The final baseline runner builds its datasets with a fixed maximum horizon of 300, giving 63,858 test samples for every selected K. Therefore the LR/RF and RSSM comparisons are not identical-row comparisons for K=1–250.

## 4. K-step supervision audit

### Finding: distinct state targets are used in the current RSSM runner

The current training code creates:

```python
target_keys = list(range(1, k + 1))
TensorDataset(x, target_state_1, target_state_2, ..., target_state_K)
```

The batch targets are then collected in increasing horizon order and passed to `model.loss()`. `model.loss()` pairs the rollout list with the target list using `zip`. Therefore, for the current code and normal execution path:

```text
prediction 1   -> x[t+1]
prediction 2   -> x[t+2]
...
prediction K   -> x[t+K]
```

The fallback that repeats `batch[-1]` would be dangerous if target extraction failed, but it is not reached in the audited runs because the dataset contains every horizon from 1 through K and the target-list length equals K.

### Finding: K changes the recursive rollout length

`SparseRSSM.rollout()` loops `for _ in range(K)`. Each iteration performs transition, dense decoding, Top-K routing, and GRU update. This is a genuine K-step autonomous latent/state rollout, not a single endpoint prediction repeated K times.

### Important limitation

Only the state reconstruction and state rollout are supervised. Attack and stage predictions are not supervised. Thus correct state-target alignment does not rescue the reported attack metrics.

## 5. Leakage audit

### Findings that pass

- Train/validation/test days are disjoint and chronological.
- Scaling is fit only on training days.
- State features do not include the label columns.
- Daily windows do not cross daily file boundaries in the inspected runners.
- Future target labels are stored separately from the state sequence.
- Delta features use prior state values, with a reset at daily boundaries.

These findings agree with the repository's existing leakage audit, although that audit's programmatic window test covers a sample of windows rather than a formal proof over every row.

### Dependence and validity limitations

- 80% overlapping windows create strong adjacent-sample dependence.
- Attack episodes are extremely long and contiguous on the test days.
- Raw duplicate flows are retained, which can amplify repeated traffic signatures.
- The test split is an OOD attack-family split, not IID sampling.
- RSSM and baseline K runs use different terminal-window truncation, as described above.

No direct train/test feature leakage was found. The dominant threat is not feature leakage; it is temporal persistence, sample-control mismatch, and an untrained attack head.

## 6. Persistence and constant-learner audit

On the fixed 63,858-sample baseline test construction, attack prevalence is 0.290723. The verified analytical baselines are:

| Predictor | F1 | Precision | Recall | FPR |
|---|---:|---:|---:|---:|
| Always normal | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Always attack | 0.4505 | 0.2907 | 1.0000 | 1.0000 |
| Persistence K=1 | 0.9996 | 0.9996 | 0.9996 | 0.0002 |
| Persistence K=100 | 0.9725 | 0.9725 | 0.9725 | 0.0112 |
| Persistence K=200 | 0.9455 | 0.9455 | 0.9455 | 0.0228 |
| Persistence K=250 | 0.9321 | 0.9321 | 0.9321 | 0.0287 |
| Persistence K=300 | 0.9186 | 0.9186 | 0.9186 | 0.0337 |

The persistence effect is expected from long contiguous attack episodes. The existing phase-4.5 reports quantify this for shorter horizons: test attack runs last thousands of windows on infiltration and botnet days, so a 2–20 minute horizon remains inside the same attack block much of the time.

Persistence is not an onset detector. It has zero recall on pure pre-onset windows by construction. Therefore both standard continuation metrics and pre-onset metrics are required; the current RSSM artifacts do not contain a valid RSSM pre-onset evaluation.

## 7. RSSM constant-learner audit

The saved RSSM arrays were independently checked. At threshold 0.5:

| K | True attack rate | Predicted attack rate | TP | FP | FN | TN | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 29.13% | 71.65% | 18,079 | 28,320 | 785 | 17,571 | 0.5540 | 0.6171 |
| 100 | 29.11% | 75.96% | 18,765 | 30,195 | 0 | 15,498 | 0.5542 | 0.6608 |
| 200 | 29.09% | 75.50% | 18,665 | 29,774 | 0 | 15,719 | 0.5563 | 0.6545 |
| 250 | 29.08% | 76.01% | 18,594 | 30,060 | 21 | 15,333 | 0.5528 | 0.6622 |
| 300 | 29.07% | 73.74% | 18,302 | 28,784 | 263 | 16,509 | 0.5576 | 0.6355 |

The attack predictor is therefore aggressive, not constant in the literal sense but close to a high-positive-rate rule. Its F1 is only modestly above always-attack F1 (0.4505) and dramatically below persistence.

The flat F1 is best explained by:

1. The attack head is untrained.
2. The 0.5 threshold is fixed rather than validation-selected.
3. Long-horizon representations remain in a similar distribution while the head outputs a high positive rate.
4. The evaluation target is dominated by continuation labels.

It cannot be interpreted as evidence that the latent world dynamics are stable or useful.

## 8. Threshold and metric audit

### Thresholds

- RSSM uses `probability >= 0.5` directly in `run_sparse_rssm.py`.
- LR/RF choose thresholds on validation F1 using `find_optimal_threshold()` and apply them to test probabilities.
- There is no evidence that RSSM test labels were used to select its threshold; the problem is instead that RSSM and baselines use different threshold protocols.

### RSSM metric arithmetic

The RSSM code computes `confusion_matrix(..., labels=[0,1])` and FPR as:

```text
FP / (FP + TN)
```

The saved probability arrays reproduce the reported RSSM F1, precision, recall, and FPR exactly. The approximately 63%–66% FPR values are mathematically correct for the saved predictions. They are not a calculation bug; they expose the aggressive predictor.

### Baseline metric limitations

The final comparison parser reconstructs precision algebraically from F1 and recall and leaves baseline FPR blank because the per-run logs do not store confusion counts. The source baseline evaluator itself computes confusion metrics correctly, but those counts were not carried into the final comparison CSV. Baseline FPR should therefore be treated as unavailable in the final table, not as zero.

## 9. RSSM versus LR/RF and explanation of RF variability

The RSSM attack F1 is approximately 0.5528–0.5576 across K=1–300. RF varies strongly: for Static-54D, F1 is 0.2938, 0.5522, 0.3031, 0.4870, and 0.4425 at K=1,100,200,250,300. LR also varies by horizon and feature variant.

This does not prove that RF has better or worse world dynamics. LR/RF are direct discriminative models retrained separately for each K against that K's target. Their input is the current 54-D state (or flattened history for one variant); they do not perform autonomous recursive latent rollout. Their variability can reflect target distribution, feature-to-label separability, validation threshold changes, and the specific direct target at each K.

RSSM's flatness is not a meaningful contrast with RF because RSSM's attack head is not trained. Moreover, RSSM K runs do not use the same rows as the baselines at K<300. The comparisons are therefore not a fair causal test of architecture.

## 10. Answers to the audit questions

1. **Why is RSSM F1 flat?** Primarily because the attack head is excluded from the loss and produces an aggressive high-positive-rate output; continuation labels and fixed threshold further flatten the score.
2. **Is it recursively forecasting?** Yes for continuous state rollout: the code recursively feeds predicted latents through decoder, Top-K, GRU, and transition. This does not mean the attack head learned forecasting.
3. **Does K change rollout length?** Yes, `range(K)` changes the number of recursive steps.
4. **Are targets distinct?** Yes in the audited current normal execution path: `x[t+1]` through `x[t+K]` are separate tensors.
5. **Repeated endpoint target?** Not in the completed normal runs; the fallback exists but is not triggered when the expected target tensors are present.
6. **Strong temporal label persistence?** Yes. Persistence F1 is 0.9996 at K=1 and 0.9186 at K=300 on the current fixed test construction.
7. **Persistence comparison?** RSSM is far below persistence at every audited K.
8. **Aggressive/near-constant attack predictor?** Yes. Predicted positive rate is 71.65%–76.01% versus 29.1% prevalence.
9. **Predicted attack rate?** Reported above and included in the CSV.
10. **Against constants/LR/RF?** RSSM is above always-normal and always-attack F1, below persistence, and roughly comparable to RF only at selected horizons. This comparison is confounded by training-loss and sample-set issues.
11. **Leakage/overlap/features/splits?** No direct label or train/test feature leakage found; strong overlap and persistence are present; daily boundaries are respected.
12. **Threshold selection?** RSSM fixed at 0.5; LR/RF validation-selected. Not test-selected, but not protocol-matched.
13. **Metric calculations?** RSSM confusion metrics and FPR are arithmetically correct for saved predictions.
14. **FPR correctness?** Yes; the high FPR is real for the saved RSSM outputs.
15. **Fair LR/RF comparison?** No, not exactly: thresholds and K-dependent sample sets differ; model input/forecasting modes also differ.
16. **RF variability?** Direct per-K retraining, target difficulty, threshold changes, and feature relationships; not evidence of recursive dynamics.
17. **Does this support robust long-horizon RSSM attack prediction?** No.
18. **What is supported?** The code contains a recursive dense-latent state rollout and uses per-step state targets in the current training path. The saved attack results do not show a trained attack forecaster.

## 11. Strongest defensible claim

> The repository contains an RSSM-shaped model that executes autonomous recursive 54-D latent/state rollouts and is trained with distinct per-step continuous-state targets. Under the current artifacts, however, its reported attack metrics reflect an untrained attack head with a high-positive-rate decision rule, not demonstrated long-horizon attack forecasting.

## 12. Claims that should not be made

Do not claim that:

- RSSM learned a useful attack-risk head.
- RSSM provides robust long-horizon attack prediction.
- RSSM outperforms persistence.
- RSSM's flat F1 demonstrates stable world dynamics.
- RSSM detects attacks before onset.
- RSSM is fairly compared with LR/RF at K=1–250.
- The reported attack F1 proves latent state quality.

## 13. Problems ranked by severity

### Critical

1. Attack/stage heads are absent from the RSSM training loss; attack metrics are from an untrained head.
2. RSSM and baseline K runs do not use identical test sample sets for K<300.

### High

3. RSSM uses fixed threshold 0.5 while LR/RF use validation-selected thresholds.
4. No RSSM pre-onset/lead-time result is stored in the audited artifacts.
5. Final comparison CSV does not contain baseline FPR because confusion counts were not persisted.

### Medium

6. Continuous RSSM test state metrics are not saved in the final per-K metrics; only validation final-step MSE is recorded.
7. 80% overlap and long contiguous episodes make standard attack metrics dominated by continuation.
8. The defensive repeated-target fallback in the runner could silently mask future supervision errors if target extraction changes.

### Low

9. Existing report files use slightly different sample-count conventions from the selected final benchmark, so report numbers must be tied to their exact runner/configuration.

## 14. Recommended next experiments

The following are recommendations only. They were **not run** because they require training or new evaluation artifacts.

1. **REQUIRES TRAINING — NOT RUN:** Add attack BCE/cross-entropy and stage loss to the RSSM objective, train on the same chronological split, and save logits for every rollout step.
2. **REQUIRES TRAINING — NOT RUN:** Use one fixed dataset construction with `max_horizon=max(K)` for every model and every K, so test rows are identical.
3. **REQUIRES TRAINING — NOT RUN:** Match threshold policy: select every model threshold on validation only, or report threshold-free PR-AUC plus fixed-threshold metrics.
4. **REQUIRES EVALUATION ARTIFACTS — NOT RUN:** Evaluate pure pre-onset windows and report onset precision, recall, F1, false alarms, and lead time.
5. **REQUIRES TRAINING — NOT RUN:** Compare autonomous rollout against teacher-forced state forecasts using the same target rows.
6. **REQUIRES EVALUATION ARTIFACTS — NOT RUN:** Save per-step test state MAE/MSE, latent norms, hidden norms, and attack probabilities.
7. **REQUIRES TRAINING — NOT RUN:** Evaluate on non-overlapping or episode-separated windows as a sensitivity analysis.
8. **REQUIRES TRAINING — NOT RUN:** Compare against persistence and always-attack baselines on both continuation and pure-onset protocols.

## 15. Artifact index

- Verified metrics table: `WORLD_MODEL_FORENSIC_RESULTS.csv`
- Existing final comparison: `results_final_selected_k/comparison/comparison.csv`
- RSSM probabilities: `results_final_selected_k/sparse_rssm/dense/k*/test_probabilities.npz`
- RSSM metrics/checkpoints: `results_final_selected_k/sparse_rssm/dense/k*/metrics.json` and `checkpoint.pt`
- RSSM source: `src/models/sparse_rssm.py`
- RSSM runner: `scripts/experiments/run_sparse_rssm.py`
- Baseline runner: `scripts/experiments/run_baseline_suite.py`
- Persistence implementation: `src/models/baselines/persistence.py`
- Metric implementation: `src/evaluation/metrics.py`

