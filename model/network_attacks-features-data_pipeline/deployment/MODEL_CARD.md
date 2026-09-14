# Model Card — SIH26153 Network Attack Forecasting (Phase 7)

## Model Identity
- **Name:** SparseRSSM Early-Warning Network Attack Forecaster
- **Version:** Phase 7 (Final Research Freeze)
- **Project:** SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
- **Git Commit:** `d2c7da5`
- **Branch:** `features/data_pipeline`
- **Date:** September 2026

---

## Model Description

A Recurrent State-Space Model (RSSM) trained to forecast network attack onset from 54-dimensional behavioral state representations of network traffic, with a 20-second prediction horizon.

**Architecture:** SparseRSSM
- MLP Encoder (54→128→128-D latent)
- GRUCell (temporal memory, 128-D hidden state)
- Transition MLP (256→128-D for autoregressive rollout)
- State Decoder (128→54-D physical state reconstruction)
- Attack Head (256→1 binary onset logit per rollout step)
- Parameters: **213,820**

**Input:** 10 consecutive 2-second network behavioral state windows (10×54 = 540 normalized scalars)  
**Output:** Onset probability [0, 1] for the next 20 seconds + 54-D forecasted physical state

---

## Intended Use

### Primary Use
- Early detection of impending network attacks (Infiltration, Botnet, and potentially generalized patterns) in Security Operations Center (SOC) environments
- Integration into real-time network monitoring dashboards
- Pre-attack threat assessment with MITRE ATT&CK behavioral attribution

### Out-of-Scope Uses
- This model is NOT intended for production deployment without validation on the target network environment
- This model should NOT be used as the sole basis for automated blocking without human analyst review
- This model does NOT classify flows in real-time — it requires temporal aggregation into 2-second state windows
- Do NOT use this model's MITRE attribution as legal evidence

---

## Performance Metrics (Test Split: Feb 28 — Mar 02 2018)

### State Forecasting
| Metric | Value |
|--------|-------|
| State MAE | 0.2766 |
| State MSE | 0.6155 |

### Operational Early-Warning (Event-Level)

| Operating Tier | Event Recall | Events/7 | False Alarms/hr | FPR | Median Lead |
|---------------|-------------|---------|----------------|-----|-------------|
| **Tier 1 (10s Cooldown)** | **100.0%** | **7/7** | **229.02** | 12.74% | **14.0s** |
| Tier 2 (30s Cooldown) | 71.43% | 5/7 | 78.95 | 4.39% | 6.0s |
| Tier 3 (60s Cooldown) | 57.14% | 4/7 | **39.89** | **2.22%** | 12.0s |
| Phase 6 Raw Baseline | 100.0% | 7/7 | 1,101.27 | 61.26% | 20.0s |

### Baselines (For Context)

| Model | Event Recall | FA/hr | Median Lead |
|-------|-------------|-------|------------|
| Majority (Predict 0) | 0.0% | 0.0 | 0s |
| Logistic Regression | 42.86% | 251.48 | 6.0s |
| Random Forest | 85.71% | 688.73 | 19.0s |
| **Phase 7 SparseRSSM (Tier 1)** | **100.0%** | **229.02** | **14.0s** |

---

## Training Data

- **Dataset:** CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)
- **Training days:** Feb 14, 15, 16, 21, 22 (5 days) — includes BruteForce, DoS, DDoS, WebAttack
- **Validation day:** Feb 23 (WebAttack family)
- **Test days:** Feb 28, Mar 01, Mar 02 (Infiltration, Botnet — fully OOD)
- **Training sequences:** 89,027 pure-benign sequences
- **Class imbalance:** Train attack rate 10.8%, computed pos_weight = 8.26

---

## Evaluation Data

The model was evaluated exclusively on **out-of-distribution attack families**:
- **Infiltration** (4 onset episodes) — Scanning + exploitation patterns not seen in training
- **Botnet** (3 onset episodes) — C2 communication patterns not seen in training

This constitutes a genuinely hard generalization test.

---

## Known Limitations

1. **High false alarm rate at raw threshold:** 1,095 FA/hr without temporal aggregation — requires operational cooldown filtering for production use.

2. **Infiltration recall under aggressive aggregation:** The 2-Consecutive+60s cooldown aggregator captures only 2/7 episodes — Infiltration's short-burst signature is suppressed by the sequential consistency requirement.

3. **Multi-seed variance:** Event recall varies from 71.43% (seed 123) to 100.0% (seeds 42 and 2025) under raw threshold. Recommend seed 42 for production.

4. **FPR-constrained threshold failure:** Setting threshold=0.99 to enforce strict FPR constraints collapses recall to zero. The precursor signal strength does not support hard FPR constraints at current model scale.

5. **MITRE attribution is heuristic:** The MITRE technique attribution is a deterministic feature-delta scoring system, NOT a trained classifier. Confidence values should be treated as relative evidence weights, not calibrated probabilities.

6. **CIC-IDS2018 representativeness:** The dataset was generated in a controlled lab environment. Real network traffic may have different distributional properties.

---

## Ethical Considerations

- **False positives** may cause alert fatigue in SOC operators. Deploy with appropriate cooldown settings.
- **False negatives** may miss real attacks. Do not rely solely on this model.
- The MITRE attribution should be reviewed by a qualified security analyst before any action is taken.
- The model was trained on a specific laboratory dataset and may not generalize to all network environments.

---

## Scientific Caveats (Do Not Override in Any Publication)

> 1. The MITRE attribution is **deterministic heuristic evidence scoring**, NOT a trained MITRE classifier. Do NOT describe it as a learned classifier.
> 2. Do NOT call this **causal inference**. Feature deltas are correlational, not causal.
> 3. Do NOT use **attention weights** as causal explanations (no attention mechanism is used in this model).
> 4. The **Persistence baseline** achieves F1≈1.0 on the continuation classification task due to multi-hour attack episodes — this is a dataset artifact, not a model capability. On pre-onset transitions, Persistence achieves 0% recall.
> 5. Do NOT claim **100% event recall from seed 123** — it achieves 71.43% (5/7) under Phase 7 evaluation.
> 6. **Phase 5 results** (before the forensic correction) are INVALIDATED and should NOT be cited.

---

## Deployment Instructions

See [deployment/README.md](README.md) for full setup instructions.

**Quick Start:**
```bash
pip install -r requirements.txt
python inference.py --state-file example_input.json
```

---

## Citation

```
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon 2026, Problem Statement 26153
Repository: ArihantSrivastava2225/network_attacks
Branch: features/data_pipeline
Final Commit: d2c7da5
```
