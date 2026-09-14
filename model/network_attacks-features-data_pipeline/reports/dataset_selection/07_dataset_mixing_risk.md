# 07 — Dataset Mixing Risk Analysis & Domain Adaptation
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. The Core Scientific Risk: Dataset Fingerprinting

When two heterogeneous network datasets (e.g., DARPA 1998 + CIC-IDS2017, or CIC-IDS2017 + CSE-CIC-IDS2018) are concatenated into a single training set:

$$X = [X_{\text{Dataset 1}}; X_{\text{Dataset 2}}]$$

The machine learning model minimizes loss by finding the most mathematically efficient decision boundary. In network security, **it is almost always easier for a model to classify the dataset capture environment than to learn true attack mechanics**.

### Mechanisms of Artificial Shortcut Learning:
1. **Network Topology Fingerprints**: 
   * CIC-IDS2017 internal IP subnet: `192.168.10.0/24`.
   * CSE-CIC-IDS2018 internal IP subnet: `172.31.0.0/16`.
   * If subnet features leak or correlate with attack classes, the model memorizes subnets.
2. **Feature Drift & Constant Imputations**:
   * As proved in our audit, forcing CIC-IDS2017 into the DARPA schema resulted in 18 constant features. The model trivially separated DARPA from CIC with 100% accuracy based on `ttl_mean == 64.0` alone.
3. **Background Traffic Dynamics**:
   * Average packet rates and connection durations differ drastically between simulated 1998 testbeds and 2018 AWS testbeds.
4. **CICFlowMeter Version Discrepancies**:
   * `CICFlowMeter-V1` (used in 2017) had different flow timeout heuristics and header length calculations than `CICFlowMeter-V3` (used in 2018).

---

## 2. Definitive Policy on Dataset Merging

### Scientific Rule:
**DO NOT CONCATENATE DISPARATE DATASETS INTO A SINGLE PRIMARY TRAINING DISTRIBUTION.**

### Recommended Two-Dataset Architecture:
Instead of mixing, we enforce a strict **Domain Adaptation / Generalization Framework**:

```
┌────────────────────────────────────────────────────────┐
│             PRIMARY TRAINING & VALIDATION              │
│                 CSE-CIC-IDS2018 (Canonical)            │
│   - Multi-day continuous chronological training        │
│   - Learns internal network dynamics and state rollout │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             EXTERNAL GENERALIZATION BENCHMARK          │
│               Cleaned CIC-IDS-2017 (Kaggle)            │
│   - Completely isolated out-of-domain evaluation       │
│   - Tests whether forecasted attack signatures hold on │
│     an unseen enterprise network topology              │
└────────────────────────────────────────────────────────┘
```
