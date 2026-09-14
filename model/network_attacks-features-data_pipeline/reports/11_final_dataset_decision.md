# 11 — Final Dataset Readiness Decision & Reconstruction Roadmap
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Final Dataset Readiness Decision

### EXACT STATUS:
# **STATUS G: CURRENT DATASET SHOULD NOT BE USED AS THE PRIMARY TRAINING DATASET**

---

## 2. Scientific & Empirical Justification

1. **Destruction of Temporal Continuity**: The CIC-IDS2017 flow dataset was randomly shuffled during preprocessing (`src/cic_feature_adapter.py`), destroying all temporal ordering. Sequences fed into the LSTM world model were synthetic random permutations.
2. **Artificial Feature Corruption**: 18 out of 47 features were hardcoded to constant values for the CIC data, making multi-domain learning an exercise in dataset fingerprinting rather than attack dynamics forecasting.
3. **Obsolete DARPA Environment**: DARPA 1998 represents a 28-year-old simulated SunOS network with 0.18% attack prevalence and obsolete exploits (`fdformat`, `loadmodule`), incapable of generalizing to modern cloud/enterprise networks.
4. **Silent Label Mislabling**: 2,180 web attack flows were mislabeled as Benign Baseline traffic due to a Unicode encoding mismatch in `cic_mapping.py`.

---

## 3. Canonical Dataset Architecture & Transition Plan

To build a research-grade temporal attack forecasting system:
1. **Primary Benchmark**: Adopt **NF-CSE-CIC-IDS2018-v2** (Sarhan et al., University of Queensland) or the full **CSE-CIC-IDS2018** official dataset.
2. **Temporal State Construction ($S_t$)**: Group continuous flows into discrete chronological time windows ($\Delta t = 5	ext{s}, 10	ext{s}, 30	ext{s}$).
3. **Sequential Modeling**: Form true sliding trajectories $[S_{t-9}, \dots, S_t]$ to forecast future state $S_{t+K}$ and attack progression timelines.
4. **Two-Layer Decoupled MITRE Interpretation**:
   * Layer 1: Neural World Model predicts continuous network dynamics $S_{t+K}$.
   * Layer 2: Rule-based / probabilistic interpreter maps predicted anomalous behavior to MITRE ATT&CK techniques (T1046, T1110, T1498, T1190).
