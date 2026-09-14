# Complete Research Flow & Scientific Decisions

## SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**The End-to-End Methodological Progression from Problem Inception to Model Handoff**

---

```
Problem Inception: Can AI forecast network attacks BEFORE they occur?
    ↓
Dataset Selection: Evaluated DARPA, CIC-IDS2017, and CSE-CIC-IDS2018
    ↓ (Discovered domain mismatch in multi-dataset stitching)
Canonical Pipeline: Standardized on CSE-CIC-IDS2018 (8.28M flows, 9 capture days)
    ↓ (Recognized that per-flow records lack temporal momentum)
Temporal State Formulation: 54-D behavioral state representation (10s window, 2s stride)
    ↓ (Audited feature lineage; verified zero temporal leakage)
Baseline Evaluation: Majority, Persistence, Logistic Regression, Random Forest, GRU, Transformer
    ↓ (Discovered the Persistence Paradox: F1=0.9996 on continuation, but 0.0% on early warning)
World Model Inception: Recurrent State Space Model (SparseRSSM) for physical rollout
    ↓ (Audit revealed untrained attack head & K_train/K_eval mismatch in Phase 5)
Forensic Correction (Phase 5.5): Enforced K_train = K_eval, restored BCE gradients, val-only thresholding
    ↓ (Discovered continuation positives mask early warning capability)
Pure-Benign Onset Formulation (Phase 6): Strict pure-benign history filter (max y_{t-9:t} = 0)
    ↓ (Precursor weighting E602 10x achieved 100% event recall on 7 OOD test episodes with 20s lead time)
Operational Noise Challenge: Raw threshold produced 1,101.3 False Alarms / hour
    ↓ (Hard negative mining showed 70% of false alarms stem from NetBIOS/mDNS and TCP resets)
Operational Alert Aggregation (Phase 7): 10s cooldown cut noise by 79% (229 FA/hr) while retaining 100% recall
    ↓ (Black-box alert probabilities insufficient for SOC operators)
Behavioral MITRE Attribution: Converted continuous state perturbation Delta S into MITRE technique evidence
    ↓
Model Selection & Research Freeze: E602 10x precursor champion frozen at commit d2c7da5
    ↓
Production Packaging: deployment/ and models/final/ standalone inference engine verified
```

---

## Detailed Progression Stages

### Stage 1: The Core Research Inception
The project was initiated under SIH26153 to move network security from reactive attack detection (identifying malicious packets after an exploit is already active) to proactive attack forecasting (learning temporal precursor dynamics in macro-behavioral telemetry before attack packets are transmitted).

### Stage 2: Dataset Selection & Forensic Ingestion
Early experiments (Phase 1) attempted to merge legacy DARPA (1999) with CIC-IDS2017. Forensic audit revealed severe timestamp distortions, synthetic artifacts, and incompatible feature sets. The research pivoted decisively to the Canadian Institute for Cybersecurity's CSE-CIC-IDS2018 dataset, comprising 8.28 million real network flows captured across a 9-day enterprise simulation.

### Stage 3: The 54-Dimensional Continuous State Space
Flow-level telemetry is noisy, discrete, and temporally irregular. To establish a stationary, physically grounded state representation, flows were aggregated into rolling 10-second temporal windows with a 2-second stride. 37 base features were constructed across 8 domain clusters (Volume, Velocity, Protocol, Port Entropy, TCP Flags, Directional Asymmetry, Packet Lengths, and IAT Jitter), augmented by 17 first-order delta features $\Delta S_t = S_t - S_{t-1}$. A comprehensive forensic audit confirmed that StandardScaler fitting was performed strictly on training days with zero temporal lookahead leakage.

### Stage 4: Baselines & The Persistence Paradox
Benchmarking standard classifiers across horizons $K \in \{1, 10, 50\}$ revealed a fundamental evaluation pitfall: Persistence ($y_{t+K} = y_t$) achieved near-perfect window $F_1 = 0.9996$. Forensic investigation revealed that attack sessions in CIC-IDS2018 last 500 to 720 minutes; out of 64,608 test windows, there were 18,867 continuation positives but only 7 attack onsets. Persistence trivially achieved high scores by repeating active labels during ongoing attacks, but collapsed to **0.00% recall on genuine attack onsets**.

### Stage 5: The Recurrent State Space Model (SparseRSSM)
To capture true temporal dynamics, a Recurrent State-Space Model (`SparseRSSM`) was engineered. SparseRSSM combines an MLP encoder, an internal 128-D latent state, a `GRUCell` recurrent memory, a transition network that rolls out continuous latent states autoregressively, a physical state decoder, and a discrete attack forecasting head.

### Stage 6: Forensic Audit & Phase 5.5 Correction
A line-by-line code audit (Phase 4.5) uncovered three critical historical bugs:
1. `SparseRSSM.loss()` omitted the binary cross-entropy loss for the attack head, leaving it completely untrained (gradient norm = 0.0000).
2. The training loop had an implicit rollout cap of $K=10$, causing extreme extrapolation errors when evaluating at $K=50$ or $K=100$.
3. Decision thresholds had been tuned across test data.

Phase 5.5 corrected all three bugs: enforced $K_{\text{train}} = K_{\text{eval}}$, restored BCE gradient backpropagation, calibrated thresholds strictly on validation data, and established verified benchmarks.

### Stage 7: Pure-Benign History Reformulation (Phase 6)
To eliminate the continuation bias, Phase 6 reformulated the forecasting task to require a **strict pure-benign history**: only sequences where all 10 history windows contain strictly 0 attack flows ($\max y_{t-9:t} = 0$) were admitted. This isolated the 7 true physical attack onsets in the test set (4 Infiltration episodes, 3 Botnet episodes—all 100% out-of-distribution).

Controlled experiments with exponential precursor loss weighting ($w_i = 1 + (M - 1)e^{-\Delta t / \tau}$) established that $10\times$ precursor weighting with $\tau=60\text{s}$ achieved **100.0% event recall (7/7 test episodes detected)** with a full **20.0-second median advance warning lead time**.

### Stage 8: Operational Alert Aggregation (Phase 7)
While Phase 6 achieved 100% event recall, raw thresholding produced 1,101.3 False Alarms / hour. Hard-negative mining of 27,721 false positive windows revealed that 70% of false alarms stemmed from benign multi-port administrative broadcasts (mDNS/NetBIOS) and legitimate TCP reset spikes.

Phase 7 resolved this operational bottleneck through temporal alert aggregation without retraining:
- **Tier 1 (10s Alert Cooldown):** Retains **100.0% event recall (7/7)** while reducing false alarms by **79.1%** (down to **229.02 FA/hr**), preserving a **14.0s median lead time**.
- **Tier 3 (60s Alert Cooldown):** Cuts false alarms by **96.4%** (down to **39.89 FA/hr**, FPR = 2.22%) while preserving **57.14% event recall**.

### Stage 9: Behavioral Attribution & Final Handoff
To make alerts actionable for SOC analysts, an evidence-based behavioral attribution layer was created to map the forecasted continuous state perturbation $\Delta S = \hat{S}_{t+10} - S_t$ to candidate MITRE ATT&CK techniques (T1046, T1110, T1498, T1071, T1190).

The final champion model weights (`artifacts/phase7/model.pt`), scaler, schemas, and standalone inference engine were packaged into `deployment/` and `models/final/`, fully verified via end-to-end smoke testing, and frozen at commit `922d3e6`.
