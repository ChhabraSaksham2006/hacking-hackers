# Phase 4.5 Forensic Audit: Report 14 — Attack Onset Operational Formulations & Dynamics

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Operational Definitions of Attack Onset

We establish three hierarchical operational definitions for network attack onsets:

### Definition A: Micro-Window State Transition (1-Step Onset)
$$\text{Onset}_A(t) = \mathbb{I}(y_t = 0 \land y_{t+1} = 1)$$
An onset occurs at the exact 2-second boundary where the network macro-state transitions from containing zero malicious flows to containing $\ge 1$ malicious flows.

### Definition B: Pure-History Episode Onset (Forecasting Window)
$$\text{Onset}_B(t, P) = \mathbb{I}\left(\left(\sum_{i=0}^{P-1} y_{t-i} = 0\right) \land y_{t+K} = 1\right)$$
An onset occurs when the entire historical lookback sequence ($P=10$ windows = 28 seconds) is purely benign, and an attack arrives within the forecast horizon $K$.

### Definition C: Sustained Attack Onset
$$\text{Onset}_C(t, P, M) = \mathbb{I}\left(\left(\sum_{i=0}^{P-1} y_{t-i} = 0\right) \land \left(\sum_{j=1}^{M} y_{t+j} = M\right)\right)$$
Filters out 1-window transient noise by requiring the attack to sustain for at least $M=5$ consecutive windows (10 seconds).

## 2. Onset Event Count Across Partitions

| Partition | Captures | Total Windows | Total Attack Windows | Definition A Onsets | Definition B Onsets ($K=1$) | Definition B Onsets ($K=10$) |
|---|---|---|---|---|---|---|
| Train (5 Days) | 5 | 102,140 | 11,038 (10.81%) | 171 | 171 | 1,100 |
| Val (1 Day) | 1 | 21,595 | 1,289 (5.97%) | 194 | 140 | 694 |
| Test (3 Days) | 3 | 64,785 | 18,874 (29.13%) | 7 | 7 | 52 |
| **Total Dataset** | **9** | **188,520** | **31,201 (16.55%)** | **372** | **318** | **1,846** |

## 3. Lead Time and Temporal Capture Resolution

Across all 14 empirical attack campaigns in CSE-CIC-IDS2018, the sliding 10s window with 2s stride captured the very first attack packet with a temporal quantization delay of **$0.00\text{s} \le \Delta t \le 2.00\text{s}$**, confirming 100% temporal coverage without blind spots.
