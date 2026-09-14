# 14 — Persistence Forensics & The "Persistence Paradox"

## 1. Mathematical Transition Probabilities

Analysis of 64,785 test windows across Days 7–9:

$$\mathbb{P}(Y_{t+1} = 1 \mid Y_t = 1) = \mathbf{99.96\%}$$
$$\mathbb{P}(Y_{t+1} = 0 \mid Y_t = 0) = \mathbf{99.98\%}$$

The transition probability from benign to attack at any single 2-second step is only:
$$\mathbb{P}(Y_{t+1} = 1 \mid Y_t = 0) = \mathbf{0.015\%}$$

## 2. Attack Episode Durations

| Session Date | Attack Family | Active Attack Duration (min) | Total Attack Windows | Number of Attack Onsets | Mean Attack Run Length |
|---|---|---|---|---|---|
| **28-02-2018** | Infiltration Day 1 | **623.0 min** | 3,998 | 2 | 1,999 windows |
| **01-03-2018** | Infiltration Day 2 | **535.0 min** | 4,658 | 2 | 2,329 windows |
| **02-03-2018** | Botnet ARES C2 | **720.0 min** | 10,218 | 3 | 3,406 windows |
| **Total Test** | Infiltration + Botnet | **1,878.0 min** | **18,874** | **7** | **2,696 windows** |

## 3. Root Cause of the "Persistence Paradox"

In the test set of 64,785 windows, there are 18,874 attack-positive windows. However, there are **only 7 genuine attack onset events** across the entire 3 days! The remaining 18,867 positive windows are **continuation positives** (an attack that was already active at step $t$ remains active at $t+K$).

Consequently:
- A naive persistence forecaster ($y_{t+K} = y_t$) achieves an apparent F1 of **0.9996** at $K=1$ and **0.9186** at $K=300$ purely by exploiting episode continuation.
- Standard episode-averaged metrics confound **attack state continuation** with **genuine early warning**.
