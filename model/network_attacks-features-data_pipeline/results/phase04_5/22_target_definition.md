# Phase 4.5 Forensic Audit: Report 22 — Exact Mathematical Target Formulations

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Mathematical Notation and Definitions

- **Continuous Macro-State Vector $S_t \in \mathbb{R}^{54}$:**
  $$S_t = \phi(\mathcal{F}[t \cdot \text{stride}, t \cdot \text{stride} + W])$$ where $W = 10.0\text{s}$, $\text{stride} = 2.0\text{s}$.

- **Lookback Sequence Matrix $X_t \in \mathbb{R}^{P \times D}$:**
  $$X_t = [S_{t-P+1}, S_{t-P+2}, \dots, S_t], \quad P = 10 \text{ steps (28.0s historical context)}.$$

- **Future Continuous State Target $S_{t+K} \in \mathbb{R}^D$:**
  State vector at future window anchor $t+K$, for $K \in \{1, 3, 5, 10\}$ (corresponding to lead times of $+2\text{s}, +6\text{s}, +10\text{s}, +20\text{s}$).

- **Binary Future Attack Presence Target $y_{t+K} \in \{0, 1\}$:**
  $$y_{t+K} = \mathbb{I}(\text{count of non-benign flows in window } t+K > 0)$$

- **Attack Family Target $c_{t+K} \in \{0, 1, \dots, 6\}$:**
  $$c_{t+K} = \text{argmax}_{c} (\text{flow count of family } c \text{ in window } t+K)$$

- **Time-to-Attack-Onset Target $\tau_t \in [0, 300.0\text{s}]$:**
  $$\tau_t = \min\left(300.0, \min_{j \ge 0} \{j \cdot \text{stride} \mid y_{t+j} = 1\}\right)$$
  If $y_t = 1$, $\tau_t = 0.0\text{s}$. If no attack occurs in the remaining session, $\tau_t = 300.0\text{s}$ (censored upper bound).

## 2. Consequences of Binary Presence Target $y_{t+K}$

Because $y_{t+K}$ measures whether *any* attack flow exists in window $t+K$, it evaluates **attack presence**, which is continuation-dominated when attacks last thousands of seconds. For the upcoming RSSM, multi-task heads for continuous state $S_{t+K}$, onset probability, and $\tau$ will disentangle continuation from early warning.
