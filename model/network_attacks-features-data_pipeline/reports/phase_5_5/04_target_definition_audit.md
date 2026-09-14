# Target Definition & Persistence Forensics Audit
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Phase:** 5.5 | **Date:** 2026-09-08

---

### 1. Mathematical Target Formulation
Let sequence of observed 54-dimensional physical network states up to anchor time $t$ be:
$$X_t = [S_{t-9}, S_{t-8}, \dots, S_t] \in \mathbb{R}^{10 \times 54}$$

For a forecasting lead horizon $K$ (where each step represents $\Delta t = 2.0$ seconds):
1. **Future Continuous State Target:** $S_{t+K} \in \mathbb{R}^{54}$
2. **Future Binary Attack Indicator Target:** $y_{t+K} \in \{0, 1\}$
   - $y_{t+K} = 1$ if ANY flow in temporal window $[(t+K)\Delta t, (t+K)\Delta t + 10.0\text{s}]$ belongs to an attack class.
   - $y_{t+K} = 0$ if the window is purely benign.

### 2. Continuation vs. Genuine Onset Delineation
A critical finding of this audit is distinguishing two distinct operational tasks:

#### Task A: Future Attack State Forecasting (Continuation-Dominated)
Evaluates whether $P(\hat{y}_{t+K} = 1) \ge \tau$ matches $y_{t+K} = 1$ across **all** test samples ($N=64,608$), regardless of whether an attack is already in progress at anchor time $t$.

Because attacks in CSE-CIC-IDS2018 (e.g., Botnet, DoS) persist across hundreds or thousands of consecutive 2-second windows:
- $P(y_{t+K}=1 \mid y_t=1) \approx 98.6\% - 99.9\%$
- The trivial Persistence forecaster ($\hat{y}_{t+K} = y_t$) achieves $F_1 = 0.986 - 0.999$.
- **High continuation $F_1$ is not evidence of predictive forecasting; it is largely an artifact of attack duration autocorrelation.**

#### Task B: Pre-Onset Early Warning Forecasting (Genuine Transition)
Evaluates whether the model provides advance warning **before an attack starts**.
- **Eligible Anchor Subset:** Pure-benign lookback sequences where **all** 10 history windows are benign:
  $$y_{t-9} = 0, y_{t-8} = 0, \dots, y_t = 0$$
- **Onset Target:** Does an attack commence within the lookahead window $H$?
  $$y_{\text{onset}}^{(H)} = \max_{1 \le k \le H/\Delta t} y_{t+k}$$
- **Persistence Baseline Performance on Onset:** $F_1 = \mathbf{0.0000}$, Recall = $\mathbf{0.00\%}$, since $y_t = 0 \implies \hat{y} = 0$.

### 3. Empirical Test Set Transition Probabilities (Measured)

| Horizon $K$ | Lead Time | $P(y_{t+K}=1 \mid y_t=1)$ | $P(y_{t+K}=1 \mid y_t=0)$ | Genuine Onset Samples | Continuation Samples | Benign Persistence Samples |
|---|---|---|---|---|---|---|
| $K=1$ | 2.0s | **0.9996** | 0.0002 | 7 | 18,866 | 45,902 |
| $K=5$ | 10.0s | **0.9981** | 0.0008 | 35 | 18,834 | 45,866 |
| $K=10$ | 20.0s | **0.9966** | 0.0014 | 65 | 18,799 | 45,826 |
| $K=25$ | 50.0s | **0.9928** | 0.0030 | 136 | 18,713 | 45,725 |
| $K=50$ | 100.0s | **0.9861** | 0.0057 | 261 | 18,563 | 45,550 |
| $K=150$ | 300.0s | **0.9594** | 0.0167 | 761 | 17,963 | 44,850 |

### 4. Methodological Conclusion
In a dataset with 64,608 test sequences, there are only **7 genuine onset transitions** at 2-second lead time and **65 transitions** at 20-second lead time.
Any report claiming high general attack recall without isolating pre-onset performance is measuring attack continuation rather than attack anticipation.
