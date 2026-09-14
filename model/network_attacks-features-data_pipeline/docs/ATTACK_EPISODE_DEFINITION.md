# Attack Episode and Onset Definition Specification

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Authoritative Operational & Mathematical Definitions**

---

## 1. Context & Motivation

In network traffic analysis, evaluating model performance by treating individual 10-second windows as independent events causes severe statistical distortion. A single persistent attack (e.g., a Botnet active for 12 hours) generates thousands of contiguous attack windows. Evaluating raw window counts allows a model to achieve high $F_1$ scores purely by recognizing ongoing attacks (the *Persistence Paradox*).

To evaluate true **proactive attack forecasting**, the unit of independence must be the **Attack Episode** and its **Attack Onset**.

---

## 2. Mathematical & Operational Definitions

### Definition 1: Temporal Network State Window ($S_t$)
A vector $S_t \in \mathbb{R}^{54}$ representing the macro-behavioral telemetry of all network flows occurring in the time interval $[t \cdot \Delta t, t \cdot \Delta t + W]$, where $W = 10.0$ seconds is the window duration and $\Delta t = 2.0$ seconds is the step stride.

### Definition 2: Attack Window Indicator ($y_t$)
A binary ground-truth indicator:
$$y_t = \begin{cases} 1 & \text{if any malicious flow exists in window } t \\ 0 & \text{if all flows in window } t \text{ are strictly benign} \end{cases}$$

### Definition 3: Attack Episode ($\mathcal{E}_j$)
An **Attack Episode** $\mathcal{E}_j = [t_{\text{start}}^{(j)}, t_{\text{end}}^{(j)}]$ is a maximal contiguous interval of attack windows:
$$y_t = 1 \quad \forall t \in [t_{\text{start}}^{(j)}, t_{\text{end}}^{(j)}]$$
such that $y_{t_{\text{start}}^{(j)}-1} = 0$ and $y_{t_{\text{end}}^{(j)}+1} = 0$.

- **Episode Duration:** $D_j = (t_{\text{end}}^{(j)} - t_{\text{start}}^{(j)} + 1) \times \Delta t$ seconds.
- **Preceding Benign Gap:** The number of contiguous benign windows immediately preceding $t_{\text{start}}^{(j)}$:
  $$G_j = \min \{ g \mid y_{t_{\text{start}}^{(j)} - g - 1} = 1 \} \quad (\text{or start of capture day})$$

### Definition 4: Attack Onset Event ($\mathcal{O}_j$)
The **Attack Onset** is the exact starting timestamp/window of an attack episode:
$$\mathcal{O}_j = t_{\text{start}}^{(j)}$$

### Definition 5: Isolated Attack Onset (Pure-Benign Precursor Eligible)
An attack onset is classified as **Isolated** if it is preceded by at least $P = 10$ consecutive benign windows ($G_j \ge 10$ windows $\equiv 20.0$ seconds of pure-benign history):
$$\text{IsIsolated}(\mathcal{O}_j) \iff \left(\max_{i \in [1, P]} y_{t_{\text{start}}^{(j)} - i} = 0\right)$$

---

## 3. Dataset-Wide Episode Inventory (CSE-CIC-IDS2018)

From the full 9-day capture analysis (`data/episodes/attack_episodes.csv`):

| Attack Family | Specific Attack Types Included | Total Independent Episodes | Isolated Onsets ($G \ge 20\text{s}$) | Mean Episode Duration |
|---|---|---|---|---|
| **Web Attack** | Brute Force - Web, Brute Force - XSS, SQL Injection | 318 | 257 | 0.22 minutes (13.3s) |
| **DDoS** | DDoS LOIC-UDP, DDoS HOIC | 37 | 18 | 1.25 minutes (75.1s) |
| **DoS** | GoldenEye, SlowHTTPTest, Hulk, Slowloris | 7 | 7 | 15.18 minutes (910.8s)|
| **Botnet** | Ares C2 Botnet Check-in & Traffic | 4 | 3 | 85.15 minutes (5,109s) |
| **Infiltration** | Dropbox Exploit, Portscan, Buffer Overflow | 4 | 4 | 72.13 minutes (4,328s) |
| **Brute Force** | FTP-BruteForce, SSH-Bruteforce | 3 | 3 | 62.74 minutes (3,764s) |
| **TOTAL** | **Complete CSE-CIC-IDS2018 Attack Taxonomy** | **373 Episodes** | **292 Isolated Onsets** | — |

---

## 4. Evaluation Protocol on Episodes & Onsets

For any forecasting model evaluated with lookback history $P=10$ and forecast horizon $K=10$:
1. **True Positive Event Detection:** An episode $\mathcal{E}_j$ is **Detected** if the model emits an operational alert at any anchor window $t$ in the advance warning window:
   $$t_{\text{start}}^{(j)} - K \le t < t_{\text{start}}^{(j)}$$
2. **Advance Lead Time:**
   $$\text{LeadTime}_j = (t_{\text{start}}^{(j)} - t_{\text{earliest\_alert}}) \times \Delta t \in (0\text{s}, 20\text{s}]$$
3. **Event Recall:**
   $$\text{EventRecall} = \frac{\sum_{j=1}^N \mathbb{I}(\mathcal{E}_j \text{ is Detected})}{N}$$
