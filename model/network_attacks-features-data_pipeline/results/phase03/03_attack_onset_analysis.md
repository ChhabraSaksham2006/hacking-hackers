# 03 — Attack Onset Dynamics & Multi-Horizon Target Formulation
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. The Forecasting Objective vs. Static Detection

Traditional IDS asks:
$$\text{Flow } x_t \longrightarrow \hat{y}_t \in \{0, 1\} \quad \text{(Is this flow malicious right now?)}$$

Temporal World Model Forecasting asks:
$$\text{Trajectory } [S_{t-9}, \dots, S_t] \longrightarrow \hat{S}_{t+K}, \; \hat{Y}_{t+K}, \; \hat{\tau}_{\text{onset}} \quad \text{(What will the network look like at } t+K \text{? When will the attack begin?)}$$

---

## 2. Multi-Horizon Target Formulation

We establish 4 complementary target representations for evaluation:

### Target 1: Continuous State Vector Forecasting ($S_{t+K} \in \mathbb{R}^{54}$)
* The primary World Model loss trains the latent dynamics to forecast the exact macro-network telemetry $S_{t+K}$ for $K \in \{1, 3, 5, 10\}$ steps ahead:
  $$\mathcal{L}_{\text{state}} = \frac{1}{54} \sum_{j=1}^{54} (S_{t+K}^{(j)} - \hat{S}_{t+K}^{(j)})^2$$

### Target 2: Multi-Horizon Attack Occurrence Binary Indicator ($Y_{t+K}^{\text{attack}} \in \{0, 1\}$)
* Predicts whether any malicious flow will be active within window $W_{t+K}$:
  $$Y_{t+K}^{\text{attack}} = \mathbb{I}\left( \sum_{f \in \mathcal{F}_{t+K}} \mathbb{I}(\text{Label}(f) \ne \text{Benign}) > 0 \right)$$

### Target 3: Future Attack Family Multi-Class Classification ($Y_{t+K}^{\text{family}} \in \{0 \dots 6\}$)
* Categorical target for dominant future attack family:
  * `0`: Benign Baseline
  * `1`: Brute Force (SSH/FTP/Web)
  * `2`: Denial of Service (Hulk/GoldenEye/Slowloris/SlowHTTPTest)
  * `3`: Distributed Denial of Service (HOIC/LOIC)
  * `4`: Web Exploits (SQLi/XSS)
  * `5`: Infiltration (Internal Recon / Lateral SMB)
  * `6`: Botnet (ARES C2 Beaconing)

### Target 4: Time-to-Next-Attack Regression ($	au_{\text{onset}} \in [0, \tau_{\max}]$)
* Continuous time remaining in seconds until the onset of the next attack transition.

---

## 3. Pilot Findings on Attack Onset Lead Times

| Attack Scenario | Earliest Measurable Pre-Attack Indicator | Observable Lead Time Before Peak Impact |
| :--- | :--- | :---: |
| **Infiltration Scenario** | Surge in Destination Port Entropy ($H(\text{Port}) > 3.8$) and failed RST connections | **15 to 45 minutes** before lateral exploitation |
| **SSH Brute Force** | Rapid sequence of low-byte TCP handshakes on Port 22 with low IAT jitter | **30 to 90 seconds** before credential exhaustion |
| **DoS Hulk** | Rapid acceleration in HTTP packet rate ($v_{\text{pkt}}$) and forward byte ratio | **10 to 30 seconds** before server saturation |
| **DDoS HOIC** | Exponential rise in SYN count and UDP/HTTP flow velocity across multiple threads | **20 to 60 seconds** before link saturation |
| **Botnet ARES** | Ultra-low IAT standard deviation (periodic keep-alive pulses every 60s) | Continuous predictive beaconing signature |
