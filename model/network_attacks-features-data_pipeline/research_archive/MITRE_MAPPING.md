# Behavioral Attribution & MITRE ATT&CK Mapping Layer

## SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Forensic Explanation Architecture: Converting State Deltas into Threat Intelligence**

---

## 1. Absolute Scientific Disclaimer

> **IMPORTANT:**  
> The behavioral attribution layer implemented in this project is a **deterministic, evidence-based heuristic scoring system**.  
> It is **NOT** a directly trained deep learning classifier.  
> It is **NOT** a causal inference engine.  
> It does **NOT** compute causal counterfactuals or use attention weights as explanations.  
> It quantitatively measures the forecasted physical telemetry shift $\Delta S = \hat{S}_{t+K} - S_t$ and scores it against established domain knowledge rules.

---

## 2. Mathematical Formulation

Let the current observed network state be $S_t \in \mathbb{R}^{54}$ and the world model's continuous autoregressive forecast $K$ steps into the future be $\hat{S}_{t+K} \in \mathbb{R}^{54}$.

The forecasted physical state perturbation vector is:
$$\Delta S = \hat{S}_{t+K} - S_t$$

We define five domain feature clusters $\mathcal{C}_k$:
1. **Volume & Rates ($\mathcal{C}_{\text{vol}}$):** `flow_count`, `total_ip_bytes`, `total_packets`, `flow_rate`, `byte_rate`, `packet_rate`, and their corresponding delta features.
2. **Port Targeting ($\mathcal{C}_{\text{port}}$):** `unique_dst_ports`, `port_concentration`, `dst_port_entropy`, `auth_port_ratio`, and their delta features.
3. **TCP Flags & Health ($\mathcal{C}_{\text{tcp}}$):** `syn_count`, `ack_count`, `rst_count`, `fin_count`, `psh_count`, `syn_ratio`, `ack_ratio`, `rst_ratio`, `rst_to_syn_ratio`, `handshake_completion_ratio`, and their delta features.
4. **Directional & Payload Asymmetry ($\mathcal{C}_{\text{payload}}$):** `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean`, `down_up_ratio_std`, `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `pkt_len_min`, `zero_payload_ratio`, and delta features.
5. **Timing Jitter & Protocol Mix ($\mathcal{C}_{\text{time}}$):** `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min`, `active_connection_lifetime_mean`, `tcp_ratio`, `udp_ratio`, `icmp_ratio`, and delta features.

For each cluster $k$, the perturbation magnitude is:
$$M_k = \frac{1}{|\mathcal{C}_k|} \sum_{i \in \mathcal{C}_k} |\Delta S_i|$$

---

## 3. Evidence Mapping Matrix to MITRE ATT&CK Techniques

| Technique ID | Technique Name | MITRE Tactic | Cluster Evidence Weights | Physical Telemetry Rationales |
|---|---|---|---|---|
| **T1046** | Network Service Scanning | Discovery (TA0007) | $0.6 \cdot M_{\text{port}} + 0.4 \cdot M_{\text{tcp}}$ | Rapid dispersion of destination ports (entropy spike), port concentration collapse, elevation in incomplete SYN attempts |
| **T1110** | Brute Force | Credential Access (TA0006) | $0.4 \cdot M_{\text{port}} + 0.3 \cdot M_{\text{tcp}} + 0.3 \cdot M_{\text{time}}$ | High concentration on authentication ports (21, 22, 3389), repeated connection teardowns (`rst_ratio`), high connection rate |
| **T1498** | Network Denial of Service | Impact (TA0040) | $0.8 \cdot M_{\text{vol}} + 0.4 \cdot M_{\text{payload}}$ | Massive velocity surges in packet/byte rates, dominance of zero-payload frames, severe directional ingress asymmetry |
| **T1071** | Application Layer Protocol | Command & Control (TA0011) | $0.7 \cdot M_{\text{time}} + 0.4 \cdot M_{\text{payload}} + 0.2 \cdot M_{\text{vol}}$ | Periodic heartbeat pacing in flow inter-arrival times (low IAT jitter), small uniform packet sizes, low-volume continuous flows |
| **T1190** | Exploit Public-Facing App | Initial Access (TA0001) | $0.3 \cdot M_{\text{tcp}} + 0.2 \cdot M_{\text{payload}}$ | Anomalous PSH flag bursts, asymmetric response byte ratios, abnormal TCP handshake transitions |

Total technique evidence scores are computed as:
$$\text{Score}(T) = \sum_{k} W_{T, k} \cdot M_k$$
Normalized technique confidence is obtained via softmax/sum normalization over candidate techniques:
$$\text{Conf}(T) = \frac{\text{Score}(T)}{\sum_{T'} \text{Score}(T')}$$

---

## 4. Empirical Attribution on Unseen Out-of-Distribution Test Episodes

From `reports/phase_7/08_behavior_to_mitre.csv` (55 pre-onset precursor windows analyzed):

### Case 1: Infiltration Episodes (Wednesday-28-02 and Thursday-01-03)
- **Observed Physical Shift:** Elevation in destination port entropy ($\Delta \text{dst\_port\_entropy} > 0.4$), accompanied by periodic pacing in flow inter-arrival times ($\Delta \text{flow\_iat\_mean}$) and drop in reset ratios.
- **Top Attributed Technique:** **T1071 (Application Layer Protocol / C2)** with **35.7% – 44.2% confidence**.
- **Secondary Technique:** **T1046 (Network Service Scanning)** with **21.4% – 27.6% confidence**.
- **Security Analyst Interpretation:** The world model detected stealthy reconnaissance and initial command-and-control beaconing 20.0 seconds before active exploitation traffic emerged.

### Case 2: Botnet Ares Episodes (Friday-02-03)
- **Observed Physical Shift:** High concentration on specific destination ports, rise in authentication port probing (`auth_port_ratio`), and sudden elevation in UDP protocol ratio.
- **Top Attributed Technique:** **T1071 (C2 Protocol)** with **31.2% – 33.2% confidence** and **T1110 (Brute Force)** with **30.2% – 32.7% confidence**.
- **Secondary Technique:** **T1498 (Denial of Service)** with **21.2% confidence**.
- **Security Analyst Interpretation:** The model detected synchronized botnet coordination, multi-endpoint check-in attempts, and credential access preparations.
