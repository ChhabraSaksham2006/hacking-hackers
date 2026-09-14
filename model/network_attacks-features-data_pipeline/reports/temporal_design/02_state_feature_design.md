# 02 — Temporal Network State Feature Design & Mathematical Formulation
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Subsystem**: Temporal State Engineering ($S_t$)  
**Timestamp**: September 2026  

---

## 1. Mathematical Definition of Network State $S_t$

For a continuous observation timeline, let $W_t = [t \cdot s, t \cdot s + \Delta t)$ represent the temporal window at step $t$ with duration $\Delta t$ and stride $s$.

Let $\mathcal{F}_t = \{f_1, f_2, \dots, f_{N_t}\}$ be the set of network flows whose start timestamps fall strictly within $W_t$:
$$\tau(f_i) \in [t \cdot s, t \cdot s + \Delta t)$$

The **System State Vector** $S_t \in \mathbb{R}^{54}$ is a deterministic mapping $\Phi: \mathcal{F}_t 	o \mathbb{R}^{54}$ capturing 9 distinct dimensions of macro-network behavior.

---

## 2. Feature Taxonomy & Mathematical Definitions (54 Features)

### Category A: Traffic Volume & Density (Features 1–3)
1. **Flow Count ($N_t$)**: Total active flows initiated in window $W_t$.
2. **Total IP Bytes ($B_t$)**: $\sum_{i=1}^{N_t} (	ext{TotLen\_Fwd}_i + 	ext{TotLen\_Bwd}_i)$.
3. **Total Packets ($P_t$)**: $\sum_{i=1}^{N_t} (	ext{Tot\_Fwd\_Pkts}_i + 	ext{Tot\_Bwd\_Pkts}_i)$.

### Category B: Traffic Velocity & Rates (Features 4–6)
4. **Flow Velocity**: $v_{	ext{flow}} = N_t / \Delta t$ (flows/sec).
5. **Byte Velocity**: $v_{	ext{byte}} = B_t / \Delta t$ (bytes/sec).
6. **Packet Velocity**: $v_{	ext{pkt}} = P_t / \Delta t$ (packets/sec).

### Category C: Protocol Distribution (Features 7–9)
7. **TCP Ratio**: $rac{1}{N_t} \sum_{i=1}^{N_t} \mathbb{I}(	ext{Proto}_i = 6)$.
8. **UDP Ratio**: $rac{1}{N_t} \sum_{i=1}^{N_t} \mathbb{I}(	ext{Proto}_i = 17)$.
9. **ICMP Ratio**: $rac{1}{N_t} \sum_{i=1}^{N_t} \mathbb{I}(	ext{Proto}_i = 1)$.

### Category D: Port & Service Targeting Telemetry (Features 10–13)
10. **Unique Destination Ports ($U_{	ext{ports}}$)**: $|\{	ext{DstPort}_i \mid i \in 1 \dots N_t\}|$.
11. **Port Targeting Concentration**: $U_{	ext{ports}} / (N_t + \epsilon)$.
12. **Shannon Destination Port Entropy**:
    $$H(	ext{Port}) = -\sum_{p \in \mathcal{P}_t} p(p) \log_2 p(p)$$
    *(Critical reconnaissance indicator: surges during Nmap port scans).*
13. **Authentication Port Ratio**: Fraction of flows targeting SSH (22), FTP (21), Telnet (23), HTTP Auth (80/8080).

### Category E: TCP Flag Signatures & Handshake Health (Features 14–23)
14. **SYN Count**: Total SYN flags in window.
15. **ACK Count**: Total ACK flags in window.
16. **RST Count**: Total RST flags in window.
17. **FIN Count**: Total FIN flags in window.
18. **PSH Count**: Total PSH flags in window.
19. **SYN Ratio**: $	ext{SYN} / (N_t + \epsilon)$ *(Spikes during SYN floods & scans)*.
20. **ACK Ratio**: $	ext{ACK} / (N_t + \epsilon)$ *(Indicates established communication)*.
21. **RST Ratio**: $	ext{RST} / (N_t + \epsilon)$ *(Indicates connection rejections / closed ports)*.
22. **RST-to-SYN Ratio**: $	ext{RST} / (	ext{SYN} + \epsilon)$ *(Signature of failed scan probes)*.
23. **Handshake Completion Ratio**: $\min(	ext{SYN}, 	ext{ACK}) / (\max(	ext{SYN}, 	ext{ACK}) + \epsilon)$.

### Category F: Directional Asymmetry & Flow Dynamics (Features 24–27)
24. **Forward Packet Ratio**: $\sum 	ext{Fwd\_Pkts} / (P_t + \epsilon)$.
25. **Forward Byte Ratio**: $\sum 	ext{Fwd\_Bytes} / (B_t + \epsilon)$.
26. **Down/Up Ratio Mean**: Mean of flow Down/Up ratios.
27. **Down/Up Ratio Std**: Standard deviation of flow Down/Up ratios.

### Category G: Packet Length Distributions (Features 28–32)
28. **Packet Length Mean**: Mean packet size across all flows.
29. **Packet Length Std**: Packet size variance/jitter.
30. **Packet Length Max**: Maximum observed packet length.
31. **Packet Length Min**: Minimum observed packet length.
32. **Zero-Payload Ratio**: Fraction of flows with zero data payload.

### Category H: Inter-Arrival Time (IAT) & Pacing Telemetry (Features 33–37)
33. **Flow IAT Mean**: Mean flow inter-arrival time in window.
34. **Flow IAT Std**: Pacing jitter *(Distinguishes automated bots from human traffic)*.
35. **Flow IAT Max**: Maximum inter-arrival gap.
36. **Flow IAT Min**: Minimum inter-arrival gap.
37. **Active Connection Lifetime Mean**: Mean duration of flows terminating in window.

### Category I: First-Order Velocity Dynamics / Acceleration (Features 38–54)
38–54. **State Acceleration Deltas**: $\Delta S_t^{(j)} = S_t^{(j)} - S_{t-1}^{(j)}$ for the top 17 primary volume, rate, flag, and entropy metrics.

---

## 3. Comparison of State Designs

| Criteria | Design A (Simple Mean) | Design B (Mean + Std + Percentiles) | Design C (Behavioral Macro-State — Recommended) |
| :--- | :---: | :---: | :---: |
| **Dimensionality** | 20 features | 65 features | **54 features** |
| **Port Scan Detection** | Fails (Mean port is uninformative) | Poor | **Excellent (Entropy & Port Concentration)** |
| **SYN Flood Dynamics** | Moderate | Moderate | **Excellent (SYN ratio & Handshake Health)** |
| **C2 Beaconing Detection** | Poor | Moderate | **Excellent (IAT Pacing Jitter)** |
| **Computational Footprint** | Very Low | High (Sorting for percentiles) | **Moderate & Fully Vectorized** |
| **Temporal Transformer Fit**| Under-expressive | High Multicollinearity | **Optimal Conditioning** |
