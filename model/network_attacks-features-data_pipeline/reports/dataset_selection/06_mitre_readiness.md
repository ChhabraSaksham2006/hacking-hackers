# 06 — MITRE ATT&CK Mapping Readiness & Hierarchy
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Decoupling Principle: Model Prediction vs. MITRE Interpretation

A fatal flaw in the senior repository was treating MITRE stages (0 through 4) as direct classification targets. 

In this new architecture, we maintain strict architectural separation:

```
[Flow Window Telemetry W_t]
            ↓
  [Discrete State S_t]
            ↓
[Temporal Transformer / World Model]
            ↓
 [Predicted Future Network State S_{t+K}]
            ↓
  [Anomaly & Behaviour Vector B_{t+K}]
            ↓
┌────────────────────────────────────────────────────────┐
│             MITRE ATT&CK INTERPRETATION LAYER          │
│   (Probabilistic rule engine matching dynamics to     │
│   Enterprise Tactics, Techniques, and Evidence)        │
└────────────────────────────────────────────────────────┘
            ↓
 [Forecasted Technique (e.g. T1110) + Confidence + Evidence]
```

---

## 2. Rigorous MITRE ATT&CK Mapping Hierarchy

| Observed Network Behaviour | Candidate Technique ID | Candidate Technique Name | Sub-Technique | Primary Tactic | Mapping Confidence | Observable Evidence in Telemetry |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **High-frequency authentication attempts on Port 21/22/HTTP with rapid TCP resets** | **T1110** | Brute Force | **T1110.001** (Password Guessing) | Credential Access (TA0006) | **VERIFIED** | Dst Port $\in \{21, 22, 80\}$, extremely low flow duration, high failed handshake count, repetitive small payloads. |
| **Sequential connection attempts across incremental destination ports on internal IPs** | **T1046** | Network Service Discovery | — | Discovery (TA0007) / Recon (TA0043) | **VERIFIED** | High destination port entropy, single-packet SYN bursts, minimal data payload, zero complete handshakes. |
| **Volumetric asymmetric packet floods (HTTP GET/POST or UDP storms) saturating links** | **T1498** | Network Denial of Service | **T1498.001** (Direct Network Flood) | Impact (TA0040) | **STRONGLY_SUPPORTED** | Extreme packet rate (pkts/s), high byte rate, abnormal forward/backward packet ratio asymmetry. |
| **Long-duration half-open TCP connections with slow byte transmission designed to starve pool** | **T1499** | Endpoint Denial of Service | **T1499.003** (App Exhaustion Flood) | Impact (TA0040) | **STRONGLY_SUPPORTED** | High flow duration, minimal packet counts, high inter-arrival times, low window size, HTTP header fragmentation. |
| **Suspicious outbound HTTP connections with regular periodicity and fixed payload intervals** | **T1071** | Application Layer Protocol | **T1071.001** (Web Protocols) | Command and Control (TA0011) | **STRONGLY_SUPPORTED** | Periodic beaconing dynamics, low flow IAT variance (low jitter), persistent communication to external IP. |
| **Phishing file download followed by internal port scanning and outbound data transfer** | **T1210 / T1567** | Exploitation of Remote Services / Exfiltration | — | Lateral Movement (TA0008) / Exfiltration (TA0010) | **HEURISTIC** | Internal host initiating external transfer, followed by horizontal scanning of adjacent `/24` subnets. |
| **Malformed SQL syntax strings in HTTP request query parameters or POST bodies** | **T1190** | Exploit Public-Facing Application | — | Initial Access (TA0001) | **STRONGLY_SUPPORTED** | Anomalous payload lengths on HTTP port 80/8080, specific HTTP error code distributions. |
