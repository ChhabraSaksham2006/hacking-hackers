# 03 — Critical Temporal & Attack-Progression Forensic Audit
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. The Core Temporal Forecasting Equation

The objective is to train an autoregressive or direct sequence forecaster:
$$[S_{t-4}, S_{t-3}, S_{t-2}, S_{t-1}, S_t] \xrightarrow{\text{Temporal Transformer}} [S_{t+1}, S_{t+3}, S_{t+5}, S_{t+10}]$$

Where $S_t \in \mathbb{R}^D$ represents the macro- or host-level network state at discrete time window $W_t = [t \cdot \Delta t, (t+1) \cdot \Delta t)$.

### Necessary Mathematical Conditions for Valid Temporal Modeling:
1. **Strict Monotonicity**: $\forall i < j, \tau_i \le \tau_j$ (timestamps must not flow backward).
2. **True Network Continuity**: Consecutive windows must capture the same continuous physical or virtual network segment without random shuffling.
3. **Realistic Event Density**: Attack actions must span multiple consecutive time steps rather than being isolated single-row impulses.
4. **Leakage-Free Splitting**: Splitting must occur along the time axis $T_{\text{split}}$, ensuring:
   $$\text{Train} = \{S_t \mid t < T_{\text{train}}\}; \quad \text{Val} = \{S_t \mid T_{\text{train}} \le t < T_{\text{val}}\}; \quad \text{Test} = \{S_t \mid t \ge T_{\text{val}}\}$$

---

## 2. Temporal Feasibility by Candidate

| Candidate | Epoch Timestamp Available? | Chronological Monotonicity? | Session / Day Boundaries Respected? | Can Support $S(t+K)$ Horizon Forecasting? | Evidence / Forensic Findings |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **A: Official CSE-CIC-IDS2018** | **YES** (`Timestamp`) | **YES** (When parsed chronologically) | **YES** (10 distinct capture days) | **YES — HIGHEST CAPABILITY** | Each CSV represents a continuous business-day capture (e.g. 08:00 to 17:00). Microsecond/second flow starts enable discrete window binning (e.g. $\Delta t = 10\text{s}$). |
| **B: NF-CSE-CIC-IDS2018-v2** | Partial (Duration only) | Sequence preserved | Grouped by NetFlow sessions | **CONDITIONAL** | Parquet files preserve the capture sequence, but wall-clock timestamps are stripped. Windowing must rely on cumulative durations or flow indices. |
| **C: CSE-CIC-IDS2018 Improved** | **YES** (Corrected Datetime) | **YES** (Audited) | **YES** (10 capture days) | **YES — HIGHEST INTEGRITY** | DistriNet fixed flow timing bugs in CICFlowMeter, ensuring flow durations and inter-arrival times match actual PCAP packet arrivals. |
| **D: Kaggle chethuhn (CIC-IDS2017)** | **YES** in raw CSVs | **DESTROYED** if shuffled | Separated by day | **YES (If Restored from Raw CSVs)** | If the raw CSVs are read chronologically and sorted by timestamp, sliding windows can be formed. However, single-day files limit cross-day campaign modeling. |
| **E: Multi-Dataset Collection** | Disjoint | No | Disparate years | **FAIL** | Gaps of months/years between datasets make multi-step forecasting meaningless across boundaries. |
| **F: BigFlow-NIDS** | Standardized | Synthetic concatenation | Merged sources | **WEAK** | Inter-dataset boundary transitions create artificial discontinuities. |
| **G: DARPA 1998** | **YES** | **YES** | 5 days (Week 1) | **YES (Technically)**, but **IRRELEVANT** | Valid 10s windows exist, but traffic dynamics are from 1998 scripted emulators. |

---

## 3. Deep Dive: Attack Progression in CSE-CIC-IDS2018 Infiltration Scenario

The crown jewel for temporal attack progression modeling is the **Infiltration Scenario** of CSE-CIC-IDS2018 (captured across **28-02-2018** and **01-03-2018**):

### Ground-Truth Multi-Stage Progression Timeline:
1. **Stage 1 — Initial Weaponization & Delivery (Morning)**:
   * Attacker sends phishing email with malicious payload (Dropbox link) to internal employee.
   * Victim downloads and executes payload (`172.31.69.28`).
2. **Stage 2 — C2 Beaconing & Foothold (Midday)**:
   * Compromised machine establishes outbound Command-and-Control (C2) channel to external attacker IP.
   * Periodic HTTP/TCP keep-alive beaconing with consistent inter-arrival times.
3. **Stage 3 — Internal Discovery & Lateral Reconnaissance (Afternoon)**:
   * Attacker executes port scanning (`Nmap`) and IP sweeps from the compromised host to map the internal subnet (`172.31.0.0/16`).
   * Dramatic spike in internal SYN packets, destination port entropy, and failed connection ratios.
4. **Stage 4 — Lateral Movement & Vulnerability Exploitation**:
   * Attacker targets vulnerable internal servers via SMB (EternalBlue / MS17-010) or SSH.
5. **Stage 5 — Privilege Escalation & Exfiltration**:
   * Attacker accesses domain controller/sensitive file repository and exfiltrates data out of the network.

### Forensic Conclusion on Progression Modeling:
CSE-CIC-IDS2018 is one of the **only public intrusion datasets that contains a genuine multi-hour, multi-stage infiltration progression on modern Windows/Linux architecture**. This enables an AI World Model to observe Stage 1/2 anomalies and forecast impending Stage 3/4 attacks with significant lead time.
