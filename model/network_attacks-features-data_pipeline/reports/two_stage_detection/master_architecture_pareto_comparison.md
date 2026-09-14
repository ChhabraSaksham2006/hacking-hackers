# Master Architecture Comparison & Validation Pareto Trade-Off Benchmark
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. Multi-Architecture Head-to-Head Benchmark Matrix

| Setting | Architecture | Precision $\uparrow$ | Recall $\uparrow$ | F1 Score $\uparrow$ | Onset Recall $\uparrow$ | Lead Time | Incident FA / Hour $\downarrow$ | Window FA / Hour $\downarrow$ | Alerts / Ep $\downarrow$ | Missed Eps $\downarrow$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Setting A | SparseRSSM (Standalone 0.50) | 43.22% | 87.22% | 0.5780 | 96.55% | 20.0s | 8.46 FA/hr | 371.98 FA/hr | 4.03 | 1 |
| Setting A | TFCNet (Standalone 0.50) | 29.29% | 99.96% | 0.4530 | 100.00% | 20.0s | 7.58 FA/hr | 807.04 FA/hr | 3.32 | 0 |
| Setting A | Hybrid Ensemble (Single Classifier 0.50) | 78.90% | 81.68% | 0.8026 | 48.28% | 20.0s | 8.61 FA/hr | 69.77 FA/hr | 4.48 | 15 |
| Setting A | **Two-Stage Early-Warning + Confirmation (Incident Aggregated)** | **15.88%** | **100.00%** | **0.2741** | **100.00%** | **20.0s** | **0.07 FA/hr** | 1800.00 FA/hr | 0.03 | 0 |
| Setting B | SparseRSSM (Standalone 0.50) | 71.98% | 18.72% | 0.2971 | 14.29% | 20.0s | 8.17 FA/hr | 53.56 FA/hr | 64.86 | 6 |
| Setting B | TFCNet (Standalone 0.50) | 37.86% | 100.00% | 0.5493 | 100.00% | 20.0s | 0.12 FA/hr | 1213.31 FA/hr | 0.57 | 0 |
| Setting B | Hybrid Ensemble (Single Classifier 0.50) | 85.22% | 12.24% | 0.2140 | 0.00% | 0.0s | 2.79 FA/hr | 15.56 FA/hr | 26.71 | 7 |
| Setting B | **Two-Stage Early-Warning + Confirmation (Incident Aggregated)** | **37.86%** | **100.00%** | **0.5492** | **100.00%** | **20.0s** | **0.12 FA/hr** | 1213.51 FA/hr | 0.57 | 0 |
| Setting C | SparseRSSM (Standalone 0.50) | 60.45% | 12.37% | 0.2053 | 14.29% | 20.0s | 6.13 FA/hr | 59.97 FA/hr | 43.14 | 6 |
| Setting C | TFCNet (Standalone 0.50) | 9.09% | 0.01% | 0.0001 | 0.00% | 0.0s | 0.16 FA/hr | 0.39 FA/hr | 0.71 | 7 |
| Setting C | Hybrid Ensemble (Single Classifier 0.50) | 86.40% | 10.71% | 0.1906 | 0.00% | 0.0s | 2.44 FA/hr | 12.50 FA/hr | 22.00 | 7 |
| Setting C | **Two-Stage Early-Warning + Confirmation (Incident Aggregated)** | **37.83%** | **97.97%** | **0.5458** | **100.00%** | **20.0s** | **0.12 FA/hr** | 1190.56 FA/hr | 0.57 | 0 |

---

## 2. Validation Pareto Trade-Off Tables (FA/hr vs. Onset Recall)

### Setting A Pareto Trade-Off Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 0.2/hr | **0.22 FA/hr** | **100.00%** | **6.30%** | **100.00%** | **0.1185** | **20.0s** |

### Setting B Pareto Trade-Off Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 0.2/hr | **0.19 FA/hr** | **100.00%** | **7.74%** | **100.00%** | **0.1436** | **20.0s** |
| FA < 7.5/hr | **7.47 FA/hr** | **100.00%** | **6.00%** | **100.00%** | **0.1131** | **20.0s** |
| FA < 31.7/hr | **31.70 FA/hr** | **100.00%** | **7.72%** | **96.35%** | **0.1430** | **20.0s** |
| FA < 90.5/hr | **90.51 FA/hr** | **100.00%** | **7.81%** | **86.27%** | **0.1432** | **20.0s** |

### Setting C Pareto Trade-Off Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 5.5/hr | **5.46 FA/hr** | **100.00%** | **7.70%** | **98.99%** | **0.1429** | **20.0s** |
| FA < 13.8/hr | **13.79 FA/hr** | **100.00%** | **7.64%** | **97.05%** | **0.1416** | **20.0s** |
| FA < 34.7/hr | **34.67 FA/hr** | **100.00%** | **7.58%** | **92.63%** | **0.1401** | **20.0s** |

---

## 3. Exemplar SOC Alert Payloads with MITRE & Physical Evidence
```json
{
  "A": [
    {
      "incident_id": "INC-000000",
      "start_time_sec": 0.0,
      "duration_sec": 58916.0,
      "peak_risk": 0.9999,
      "family": "DoS",
      "mitre_tactic": "Impact (Network Denial of Service)",
      "mitre_technique": "T1498",
      "delta_evidence": {
        "zero_payload_ratio": 0.1513,
        "fwd_byte_ratio": 0.1193,
        "flow_iat_std": 0.1105,
        "pkt_len_mean": 0.0986,
        "handshake_completion_ratio": 0.0965
      }
    }
  ],
  "B": [
    {
      "incident_id": "INC-000000",
      "start_time_sec": 0.0,
      "duration_sec": 16222.0,
      "peak_risk": 0.9995,
      "family": "WebAttack",
      "mitre_tactic": "Initial Access (Exploit Public-Facing Application)",
      "mitre_technique": "T1190",
      "delta_evidence": {
        "rst_ratio": 0.6604,
        "syn_count": 0.2559,
        "udp_ratio": 0.238,
        "auth_port_ratio": 0.2014,
        "rst_to_syn_ratio": 0.1842
      }
    },
    {
      "incident_id": "INC-013983",
      "start_time_sec": 27966.0,
      "duration_sec": 32318.0,
      "peak_risk": 1.0,
      "family": "DDoS",
      "mitre_tactic": "Impact (Endpoint Denial of Service)",
      "mitre_technique": "T1499",
      "delta_evidence": {
        "rst_ratio": 0.5182,
        "syn_count": 0.2163,
        "auth_port_ratio": 0.197,
        "flow_iat_mean": 0.161,
        "fwd_byte_ratio": 0.1549
      }
    },
    {
      "incident_id": "INC-034657",
      "start_time_sec": 69314.0,
      "duration_sec": 34408.0,
      "peak_risk": 1.0,
      "family": "DDoS",
      "mitre_tactic": "Impact (Endpoint Denial of Service)",
      "mitre_technique": "T1499",
      "delta_evidence": {
        "rst_ratio": 0.5098,
        "fwd_byte_ratio": 0.2547,
        "syn_count": 0.2236,
        "syn_ratio": 0.2128,
        "total_ip_bytes": 0.1776
      }
    }
  ],
  "C": [
    {
      "incident_id": "INC-000000",
      "start_time_sec": 0.0,
      "duration_sec": 16220.0,
      "peak_risk": 0.9996,
      "family": "BruteForce",
      "mitre_tactic": "Credential Access (Brute Force)",
      "mitre_technique": "T1110",
      "delta_evidence": {
        "rst_ratio": 0.7858,
        "udp_ratio": 0.2358,
        "auth_port_ratio": 0.2143,
        "rst_to_syn_ratio": 0.1855,
        "fwd_byte_ratio": 0.1639
      }
    },
    {
      "incident_id": "INC-013983",
      "start_time_sec": 27966.0,
      "duration_sec": 32316.0,
      "peak_risk": 1.0,
      "family": "DDoS",
      "mitre_tactic": "Impact (Endpoint Denial of Service)",
      "mitre_technique": "T1499",
      "delta_evidence": {
        "rst_ratio": 0.5475,
        "fwd_byte_ratio": 0.214,
        "auth_port_ratio": 0.197,
        "flow_iat_mean": 0.1627,
        "flow_count": 0.1417
      }
    },
    {
      "incident_id": "INC-034657",
      "start_time_sec": 69314.0,
      "duration_sec": 34406.0,
      "peak_risk": 1.0,
      "family": "DDoS",
      "mitre_tactic": "Impact (Endpoint Denial of Service)",
      "mitre_technique": "T1499",
      "delta_evidence": {
        "rst_ratio": 0.4827,
        "fwd_byte_ratio": 0.3255,
        "syn_ratio": 0.2276,
        "udp_ratio": 0.1682,
        "flow_iat_mean": 0.1551
      }
    }
  ]
}
```