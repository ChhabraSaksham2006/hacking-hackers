# Two-Stage Early-Warning + Confirmation Architecture Benchmark
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. Multi-Task Test Benchmark Summary

| Setting | Architecture | Precision | Recall | F1 Score | Onset Recall | Median Lead Time | Incident FA / Hour | Window FA / Hour | Alerts / Episode | Missed Episodes |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Setting A** | Two-Stage Early-Warning + Confirmation | **45.58%** | **87.00%** | **0.5982** | **96.55%** | **20.0s** | **9.20 FA/hr** | 335.40 FA/hr | 4.32 | 1 |
| **Setting B** | Two-Stage Early-Warning + Confirmation | **63.98%** | **25.99%** | **0.3696** | **28.57%** | **20.0s** | **12.30 FA/hr** | 107.76 FA/hr | 96.14 | 5 |
| **Setting C** | Two-Stage Early-Warning + Confirmation | **48.29%** | **17.73%** | **0.2594** | **28.57%** | **20.0s** | **8.65 FA/hr** | 140.30 FA/hr | 66.71 | 5 |

---

## 2. Validation Pareto Trade-Off Tables (FA/hr vs. Onset Recall)

### Setting A Pareto Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 0.7/hr | **0.67 FA/hr** | **88.89%** | **53.97%** | **88.10%** | **0.6694** | **20.0s** |

### Setting B Pareto Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 79.3/hr | **79.30 FA/hr** | **87.86%** | **7.81%** | **68.27%** | **0.1402** | **20.0s** |
| FA < 100.7/hr | **100.66 FA/hr** | **80.71%** | **7.34%** | **47.17%** | **0.1270** | **20.0s** |

### Setting C Pareto Operating Points

| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| FA < 30.5/hr | **30.46 FA/hr** | **96.43%** | **7.66%** | **87.98%** | **0.1409** | **20.0s** |
| FA < 53.3/hr | **53.25 FA/hr** | **96.43%** | **7.55%** | **82.39%** | **0.1383** | **20.0s** |
| FA < 123.6/hr | **123.55 FA/hr** | **81.43%** | **7.17%** | **36.38%** | **0.1198** | **20.0s** |

---

## 3. Exemplar SOC Alert Payloads with MITRE & Physical Evidence
```json
{
  "A": [
    {
      "incident_id": "INC-005362",
      "start_time_sec": 10724.0,
      "duration_sec": 12.0,
      "peak_risk": 0.9514,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "delta_port_concentration": 1.6459,
        "fwd_packet_ratio": 0.9795,
        "tcp_ratio": 0.9654,
        "pkt_len_std": 0.8963,
        "pkt_len_mean": 0.8315
      }
    },
    {
      "incident_id": "INC-005582",
      "start_time_sec": 11164.0,
      "duration_sec": 24.0,
      "peak_risk": 0.9942,
      "family": "BruteForce",
      "mitre_tactic": "Credential Access (Brute Force)",
      "mitre_technique": "T1110",
      "delta_evidence": {
        "flow_count": 3.8192,
        "psh_count": 3.7902,
        "flow_rate": 3.7817,
        "ack_count": 3.7716,
        "rst_count": 3.719
      }
    },
    {
      "incident_id": "INC-007656",
      "start_time_sec": 15312.0,
      "duration_sec": 4.0,
      "peak_risk": 0.3624,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "flow_iat_min": 9.5325,
        "flow_iat_mean": 7.2378,
        "active_connection_lifetime_mean": 5.8611,
        "zero_payload_ratio": 3.341,
        "port_concentration": 2.7477
      }
    }
  ],
  "B": [
    {
      "incident_id": "INC-000000",
      "start_time_sec": 0.0,
      "duration_sec": 2.0,
      "peak_risk": 0.153,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "rst_ratio": 1.6694,
        "delta_dst_port_entropy": 1.5164,
        "syn_count": 0.6657,
        "delta_auth_port_ratio": 0.6382,
        "delta_ack_ratio": 0.4291
      }
    },
    {
      "incident_id": "INC-000012",
      "start_time_sec": 24.0,
      "duration_sec": 20.0,
      "peak_risk": 0.3363,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "delta_dst_port_entropy": 0.8764,
        "delta_rst_ratio": 0.7011,
        "rst_ratio": 0.5578,
        "udp_ratio": 0.5151,
        "syn_count": 0.3094
      }
    },
    {
      "incident_id": "INC-000040",
      "start_time_sec": 80.0,
      "duration_sec": 18.0,
      "peak_risk": 0.3565,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "rst_ratio": 0.9033,
        "delta_rst_ratio": 0.7596,
        "delta_ack_ratio": 0.6173,
        "delta_syn_ratio": 0.4695,
        "delta_dst_port_entropy": 0.435
      }
    }
  ],
  "C": [
    {
      "incident_id": "INC-000014",
      "start_time_sec": 28.0,
      "duration_sec": 16.0,
      "peak_risk": 0.3762,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "delta_rst_ratio": 1.2138,
        "delta_dst_port_entropy": 1.1273,
        "rst_ratio": 0.8158,
        "udp_ratio": 0.4255,
        "flow_iat_mean": 0.2281
      }
    },
    {
      "incident_id": "INC-000045",
      "start_time_sec": 90.0,
      "duration_sec": 8.0,
      "peak_risk": 0.2453,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "delta_rst_ratio": 1.4475,
        "syn_count": 0.8634,
        "delta_ack_ratio": 0.6828,
        "rst_ratio": 0.6488,
        "syn_ratio": 0.5327
      }
    },
    {
      "incident_id": "INC-000090",
      "start_time_sec": 180.0,
      "duration_sec": 30.0,
      "peak_risk": 0.3204,
      "family": "Benign",
      "mitre_tactic": "Normal Operations",
      "mitre_technique": "None",
      "delta_evidence": {
        "delta_rst_ratio": 0.7411,
        "flow_iat_mean": 0.4216,
        "rst_ratio": 0.381,
        "ack_ratio": 0.2717,
        "pkt_len_std": 0.2466
      }
    }
  ]
}
```