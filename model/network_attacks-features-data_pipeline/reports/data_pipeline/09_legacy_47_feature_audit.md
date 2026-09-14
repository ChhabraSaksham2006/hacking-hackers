# 09 — Forensic Audit of Senior 47-Feature Legacy Schema
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Origin of the 47-Feature Schema

The 47-feature schema defined in `src/feature_extractor.py` was originally crafted for **packet-level DARPA 1998 PCAP captures** to detect 1990s IP fragmentation (Teardrop) and ICMP buffer crashes (Ping of Death).

---

## 2. Why the 47-Feature Schema Failed for CICFlowMeter Data

When the senior pipeline attempted to adapt CIC-IDS2017 into this 47-D schema (`src/cic_feature_adapter.py`), **18 out of 47 features had to be hardcoded to static constants**:

| Feature Name in 47-D Schema | Hardcoded Value in CIC Projection | Consequence |
| :--- | :---: | :--- |
| `tcp_ratio` | `1.0` | Constant (Zero variance) |
| `udp_ratio` | `0.0` | Constant (Zero variance) |
| `icmp_ratio` | `0.0` | Constant (Zero variance) |
| `unique_src_ips` | `1.0` | Constant (Zero variance) |
| `unique_dst_ips` | `1.0` | Constant (Zero variance) |
| `unique_dst_ports` | `1.0` | Constant (Zero variance) |
| `port_entropy` | `0.0` | Constant (Zero variance) |
| `ttl_mean` | `64.0` | Constant (Zero variance) |
| `fragment_count` | `0.0` | Constant (Zero variance) |
| `oversized_icmp_count` | `0.0` | Constant (Zero variance) |

### Verdict:
**The senior 47-feature schema is permanently retired.** The new data engineering pipeline uses the curated 54-feature behavioral subset derived directly from authentic flow telemetry.
