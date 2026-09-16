# Aegis Vantage — Distributed Edge Sensor Agent

## 1. Overview
The **Aegis Vantage Edge Sensor Agent** is a lightweight, high-throughput network edge telemetry probe designed to run on perimeter gateways, edge routers, Linux firewalls, and TAP/SPAN ports. 

It acts as the first line of defense in the Aegis Vantage intrusion detection pipeline:
1. Ingests raw network wire packets (binary libpcap or live interfaces).
2. Maintains bidirectional stateful 5-tuple flow tables and TCP handshakes.
3. Slices traffic into continuous **2.0-second temporal observation windows**.
4. Computes the exact **54-dimensional feature vector** expected by the Cyber World Model (`SparseRSSM` + `TFCNet`).
5. Performs **sub-millisecond local edge triage** before central inference (detecting port sweeps, SYN floods, and privileged SMB/auth bursts).
6. Dispatches serialized telemetry frames upstream to the central backend.

---

## 2. Architecture & Pipeline

```
[ Network TAP / PCAP Dump ]
             │
             ▼
 ┌────────────────────────────────────────┐
 │ Stage 1: Packet Ingress Engine         │  Raw packet dissection (Ethernet, IPv4, TCP, UDP, ICMP)
 └──────────────────┬─────────────────────┘
                    │ RawPacket
                    ▼
 ┌────────────────────────────────────────┐
 │ Stage 2: Stateful Flow Engine          │  Bi-directional 5-tuples, TCP handshakes, IATs
 └──────────────────┬─────────────────────┘
                    │ FlowRecord
                    ▼
 ┌────────────────────────────────────────┐
 │ Stage 3: 2.0s Temporal Window Extractor│  2.0s slicing & 54-D state vector computation
 └──────────────────┬─────────────────────┘
                    │ TemporalWindow (54-D Vector)
                    ▼
 ┌────────────────────────────────────────┐
 │ Stage 4: Edge Anomaly Sentinel         │  Zero-latency local triage & MITRE alerts
 └──────────────────┬─────────────────────┘
                    │ TriageAlerts
                    ▼
 ┌────────────────────────────────────────┐
 │ Stage 5: Telemetry Dispatcher & UI     │  Streaming to Upstream API, NDJSON, and Live Terminal
 └────────────────────────────────────────┘
```

---

## 3. Directory Layout

```
edge_sensor/
├── README.md                      # Complete architectural and operational guide
├── config.json                    # Sensor configuration (window duration, thresholds)
├── run_sensor.py                  # Main CLI runner & interactive demonstration
├── core/
│   ├── __init__.py
│   ├── packet_ingress.py          # Binary libpcap parser & live packet sniffer
│   ├── flow_tracker.py            # Stateful bidirectional 5-tuple flow engine
│   ├── feature_extractor.py       # 2.0s temporal aggregator & 54-D state vector extractor
│   ├── edge_sentinel.py           # Zero-latency edge heuristics & triage alert generator
│   └── telemetry_dispatcher.py    # Asynchronous upstream HTTP & NDJSON dispatcher
├── demo/
│   ├── __init__.py
│   ├── traffic_generator.py       # Realistic multi-stage enterprise traffic generator
│   └── visualizer.py              # Real-time ANSI terminal telemetry dashboard
└── tests/
    ├── __init__.py
    └── test_sensor_pipeline.py    # Full unit test suite
```

---

## 4. Quick Start & Execution Modes

### Mode A: Interactive Multi-Stage Attack Demonstration
Launches an animated terminal dashboard demonstrating live traffic flowing through all 5 stages of the sensor agent:
```bash
python edge_sensor/run_sensor.py --mode demo --speed 2.0
```
- Cycles through: Normal Enterprise Baseline $\to$ Reconnaissance Port Sweep $\to$ SMB EternalBlue Exploitation $\to$ Exfiltration.
- Displays live packet stream, top flow sessions, 2.0s window progress bar, 54-D vector values, and local triage alerts.

### Mode B: Replay Real Binary PCAP Capture
Feeds an actual binary `.pcap` capture through the edge sensor:
```bash
python edge_sensor/run_sensor.py --mode pcap --file sample_captures/sample_2_ransomware_eternalblue_smb.pcap --speed 3.0
```

### Mode C: Headless Telemetry Daemon (Production)
Streams 54-D temporal state windows and edge triage alerts to a local NDJSON log file or central REST endpoint:
```bash
python edge_sensor/run_sensor.py --mode headless --output edge_sensor/telemetry.ndjson
```

---

## 5. Extracted 54-D State Vector Reference
The edge sensor outputs the exact 54 dimensions required by the Aegis Vantage world model:

| Dimensions | Feature Category | Key Metrics |
|:---:|:---|:---|
| **0 – 5** | Flow & Volume Dynamics | `flow_count`, `total_ip_bytes`, `total_packets`, `flow_rate`, `byte_rate`, `packet_rate` |
| **6 – 8** | Protocol Distribution | `tcp_ratio`, `udp_ratio`, `icmp_ratio` |
| **9 – 12** | Port & Entropy Dynamics | `unique_dst_ports`, `port_concentration`, `dst_port_entropy` (Shannon), `auth_port_ratio` (ports 22, 88, 139, 389, 445, 3389) |
| **13 – 22** | TCP Flag & Handshake Dynamics | `syn_count`, `ack_count`, `rst_count`, `syn_ratio`, `rst_to_syn_ratio`, `handshake_completion_ratio` |
| **23 – 26** | Directional Ratios | `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean`, `down_up_ratio_std` |
| **27 – 36** | Packet Lengths & Jitter/IAT | `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `pkt_len_min`, `zero_payload_ratio`, `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min` |
| **37** | Session Persistence | `active_connection_lifetime_mean` |
| **38 – 53** | 17 Velocity Deltas ($\Delta$) | First-order temporal derivatives ($\Delta = x_t - x_{t-1}$) capturing sudden network phase shifts |
