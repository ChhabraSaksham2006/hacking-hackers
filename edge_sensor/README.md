# Flow Drishti â€” Distributed Edge Sensor Agent

## 1. Overview
The **Flow Drishti Edge Sensor Agent** is a lightweight, high-throughput network edge telemetry probe designed to run on perimeter gateways, edge routers, Linux firewalls, and TAP/SPAN ports. 

It acts as the first line of defense in the Flow Drishti intrusion detection pipeline:
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
             â”‚
             â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ Stage 1: Packet Ingress Engine         â”‚  Raw packet dissection (Ethernet, IPv4, TCP, UDP, ICMP)
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚ RawPacket
                    â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ Stage 2: Stateful Flow Engine          â”‚  Bi-directional 5-tuples, TCP handshakes, IATs
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚ FlowRecord
                    â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ Stage 3: 2.0s Temporal Window Extractorâ”‚  2.0s slicing & 54-D state vector computation
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚ TemporalWindow (54-D Vector)
                    â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ Stage 4: Edge Anomaly Sentinel         â”‚  Zero-latency local triage & MITRE alerts
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚ TriageAlerts
                    â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ Stage 5: Telemetry Dispatcher & UI     â”‚  Streaming to Upstream API, NDJSON, and Live Terminal
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## 3. Directory Layout

```
edge_sensor/
â”œâ”€â”€ README.md                      # Complete architectural and operational guide
â”œâ”€â”€ config.json                    # Sensor configuration (window duration, thresholds)
â”œâ”€â”€ run_sensor.py                  # Main CLI runner & interactive demonstration
â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ packet_ingress.py          # Binary libpcap parser & live packet sniffer
â”‚   â”œâ”€â”€ flow_tracker.py            # Stateful bidirectional 5-tuple flow engine
â”‚   â”œâ”€â”€ feature_extractor.py       # 2.0s temporal aggregator & 54-D state vector extractor
â”‚   â”œâ”€â”€ edge_sentinel.py           # Zero-latency edge heuristics & triage alert generator
â”‚   â””â”€â”€ telemetry_dispatcher.py    # Asynchronous upstream HTTP & NDJSON dispatcher
â”œâ”€â”€ demo/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ traffic_generator.py       # Realistic multi-stage enterprise traffic generator
â”‚   â””â”€â”€ visualizer.py              # Real-time ANSI terminal telemetry dashboard
â””â”€â”€ tests/
    â”œâ”€â”€ __init__.py
    â””â”€â”€ test_sensor_pipeline.py    # Full unit test suite
```

---

## 4. Quick Start & Execution Modes

### Mode 1: Live External Device Gateway (Smartphone / Audience Demo)
Allows any external phone or laptop connected to the same Wi-Fi / local network to interact directly with the sensor in real time:
```bash
python edge_sensor/run_sensor.py --mode live
```
1. The sensor agent automatically detects the host computer's LAN IP and hosts an interactive portal (e.g. `http://192.168.1.31:8888`).
2. Anyone (judge, presenter, team member) opens that URL in their mobile browser.
3. The sensor terminal immediately shows:
   - **Device Ingress & Platform Detection**: Client IP, User-Agent (iPhone, Android, Windows, Mac), and socket status.
   - **Real-Time Verification Logs**: Exact wire frames, timestamp, source port, destination port, payload bytes, and actions recorded to `live_ingress.log`.
   - **Interactive Actions**: The mobile screen provides buttons to send Normal Traffic, trigger Reconnaissance Sweeps, surge privileged SMB/Auth ports (445/22), launch Exfiltration bursts, or inject a custom judge identification message.
   - **Zero Dummy Data**: Every packet is parsed from a genuine TCP socket request, tracks real TCP state, slices into 2.0s windows, extracts genuine 54-D mathematical features, and triggers zero-latency triage alerts.

### Mode 2: Multi-Stage Attack Simulation Visualizer
Launches an animated terminal dashboard demonstrating simulated traffic flowing through all 5 stages of the sensor agent:
```bash
python edge_sensor/run_sensor.py --mode demo --speed 2.0
```
- Cycles through: Normal Enterprise Baseline -> Reconnaissance Port Sweep -> SMB EternalBlue Exploitation -> Exfiltration.
- Displays live packet stream, top flow sessions, 2.0s window progress bar, 54-D vector values, and local triage alerts.

### Mode 3: Replay Real Binary PCAP Capture
Feeds an actual binary `.pcap` capture through the edge sensor:
```bash
python edge_sensor/run_sensor.py --mode pcap --file sample_captures/sample_2_ransomware_eternalblue_smb.pcap --speed 3.0
```

### Mode 4: Headless Telemetry Daemon (Production)
Streams 54-D temporal state windows and edge triage alerts to a local NDJSON log file or central REST endpoint:
```bash
python edge_sensor/run_sensor.py --mode headless --output edge_sensor/telemetry.ndjson
```

---

## 5. Extracted 54-D State Vector Reference
The edge sensor outputs the exact 54 dimensions required by the Flow Drishti world model:

| Dimensions | Feature Category | Key Metrics |
|:---:|:---|:---|
| **0 â€“ 5** | Flow & Volume Dynamics | `flow_count`, `total_ip_bytes`, `total_packets`, `flow_rate`, `byte_rate`, `packet_rate` |
| **6 â€“ 8** | Protocol Distribution | `tcp_ratio`, `udp_ratio`, `icmp_ratio` |
| **9 â€“ 12** | Port & Entropy Dynamics | `unique_dst_ports`, `port_concentration`, `dst_port_entropy` (Shannon), `auth_port_ratio` (ports 22, 88, 139, 389, 445, 3389) |
| **13 â€“ 22** | TCP Flag & Handshake Dynamics | `syn_count`, `ack_count`, `rst_count`, `syn_ratio`, `rst_to_syn_ratio`, `handshake_completion_ratio` |
| **23 â€“ 26** | Directional Ratios | `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean`, `down_up_ratio_std` |
| **27 â€“ 36** | Packet Lengths & Jitter/IAT | `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `pkt_len_min`, `zero_payload_ratio`, `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min` |
| **37** | Session Persistence | `active_connection_lifetime_mean` |
| **38 â€“ 53** | 17 Velocity Deltas ($\Delta$) | First-order temporal derivatives ($\Delta = x_t - x_{t-1}$) capturing sudden network phase shifts |
