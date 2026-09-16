"""
Terminal Dashboard & Visualizer
Displays an animated, real-time console dashboard illustrating the flow of traffic
through every stage of the Edge Sensor Agent.
"""

import os
import sys
import time
from typing import List, Optional
try:
    from ..core.packet_ingress import RawPacket
    from ..core.flow_tracker import FlowRecord
    from ..core.feature_extractor import TemporalWindow
    from ..core.edge_sentinel import TriageAlert
except (ImportError, ValueError):
    from core.packet_ingress import RawPacket
    from core.flow_tracker import FlowRecord
    from core.feature_extractor import TemporalWindow
    from core.edge_sentinel import TriageAlert


# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_BLUE = "\033[44m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"


class TerminalVisualizer:
    """
    Renders live ASCII telemetry dashboard for the Edge Sensor Agent.
    """

    def __init__(self, sensor_id: str = "edge-sensor-alpha-01", mode: str = "Simulation Replay"):
        self.sensor_id = sensor_id
        self.mode = mode
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.recent_packets: List[RawPacket] = []
        self.recent_alerts: List[TriageAlert] = []
        self.last_window: Optional[TemporalWindow] = None
        self.windows_emitted = 0

    def update_packet(self, packet: RawPacket):
        self.total_packets += 1
        self.total_bytes += packet.wire_len
        self.recent_packets.append(packet)
        if len(self.recent_packets) > 6:
            self.recent_packets.pop(0)

    def update_window(self, window: TemporalWindow, alerts: List[TriageAlert]):
        self.last_window = window
        self.windows_emitted += 1
        if alerts:
            self.recent_alerts.extend(alerts)
            if len(self.recent_alerts) > 5:
                self.recent_alerts = self.recent_alerts[-5:]

    def render(self, active_flows: List[FlowRecord], current_progress: float = 0.0):
        """Draws the live sensor telemetry frame."""
        elapsed = time.time() - self.start_time
        pkt_rate = self.total_packets / max(0.1, elapsed)
        kb_rate = (self.total_bytes / 1024.0) / max(0.1, elapsed)

        # Clear screen and move cursor home
        sys.stdout.write("\033[2J\033[H")

        out = []
        out.append(f"{BG_BLUE}{WHITE}{BOLD}  AEGIS VANTAGE :: DISTRIBUTED EDGE SENSOR AGENT  {RESET}  {DIM}ID:{RESET} {CYAN}{self.sensor_id}{RESET} | {DIM}MODE:{RESET} {GREEN}{self.mode}{RESET}")
        out.append(f"{DIM}Uptime: {elapsed:05.1f}s | Ingress Rate: {pkt_rate:6.1f} pkts/s | Throughput: {kb_rate:7.2f} KB/s | Active Sessions: {len(active_flows)}{RESET}")
        out.append(f"{CYAN}{'─' * 78}{RESET}")

        # ── 1. Ingress Packet Stream (Stage 1) ──────────────────────
        out.append(f"{BOLD}[STAGE 1: PACKET INGRESS & TAP]{RESET} {DIM}Latest Dissected Wire Frames:{RESET}")
        for p in self.recent_packets[-4:]:
            flag_str = f"{YELLOW}{p.tcp_flags}{RESET}" if p.tcp_flags else f"{DIM}N/A{RESET}"
            proto_color = GREEN if p.protocol == "TCP" else CYAN
            out.append(
                f"  {DIM}▸{RESET} {proto_color}{p.protocol:4s}{RESET} "
                f"{p.src_ip:>15s}:{p.src_port:<5d} → {p.dst_ip:>15s}:{p.dst_port:<5d} "
                f"{p.wire_len:4d}B  [{flag_str:10s}]"
            )

        # ── 2. Active Flow Tracker Table (Stage 2) ──────────────────
        out.append(f"\n{BOLD}[STAGE 2: STATEFUL FLOW TRACKER]{RESET} {DIM}Bidirectional 5-Tuple Table (Top Sessions):{RESET}")
        out.append(f"  {DIM}{'ID':<12s} {'Source':<21s} {'Destination':<21s} {'Proto':<5s} {'Packets':<8s} {'Bytes':<8s} {'State'}{RESET}")
        
        sorted_flows = sorted(active_flows, key=lambda x: x.total_packets, reverse=True)[:4]
        for f in sorted_flows:
            state_color = GREEN if f.tcp_state == "ESTABLISHED" else RED if f.tcp_state == "RESET" else YELLOW
            out.append(
                f"  {CYAN}{f.flow_id:<12s}{RESET} "
                f"{f.src_ip}:{f.src_port:<15s} → {f.dst_ip}:{f.dst_port:<15s} "
                f"{f.protocol:<5s} {f.total_packets:<8d} {f.total_bytes:<8d} "
                f"{state_color}{f.tcp_state}{RESET}"
            )

        # ── 3. 2.0s Temporal Window Aggregator (Stage 3) ────────────
        pct = min(100, int(current_progress * 100))
        bar_len = 30
        filled = int((pct / 100.0) * bar_len)
        bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{RESET}"

        win_idx_str = f"#{self.windows_emitted}" if self.last_window else "#0"
        out.append(f"\n{BOLD}[STAGE 3: TEMPORAL WINDOW AGGREGATOR (Δt = 2.0s)]{RESET} Window {CYAN}{win_idx_str}{RESET}")
        out.append(f"  Aggregating Buffer: [{bar}] {pct:3d}%  (Emitted Windows: {self.windows_emitted})")

        # ── 4. Extracted 54-D State Vector (Stage 4) ────────────────
        if self.last_window:
            feat = self.last_window.feature_dict
            entropy = feat.get("dst_port_entropy", 0.0)
            auth_ratio = feat.get("auth_port_ratio", 0.0) * 100.0
            syn_ratio = feat.get("syn_ratio", 0.0) * 100.0
            byte_rate = feat.get("byte_rate", 0.0)

            ent_color = RED if entropy >= 3.0 else YELLOW if entropy >= 2.0 else GREEN
            auth_color = RED if auth_ratio >= 40.0 else YELLOW if auth_ratio >= 20.0 else GREEN
            syn_color = RED if syn_ratio >= 70.0 else YELLOW if syn_ratio >= 40.0 else GREEN

            out.append(f"\n{BOLD}[STAGE 4: EXTRACTED 54-D CYBER WORLD MODEL VECTOR]{RESET}")
            out.append(
                f"  Entropy: {ent_color}{entropy:4.2f} bits{RESET}  | "
                f"Auth Ports (445/22): {auth_color}{auth_ratio:4.1f}%{RESET}  | "
                f"SYN Ratio: {syn_color}{syn_ratio:4.1f}%{RESET}  | "
                f"Byte Rate: {byte_rate:7.1f} B/s"
            )
            out.append(
                f"  {DIM}Vector preview [0..7]: {self.last_window.vector_54[:8]}{RESET}"
            )
        else:
            out.append(f"\n{BOLD}[STAGE 4: EXTRACTED 54-D CYBER WORLD MODEL VECTOR]{RESET} {DIM}Awaiting first 2.0s window tick...{RESET}")

        # ── 5. Edge Anomaly Sentinel & Alerts (Stage 5) ─────────────
        out.append(f"\n{BOLD}[STAGE 5: EDGE ANOMALY SENTINEL (Zero-Latency Local Triage)]{RESET}")
        if self.recent_alerts:
            for a in self.recent_alerts[-2:]:
                sev_badge = f"{BG_RED}{WHITE}{BOLD} CRITICAL {RESET}" if a.severity == "critical" else f"{BG_YELLOW}{WHITE}{BOLD}  ALERT   {RESET}"
                out.append(f"  {sev_badge} {RED}{BOLD}[{a.threat_type}]{RESET} {a.technique_id} - {a.technique_name}")
                out.append(f"    {DIM}Description:{RESET} {a.description}")
                out.append(f"    {DIM}Edge Action:{RESET} {YELLOW}{a.recommended_edge_action}{RESET}")
        else:
            out.append(f"  {GREEN}✓ Normal Baseline Operations{RESET} {DIM}— zero local heuristic violations detected.{RESET}")

        out.append(f"\n{CYAN}{'─' * 78}{RESET}")
        out.append(f"{DIM}Press Ctrl+C to safely detach sensor agent.{RESET}")

        sys.stdout.write("\n".join(out) + "\n")
        sys.stdout.flush()
