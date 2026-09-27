"""
Edge Anomaly Sentinel
Zero-latency edge heuristic analysis and triage alert generator running locally on edge sensors.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from .feature_extractor import TemporalWindow


@dataclass
class TriageAlert:
    """Instant local alert generated at network edge."""
    alert_id: str
    timestamp: float
    window_idx: int
    severity: str           # 'info', 'watch', 'high', 'critical'
    threat_type: str        # 'Port Scan', 'SYN Flood', 'SMB Exploitation', 'Exfiltration'
    technique_id: str       # MITRE ATT&CK ID
    technique_name: str
    description: str
    trigger_metric: str
    recommended_edge_action: str


class EdgeSentinel:
    """
    Lightweight rule-based edge sentinel performing sub-millisecond triage
    directly on emitted 54-D state windows before central model inference.
    """

    def __init__(self, enable_heuristics: bool = True):
        self.alert_counter = 0
        self.enable_heuristics = enable_heuristics

    def evaluate(self, window: TemporalWindow) -> List[TriageAlert]:
        """Evaluates a temporal window against edge security baselines."""
        if not self.enable_heuristics:
            return []

        alerts: List[TriageAlert] = []
        feat = window.feature_dict

        dst_port_entropy = feat.get("dst_port_entropy", 0.0)
        unique_ports = feat.get("unique_dst_ports", 1.0)
        auth_port_ratio = feat.get("auth_port_ratio", 0.0)
        syn_ratio = feat.get("syn_ratio", 0.0)
        handshake_ratio = feat.get("handshake_completion_ratio", 1.0)
        packet_rate = feat.get("packet_rate", 0.0)
        byte_rate = feat.get("byte_rate", 0.0)
        delta_entropy = feat.get("delta_dst_port_entropy", 0.0)

        # 1. High-Entropy Port Sweep & Reconnaissance Detection (MITRE T1046)
        is_port_sweep = (
            (dst_port_entropy >= 3.2 and unique_ports >= 8 and (syn_ratio >= 0.20 or packet_rate >= 12.0))
            or (unique_ports >= 20)
            or (delta_entropy >= 2.2 and unique_ports >= 8 and syn_ratio >= 0.20)
        )
        if is_port_sweep:
            self.alert_counter += 1
            alerts.append(
                TriageAlert(
                    alert_id=f"EDGE-{self.alert_counter:04d}",
                    timestamp=window.timestamp_start,
                    window_idx=window.window_idx,
                    severity="watch",
                    threat_type="Reconnaissance Sweep",
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    description=f"Shannon destination port entropy diverged to {dst_port_entropy:.2f} across {int(unique_ports)} distinct ports (SYN Ratio: {syn_ratio*100:.1f}%).",
                    trigger_metric=f"dst_port_entropy={dst_port_entropy:.2f}, unique_ports={int(unique_ports)}, syn_ratio={syn_ratio:.2f}",
                    recommended_edge_action="Activate dynamic edge rate-limiting for scanning IP address.",
                )
            )

        # 2. SYN Flood / DoS Incomplete Handshake Surge
        if syn_ratio >= 0.70 and handshake_ratio <= 0.25 and packet_rate >= 30.0:
            self.alert_counter += 1
            alerts.append(
                TriageAlert(
                    alert_id=f"EDGE-{self.alert_counter:04d}",
                    timestamp=window.timestamp_start,
                    window_idx=window.window_idx,
                    severity="high",
                    threat_type="SYN Flood / DoS Burst",
                    technique_id="T1498",
                    technique_name="Network Denial of Service",
                    description=f"SYN packet ratio ({syn_ratio * 100:.1f}%) with near-zero handshake completion ({handshake_ratio * 100:.1f}%).",
                    trigger_metric=f"syn_ratio={syn_ratio:.2f}, handshake_completion={handshake_ratio:.2f}",
                    recommended_edge_action="Deploy SYN proxy / SYN cookies at ingress interface.",
                )
            )

        # 3. Privileged Authentication Port Sweep / Lateral Movement
        if auth_port_ratio >= 0.40 and (unique_ports <= 4 or packet_rate >= 15.0):
            self.alert_counter += 1
            is_critical = auth_port_ratio >= 0.70
            alerts.append(
                TriageAlert(
                    alert_id=f"EDGE-{self.alert_counter:04d}",
                    timestamp=window.timestamp_start,
                    window_idx=window.window_idx,
                    severity="critical" if is_critical else "high",
                    threat_type="Internal Lateral Movement / Auth Burst",
                    technique_id="T1021.002",
                    technique_name="SMB/Windows Admin Shares & Remote Auth",
                    description=f"Authentication port ratio surged to {auth_port_ratio * 100:.1f}% targeting administrative services (445/139/22/3389).",
                    trigger_metric=f"auth_port_ratio={auth_port_ratio:.2f}",
                    recommended_edge_action="Quarantine source host VLAN and revoke active SMB/Kerberos tickets.",
                )
            )

        return alerts
