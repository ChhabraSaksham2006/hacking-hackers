"""
mitre_attack_graph.py
=====================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Enterprise MITRE ATT&CK Knowledge Graph Mapping Engine.
Connects network telemetry precursors to MITRE ATT&CK Tactics, Techniques,
and Automated SOC Defensive Playbooks.
"""

from __future__ import annotations
import json
from typing import Dict, List, Tuple, Optional, Any


MITRE_KNOWLEDGE_BASE = {
    "PortScan": {
        "precursor_id": "PP_PORT_SCAN_SWEEP",
        "precursor_name": "Rapid Multi-Port Connection Probing",
        "primary_feature_group": "port_entropy_scanners",
        "diagnostic_features": ["dst_port_entropy", "unique_dst_ports", "delta_dst_port_entropy", "syn_ratio"],
        "mitre_tactic_id": "TA0043",
        "mitre_tactic_name": "Reconnaissance",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "technique_description": "Adversaries attempt to discover available services by sweeping IP addresses and port ranges.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Apply dynamic firewall ACL to rate-limit unauthenticated SYN requests and drop source IP subnets exceeding 50 connection attempts/sec."
            },
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "action": "Engage IPS port-scan threshold filter and isolate probing host into quarantine VLAN."
            }
        ]
    },
    "DoS Hulk": {
        "precursor_id": "PP_HTTP_FLOOD_VOLUMETRIC",
        "precursor_name": "Asymmetric HTTP Packet Rate Spike",
        "primary_feature_group": "volumetric_rates",
        "diagnostic_features": ["packet_rate", "byte_rate", "delta_packet_rate", "fwd_packet_ratio"],
        "mitre_tactic_id": "TA0040",
        "mitre_tactic_name": "Impact",
        "mitre_technique_id": "T1498.001",
        "mitre_technique_name": "Network Denial of Service: Direct Network Flood",
        "technique_description": "Adversaries flood the targeted network service with high-rate requests to exhaust network bandwidth and connection slots.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Enable upstream BGP Flowspec rate-limiting on target HTTP endpoints and activate CDN DDoS mitigation scrubbing center."
            },
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "action": "Trigger SYN proxy challenge and enforce strict TCP connection timeout window reduction."
            }
        ]
    },
    "DoS GoldenEye": {
        "precursor_id": "PP_SLOW_HTTP_EXHAUSTION",
        "precursor_name": "High Lifetime Connection Starvation",
        "primary_feature_group": "flow_timing_iat",
        "diagnostic_features": ["active_connection_lifetime_mean", "flow_iat_mean", "zero_payload_ratio"],
        "mitre_tactic_id": "TA0040",
        "mitre_tactic_name": "Impact",
        "mitre_technique_id": "T1499.003",
        "mitre_technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
        "technique_description": "Adversaries maintain slow concurrent HTTP connections to hold server socket pools open until the web service becomes unresponsive.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Configure reverse-proxy request header timeout (< 5 seconds) and enforce minimum data transfer rate per connection."
            },
            {
                "mitigation_id": "M1030",
                "name": "Network Segmentation",
                "action": "Isolate compromised ingress load balancer nodes and spawn auto-scaling container replicas."
            }
        ]
    },
    "DDoS LOIC": {
        "precursor_id": "PP_DISTRIBUTED_SYN_UDP_FLOOD",
        "precursor_name": "Coordinated Volumetric Traffic Surge",
        "primary_feature_group": "volumetric_rates",
        "diagnostic_features": ["total_packets", "total_ip_bytes", "syn_count", "delta_flow_rate"],
        "mitre_tactic_id": "TA0040",
        "mitre_tactic_name": "Impact",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "technique_description": "Distributed denial-of-service attack generating coordinated multi-source flooding against network infrastructure.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Activate upstream Tier-1 ISP Anycast scrubbing and route suspect CIDRs into Blackhole null-routes."
            },
            {
                "mitigation_id": "M1036",
                "name": "Account Use Policies",
                "action": "Alert SOC on-call engineer and execute automated DDoS incident runbook playbook."
            }
        ]
    },
    "SSH-Patator": {
        "precursor_id": "PP_SSH_BRUTE_FORCE_BURST",
        "precursor_name": "Repetitive Auth Port Connection Cycling",
        "primary_feature_group": "port_entropy_scanners",
        "diagnostic_features": ["auth_port_ratio", "syn_ratio", "rst_count", "delta_auth_port_ratio"],
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "technique_description": "Adversaries systematically submit passwords against SSH service port 22 until an authentication succeeds.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1036",
                "name": "Account Use Policies",
                "action": "Trigger fail2ban automated IP ban (1 hour) on offending source address exceeding 5 failed attempts in 30s."
            },
            {
                "mitigation_id": "M1032",
                "name": "Multi-factor Authentication",
                "action": "Enforce mandatory SSH key-pair authentication and disable password-based login."
            }
        ]
    },
    "FTP-Patator": {
        "precursor_id": "PP_FTP_BRUTE_FORCE_BURST",
        "precursor_name": "Repetitive FTP Auth Connection Cycling",
        "primary_feature_group": "port_entropy_scanners",
        "diagnostic_features": ["auth_port_ratio", "syn_count", "rst_to_syn_ratio"],
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "technique_description": "Adversaries attempt credential guessing against FTP service port 21.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1036",
                "name": "Account Use Policies",
                "action": "Enforce temporary IP lockouts on port 21 and mandate TLS/SFTP migration."
            }
        ]
    },
    "Web Attack": {
        "precursor_id": "PP_WEB_APPLICATION_PROBE",
        "precursor_name": "Malformed Payload Injection Sequence",
        "primary_feature_group": "packet_size_dynamics",
        "diagnostic_features": ["pkt_len_mean", "zero_payload_ratio", "fwd_byte_ratio", "psh_count"],
        "mitre_tactic_id": "TA0001",
        "mitre_tactic_name": "Initial Access",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "technique_description": "Adversaries attempt SQL Injection, Cross-Site Scripting, or Command Injection via public HTTP interfaces.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1050",
                "name": "Exploit Protection",
                "action": "Engage Web Application Firewall (WAF) OWASP Core Rule Set in blocking mode."
            },
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Block offending source IP at reverse proxy layer and inspect URI payload tokens."
            }
        ]
    },
    "Infiltration": {
        "precursor_id": "PP_COMMAND_AND_CONTROL_BEACON",
        "precursor_name": "Periodic Low-Volume Beaconing",
        "primary_feature_group": "flow_timing_iat",
        "diagnostic_features": ["flow_iat_std", "flow_iat_mean", "packet_rate", "tcp_ratio"],
        "mitre_tactic_id": "TA0011",
        "mitre_tactic_name": "Command and Control",
        "mitre_technique_id": "T1071.001",
        "mitre_technique_name": "Application Layer Protocol: Web Protocols",
        "technique_description": "Adversaries communicate with compromised hosts using periodic beaconing over standard web channels.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "action": "Perform Deep Packet Inspection (DPI) on suspicious C2 beaconing intervals and sever active TCP sockets."
            }
        ]
    },
    "Heartbleed": {
        "precursor_id": "PP_TLS_OVERSIZED_PROBE",
        "precursor_name": "Oversized TLS Heartbeat Request",
        "primary_feature_group": "packet_size_dynamics",
        "diagnostic_features": ["pkt_len_max", "down_up_ratio_mean", "psh_count"],
        "mitre_tactic_id": "TA0001",
        "mitre_tactic_name": "Initial Access",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "technique_description": "Adversaries exploit OpenSSL TLS heartbeat buffer over-read (CVE-2014-0160) to exfiltrate memory data.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1051",
                "name": "Update Software",
                "action": "Verify OpenSSL version is patched and disable TLS heartbeat extensions at load balancer."
            }
        ]
    },
    "Botnet": {
        "precursor_id": "PP_BOTNET_COMM_COORDINATION",
        "precursor_name": "Synchronized Distributed Socket Activity",
        "primary_feature_group": "protocol_composition",
        "diagnostic_features": ["udp_ratio", "flow_count", "rst_ratio", "delta_flow_count"],
        "mitre_tactic_id": "TA0011",
        "mitre_tactic_name": "Command and Control",
        "mitre_technique_id": "T1071",
        "mitre_technique_name": "Application Layer Protocol",
        "technique_description": "Adversaries coordinate compromised bots for botnet propagation and centralized command execution.",
        "recommended_mitigations": [
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "action": "Sinkhole rogue DNS domain queries and isolate internal endpoint infected nodes."
            }
        ]
    }
}


class MITREKnowledgeGraph:
    """
    Query and mapping engine for MITRE ATT&CK Knowledge Graph.
    """
    def __init__(self):
        self.kb = MITRE_KNOWLEDGE_BASE

    def get_attack_mapping(self, attack_name: str) -> Dict[str, Any]:
        """
        Retrieves MITRE ATT&CK entity mapping for an attack family.
        """
        for key, entry in self.kb.items():
            if key.lower() in attack_name.lower() or attack_name.lower() in key.lower():
                return entry
                
        # Default generic mapping if unmapped
        return {
            "precursor_id": "PP_GENERIC_ANOMALY",
            "precursor_name": "General Telemetry Anomaly",
            "primary_feature_group": "volumetric_rates",
            "diagnostic_features": ["flow_rate", "packet_rate"],
            "mitre_tactic_id": "TA0040",
            "mitre_tactic_name": "Impact",
            "mitre_technique_id": "T1498",
            "mitre_technique_name": "Network Denial of Service",
            "technique_description": "Unclassified network anomaly with high likelihood of service degradation.",
            "recommended_mitigations": [
                {
                    "mitigation_id": "M1037",
                    "name": "Filter Network Traffic",
                    "action": "Apply dynamic bandwidth throttling on affected segment."
                }
            ]
        }
