"""
CIC-IDS2017 to MITRE ATT&CK Stage Mapping Taxonomy

Maps all 15 attack classes in CIC-IDS2017 into the 5 MITRE ATT&CK Kill-Chain Stages:
  Stage 0: Benign (Normal background traffic)
  Stage 1: Reconnaissance (PortScan, IP sweep, service enumeration)
  Stage 2: Initial Access (Brute force: SSH, FTP, Web authentication)
  Stage 3: Lateral Movement / Exploits / Execution (Infiltration, SQLi, XSS, Heartbleed, Bot)
  Stage 4: Denial of Service (DoS Hulk, DDoS, GoldenEye, Slowloris, Slowhttptest)
"""

from typing import Dict

# Detailed human-readable mapping from raw CIC label to MITRE ATT&CK Kill Chain Stage
CIC_LABEL_TO_STAGE: Dict[str, int] = {
    # ── Stage 0: Benign Baseline ─────────────────────────────────────────────
    "BENIGN": 0,

    # ── Stage 1: Reconnaissance (TA0043) ────────────────────────────────────
    # Active scanning, port probing, host discovery
    "PortScan": 1,

    # ── Stage 2: Initial Access & Credential Access (TA0001, TA0006) ────────
    # Brute-force credential guessing to gain an initial foothold
    "FTP-Patator": 2,
    "SSH-Patator": 2,
    "Web Attack \x96 Brute Force": 2,
    "Web Attack - Brute Force": 2,

    # ── Stage 3: Lateral Movement, Exploitation & Execution (TA0002, TA0008) ─
    # Exploitation of vulnerabilities, internal infiltration, botnet commands
    "Infiltration": 3,
    "Web Attack \x96 Sql Injection": 3,
    "Web Attack - Sql Injection": 3,
    "Web Attack \x96 XSS": 3,
    "Web Attack - XSS": 3,
    "Heartbleed": 3,
    "Bot": 3,

    # ── Stage 4: Denial of Service & Impact (TA0040) ─────────────────────────
    # Volumetric and resource-exhaustion attacks
    "DoS Hulk": 4,
    "DDoS": 4,
    "DoS GoldenEye": 4,
    "DoS slowloris": 4,
    "DoS Slowhttptest": 4,
}

STAGE_NAMES_CIC: Dict[int, str] = {
    0: "Benign Baseline",
    1: "Reconnaissance (PortScan)",
    2: "Initial Access (SSH/FTP/Web Brute-Force)",
    3: "Lateral Movement & Exploits (SQLi/XSS/Infiltration/Bot)",
    4: "Denial of Service (DoS/DDoS/Slowloris/Hulk)"
}


def map_cic_label_to_stage(label_str: str) -> int:
    """Safely maps raw string label to MITRE stage code (0..4)."""
    clean_label = str(label_str).strip()
    if clean_label in CIC_LABEL_TO_STAGE:
        return CIC_LABEL_TO_STAGE[clean_label]
    # Fallback for encoding discrepancies
    for k, v in CIC_LABEL_TO_STAGE.items():
        if k.lower() in clean_label.lower():
            return v
    return 0  # Default to benign if unrecognized
