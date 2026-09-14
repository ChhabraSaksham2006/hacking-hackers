"""
MITRE ATT&CK Stage Mapping Module — Updated with DoS Stage

Stage Codes:
- 0: Benign (Normal Operation)
- 1: Reconnaissance / Discovery (TA0043 / TA0007)
- 2: Initial Access / Credential Access (TA0001 / TA0006)
- 3: Lateral Movement / Execution (TA0008 / TA0002)
- 4: Denial of Service / Impact (TA0040)
"""

from typing import Union

STAGE_NAMES = {
    0: "Benign",
    1: "Reconnaissance",
    2: "Initial Access",
    3: "Lateral Movement / Execution",
    4: "Denial of Service"
}

STAGE_MITRE_TACTICS = {
    0: "None (Normal Operation)",
    1: "Reconnaissance (TA0043) / Discovery (TA0007)",
    2: "Initial Access (TA0001) / Credential Access (TA0006)",
    3: "Lateral Movement (TA0008) / Execution (TA0002)",
    4: "Impact (TA0040) — Network Denial of Service (T1498)"
}

ATTACK_TO_STAGE = {
    # Benign
    "-": 0,
    "benign": 0,
    "normal": 0,
    "none": 0,

    # Stage 1 — Reconnaissance / Discovery
    "port-scan": 1,
    "port_scan": 1,
    "ping-sweep": 1,
    "ping_sweep": 1,
    "ipsweep": 1,
    "portsweep": 1,
    "nmap": 1,
    "satan": 1,
    "saint": 1,
    "mscan": 1,

    # Stage 2 — Initial Access / Credential Access
    "guess": 2,
    "phf": 2,
    "dictionary": 2,
    "dict": 2,
    "dict_simple": 2,
    "ftp-write": 2,
    "ftp_write": 2,
    "imap": 2,
    "named": 2,
    "sendmail": 2,
    "ssh-bruteforce": 2,
    "ftp-bruteforce": 2,

    # Stage 3 — Lateral Movement / Execution
    "rsh": 3,
    "rlogin": 3,
    "rcp": 3,
    "exec": 3,
    "buffer_overflow": 3,
    "loadmodule": 3,
    "load_clear": 3,
    "perl": 3,
    "perl_clear": 3,
    "rootkit": 3,
    "ps": 3,
    "eject": 3,
    "fdformat": 3,
    "format_clear": 3,
    "ffbconfig": 3,
    "ffb_clear": 3,
    "xterm": 3,

    # Stage 4 — Denial of Service / Impact
    "neptune": 4,       # TCP SYN flood
    "smurf": 4,         # ICMP echo reply amplification flood
    "teardrop": 4,      # Malformed UDP fragment crash
    "pod": 4,           # Ping of Death (oversized ICMP)
    "land": 4,          # TCP SYN with spoofed src=dst
    "back": 4,          # Apache DoS via malformed requests
    "apache2": 4,
    "udpstorm": 4,
    "processtable": 4,
    "mailbomb": 4,
}

def get_mitre_stage_code(attack_name: Union[str, float, None]) -> int:
    """Return numeric stage code for a given attack name."""
    if attack_name is None:
        return 0
    attack_clean = str(attack_name).strip().lower()
    if attack_clean in ["", "-", "0", "nan"]:
        return 0
    return ATTACK_TO_STAGE.get(attack_clean, 0)

def get_mitre_stage_name(stage_code: int) -> str:
    return STAGE_NAMES.get(stage_code, "Unknown")

def get_mitre_tactic(stage_code: int) -> str:
    return STAGE_MITRE_TACTICS.get(stage_code, "Unknown")
