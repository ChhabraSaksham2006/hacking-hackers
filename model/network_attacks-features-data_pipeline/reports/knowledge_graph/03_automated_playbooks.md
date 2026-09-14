# Automated SOC Defensive Playbooks
**SIH26153 | AI-Based Network Attack Forecasting from Network Traffic Data**
**Date:** 2026-09-12 | **Target Integration:** SIEM / SOAR / Next-Gen Firewall (Palo Alto / Fortinet / iptables)

---

## 1. Incident Response Execution Workflow

When a Stage 2 Confirmation alert is triggered with median lead time $T_{\text{lead}} \ge 20\text{s}$:

1. **T-20s (Precursor Detection):** Stage 1 High-Recall trigger detects temporal anomaly gradient ($\Delta \ge 2.0\sigma$).
2. **T-16s (Stage 2 Confirmation):** Trajectory slope and latent deviation confirm imminent onset; Incident Intelligence Card generated.
3. **T-14s (SOAR Ingestion):** SIEM/SOAR parses MITRE Technique ID and dominant feature group.
4. **T-10s (Automated Containment):** Target mitigation playbook deployed automatically before full network impact occurs.
5. **T-0s (Attack Impact Negated):** Upstream filtering drops malicious burst with zero downtime to benign traffic.

---

## 2. Playbook Catalog

### Playbook PB-01: Volumetric Flood Mitigation (`T1498`)
- **Trigger:** `volumetric_rates` attribution $> 40\%$, trajectory slope $> 0.10$.
- **Actions:**
  1. Push BGP Flowspec rule to upstream router to rate-limit destination IP to 10,000 pps.
  2. Activate edge CDN scrubbing center for Layer 7 HTTP flood inspection.
  3. Notify Tier-2 SOC with real-time XAI telemetry card.

### Playbook PB-02: Port Scan & Reconnaissance Isolation (`T1046`)
- **Trigger:** `port_entropy_scanners` attribution $> 50\%$, unique destination ports spike.
- **Actions:**
  1. Insert temporary iptables drop rule for offending source subnet `/24`.
  2. Isolate internal targets into protected micro-segmentation VLAN.
  3. Capture full packet PCAP on switch port mirror for forensic logging.

### Playbook PB-03: Brute-Force Authentication Lockout (`T1110`)
- **Trigger:** `auth_port_ratio` elevation $> 3.0\sigma$, TCP handshake reset surge.
- **Actions:**
  1. Execute API call to fail2ban daemon to block source IP on ports 21/22/3389 for 3600 seconds.
  2. Check directory service for brute-force targeted usernames and enable step-up MFA.
