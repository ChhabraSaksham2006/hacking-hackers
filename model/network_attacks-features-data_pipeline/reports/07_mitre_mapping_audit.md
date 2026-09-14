# 07 — MITRE ATT&CK Mapping Quality Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Audit of the Existing 5-Stage Heuristic Taxonomy

The repository collapses network security events into 5 sequential stage codes (0 through 4):
* `Stage 0`: Benign Baseline
* `Stage 1`: Reconnaissance (TA0043)
* `Stage 2`: Initial Access (TA0001) / Credential Access (TA0006)
* `Stage 3`: Lateral Movement (TA0008) / Execution (TA0002)
* `Stage 4`: Denial of Service (Impact TA0040)

### Scientific Critique:
* **Tactics vs. Stages**: In real-world cyber campaigns, MITRE ATT&CK tactics are **objectives (WHY)**, not strict temporal sequence stages. An adversary can perform DoS as a diversion before initial access, or execute brute force credential guessing across multiple hosts internally.
* **Forced Linearity**: Forcing attacks into stages 0..4 creates artificial transition expectations ($1 	o 2 	o 3 	o 4$) that do not reflect genuine multi-path cyber campaigns.

---

## 2. Discovery of Critical Silent Encoding Bug

In `data/processed_cic/windows_cic_Thursday-WorkingHours-Morning-WebAttacks.parquet`:
* **Raw Labels Present**: `Web Attack  Brute Force` (1,507), `Web Attack  XSS` (652), `Web Attack  Sql Injection` (21).
* **Assigned Stage Codes in Parquet**: **`Stage 0: 102,180` (100% Benign)**.
* **Root Cause**: In `src/cic_mapping.py`, the mapping dictionary contained string literals with `` and `-`, but the CSV was parsed with Unicode replacement characters (`�`). The dictionary lookup failed and defaulted to `return 0`.
* **Impact**: **2,180 web attack records were silently mislabeled as Benign Baseline traffic**.

---

## 3. Verified MITRE ATT&CK Forensic Mapping Hierarchy

| Observed Raw Label | Attack Family | Candidate Technique ID | Technique Name | MITRE Tactic | Mapping Confidence | Evidence / Source |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `FTP-Patator` / `FTP-BruteForce` | Credential Access | **T1110.001** | Password Guessing | Credential Access (TA0006) | **VERIFIED** | Automated port 21 dictionary authentication |
| `SSH-Patator` / `SSH-Bruteforce` | Credential Access | **T1110.001** | Password Guessing | Credential Access (TA0006) | **VERIFIED** | Automated port 22 dictionary authentication |
| `PortScan` / `portsweep` | Reconnaissance | **T1046** | Network Service Discovery | Discovery (TA0007) / Recon (TA0043) | **VERIFIED** | Systematic TCP SYN / connect scanning |
| `DoS Hulk` / `DDoS` | Denial of Service | **T1498.001** | Direct Network Flood | Impact (TA0040) | **STRONGLY_SUPPORTED** | High-volume HTTP/UDP volumetric flooding |
| `DoS slowloris` / `GoldenEye` | Application DoS | **T1499.003** | App Exhaustion Flood | Impact (TA0040) | **STRONGLY_SUPPORTED** | Connection pool & HTTP header starvation |
| `Heartbleed` | Exploitation | **T1212** | Exploitation for Credential Access | Credential Access (TA0006) | **VERIFIED** | OpenSSL TLS Heartbeat buffer over-read (CVE-2014-0160) |
| `Infiltration` | Lateral Movement | **T1210 / T1567** | Exploitation of Remote Services | Lateral Movement (TA0008) | **HEURISTIC** | Multi-stage victim compromise & payload download |
| `Bot` | C2 Communication | **T1071.001** | Web Protocols | Command and Control (TA0011) | **STRONGLY_SUPPORTED** | ARES HTTP botnet beaconing |
| `U2R-ffbconfig` / `fdformat` | Privilege Escalation | **T1068** | Exploitation for Privilege Escalation | Privilege Escalation (TA0004) | **STRONGLY_SUPPORTED** | Local buffer overflow execution on Solaris |
