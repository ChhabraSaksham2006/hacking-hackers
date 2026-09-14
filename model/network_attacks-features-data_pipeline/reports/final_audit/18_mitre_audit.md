# 18 — MITRE ATT&CK Mapping Audit

## 1. Master MITRE ATT&CK Taxonomy Mapping

Source metadata: `data/metadata/mitre_mapping.csv`.

| Observed Dataset Behavior | Dataset Label | MITRE Technique ID | MITRE Technique Name | Mapping Confidence | Evidence Source | MITRE Tactic |
|---|---|---|---|---|---|---|
| High-frequency auth attempts (Port 21) | `FTP-BruteForce` | `T1110.001` | Brute Force: Password Guessing | **VERIFIED (HIGH)** | Official documentation / Patator tool | Credential Access (TA0006) |
| High-frequency auth attempts (Port 22) | `SSH-Bruteforce` | `T1110.001` | Brute Force: Password Guessing | **VERIFIED (HIGH)** | Official documentation / Patator tool | Credential Access (TA0006) |
| Automated HTTP POST brute force | `Brute Force -Web` | `T1110.001` | Brute Force: Password Guessing | **VERIFIED (HIGH)** | Hydra web login attempts | Credential Access (TA0006) |
| Stored / Reflected Cross-Site Scripting | `Brute Force -XSS`| `T1190` | Exploit Public-Facing App | **STRONGLY SUPPORTED** | XSS scripts in HTTP payload | Initial Access (TA0001) |
| SQL injection payloads | `SQL Injection` | `T1190` | Exploit Public-Facing App | **STRONGLY SUPPORTED** | SQL syntax injection in parameters | Initial Access (TA0001) |
| Slow incomplete HTTP request headers | `DoS attacks-Slowloris` | `T1499.003` | Endpoint DoS: App Exhaustion | **STRONGLY SUPPORTED** | Slowloris header starvation | Impact (TA0040) |
| Slow HTTP POST request body | `DoS attacks-SlowHTTPTest` | `T1499.003` | Endpoint DoS: App Exhaustion | **STRONGLY SUPPORTED** | SlowHTTPTest keep-alive starvation| Impact (TA0040) |
| High-volume HTTP request flood | `DoS attacks-Hulk` | `T1498.001` | Network DoS: Direct Flood | **STRONGLY SUPPORTED** | Hulk multi-threaded HTTP flood | Impact (TA0040) |
| Keep-Alive / No-Cache HTTP flood | `DoS attacks-GoldenEye` | `T1499.003` | Endpoint DoS: App Exhaustion | **STRONGLY SUPPORTED** | GoldenEye connection exhaustion | Impact (TA0040) |
| Volumetric UDP packet flood | `DDOS attack-LOIC-UDP` | `T1498.001` | Network DoS: Direct Flood | **STRONGLY SUPPORTED** | LOIC UDP packet storm | Impact (TA0040) |
| High-Orbit Ion Cannon HTTP flood | `DDOS attack-HOIC` | `T1498.001` | Network DoS: Direct Flood | **STRONGLY SUPPORTED** | HOIC booster volumetric flood | Impact (TA0040) |
| Internal foothold & lateral movement | `Infilteration` | `T1210 / T1567` | Exploitation of Remote Services | **HEURISTIC (MEDIUM)**| Multi-stage Dropbox payload | Lateral Movement (TA0008) |
| ARES Botnet C2 beaconing | `Bot` | `T1071.001` | App Layer Protocol: Web | **STRONGLY SUPPORTED** | Periodic HTTP C2 beaconing | Command & Control (TA0011)|

## 2. Research Guidelines Regarding MITRE Ground Truth

> [!WARNING]
> MITRE ATT&CK labels are post-hoc expert behavioral mappings of documented dataset scenarios. They are NOT raw ground-truth packet headers. MITRE classification should be treated as an interpretability layer, not as an intrinsic physical network label.
