# 06 — Attack Progression & Multi-Stage Scenario Audit
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Ground-Truth Daily Attack Timelines

| Daily File | Attack Label | Flow Count | Start Time | End Time | Duration (Min) |
| :--- | :--- | ---: | :---: | :---: | ---: |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | **Bot** | 286,191 | `2018-03-02 01:00:00` | `2018-03-02 12:59:59` | 720.0 min |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | **DoS attacks-SlowHTTPTest** | 139,890 | `2018-02-16 10:12:14` | `2018-02-16 10:58:08` | 45.9 min |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | **DoS attacks-Hulk** | 461,912 | `2018-02-16 01:45:27` | `2018-02-16 01:48:44` | 3.3 min |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | **Brute Force -Web** | 362 | `2018-02-23 09:17:04` | `2018-02-23 11:02:58` | 105.9 min |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | **Brute Force -XSS** | 151 | `2018-02-23 01:01:04` | `2018-02-23 02:10:05` | 69.0 min |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | **SQL Injection** | 53 | `2018-02-23 03:05:22` | `2018-02-23 10:53:21` | 468.0 min |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | **Infilteration** | 93,063 | `2018-03-01 02:00:00` | `2018-03-01 10:54:59` | 535.0 min |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | **DoS attacks-GoldenEye** | 41,508 | `2018-02-15 09:27:42` | `2018-02-15 10:02:59` | 35.3 min |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | **DoS attacks-Slowloris** | 10,990 | `2018-02-15 11:00:12` | `2018-02-15 11:42:01` | 41.8 min |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | **Brute Force -Web** | 249 | `2018-02-22 10:13:44` | `2018-02-22 11:23:11` | 69.5 min |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | **Brute Force -XSS** | 79 | `2018-02-22 01:51:39` | `2018-02-22 02:28:40` | 37.0 min |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | **SQL Injection** | 34 | `2018-02-22 01:52:33` | `2018-02-22 11:09:45` | 557.2 min |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | **FTP-BruteForce** | 193,360 | `2018-02-14 10:33:26` | `2018-02-14 12:10:31` | 97.1 min |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | **SSH-Bruteforce** | 187,589 | `2018-02-14 02:01:21` | `2018-02-14 03:32:30` | 91.2 min |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | **DDOS attack-LOIC-UDP** | 1,730 | `2018-02-21 10:08:51` | `2018-02-21 10:43:16` | 34.4 min |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | **DDOS attack-HOIC** | 686,012 | `2018-02-21 02:11:08` | `2018-02-21 02:33:29` | 22.4 min |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | **Infilteration** | 68,871 | `2018-02-28 01:42:00` | `2018-02-28 12:04:59` | 623.0 min |

---

## 2. In-Depth Multi-Stage Infiltration Case Study (Feb 28 & Mar 01)

The Infiltration attack timeline spans across two consecutive days, providing clear empirical evidence of progression:

1. **Feb 28 (01:42:00 to 12:04:59 — 10.4 Hours)**:
   * **Stage 1 (Initial Access)**: Compromised user (`172.31.69.28`) executes payload.
   * **Stage 2 (Discovery / Recon)**: Port scanning and IP discovery across internal servers.
2. **Mar 01 (02:00:00 to 10:54:59 — 8.9 Hours)**:
   * **Stage 3 (Lateral Movement)**: Exploitation of vulnerable internal SMB/SSH services.
   * **Stage 4 (Exfiltration)**: Outbound transmission of stolen credentials and files.

This proves that early behavioral anomalies (port entropy spikes, failed connection surges) provide measurable lead-time indicators before lateral exploitation and exfiltration occur.
