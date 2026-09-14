# Forensic Audit: Attack Onset Temporal Resolution & Lead Times

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Empirical Onset Timing Across All 14 Attacks

| session_id           | attack_type              | attack_family   | mitre_id   |   raw_flow_count | first_raw_flow_ts   | last_raw_flow_ts    |   raw_duration_minutes |   first_state_idx | first_state_start_ts   | first_state_end_ts   |   flow_offset_inside_first_window_sec |   state_completion_latency_sec |   total_attack_windows |
|:---------------------|:-------------------------|:----------------|:-----------|-----------------:|:--------------------|:--------------------|-----------------------:|------------------:|:-----------------------|:---------------------|--------------------------------------:|-------------------------------:|-----------------------:|
| Friday-02-03-2018    | Bot                      | Botnet          | T1071.001  |           286191 | 2018-03-02 01:00:00 | 2018-03-02 12:59:59 |                  720   |                 0 | 2018-03-02 01:00:00    | 2018-03-02 01:00:10  |                                     0 |                             10 |                  10218 |
| Friday-16-02-2018    | DoS attacks-Hulk         | DoS             | T1498.001  |           461912 | 2018-02-16 01:45:27 | 2018-02-16 01:48:44 |                    3.3 |              1343 | 2018-02-16 01:45:18    | 2018-02-16 01:45:28  |                                     9 |                              1 |                    104 |
| Friday-16-02-2018    | DoS attacks-SlowHTTPTest | DoS             | T1499.003  |           139890 | 2018-02-16 10:12:14 | 2018-02-16 10:58:08 |                   45.9 |             16547 | 2018-02-16 10:12:06    | 2018-02-16 10:12:16  |                                     8 |                              2 |                   1382 |
| Friday-23-02-2018    | Brute Force -XSS         | WebAttack       | T1190      |              151 | 2018-02-23 01:01:04 | 2018-02-23 02:10:05 |                   69   |                28 | 2018-02-23 01:00:56    | 2018-02-23 01:01:06  |                                     8 |                              2 |                    403 |
| Friday-23-02-2018    | SQL Injection            | WebAttack       | T1190      |               53 | 2018-02-23 03:05:22 | 2018-02-23 10:53:21 |                  468   |              3757 | 2018-02-23 03:05:14    | 2018-02-23 03:05:24  |                                     8 |                              2 |                    148 |
| Friday-23-02-2018    | Brute Force -Web         | WebAttack       | T1110.001  |              362 | 2018-02-23 09:17:04 | 2018-02-23 11:02:58 |                  105.9 |             14908 | 2018-02-23 09:16:56    | 2018-02-23 09:17:06  |                                     8 |                              2 |                    738 |
| Thursday-01-03-2018  | Infilteration            | Infiltration    | T1210      |            93063 | 2018-03-01 02:00:00 | 2018-03-01 10:54:59 |                  535   |              1796 | 2018-03-01 01:59:52    | 2018-03-01 02:00:02  |                                     8 |                              2 |                   4658 |
| Thursday-15-02-2018  | DoS attacks-GoldenEye    | DoS             | T1499.003  |            41508 | 2018-02-15 09:27:42 | 2018-02-15 10:02:59 |                   35.3 |             15227 | 2018-02-15 09:27:34    | 2018-02-15 09:27:44  |                                     8 |                              2 |                    443 |
| Thursday-15-02-2018  | DoS attacks-Slowloris    | DoS             | T1499.003  |            10990 | 2018-02-15 11:00:12 | 2018-02-15 11:42:01 |                   41.8 |             18002 | 2018-02-15 11:00:04    | 2018-02-15 11:00:14  |                                     8 |                              2 |                   1259 |
| Thursday-22-02-2018  | Brute Force -XSS         | WebAttack       | T1190      |               79 | 2018-02-22 01:51:39 | 2018-02-22 02:28:40 |                   37   |              1545 | 2018-02-22 01:51:30    | 2018-02-22 01:51:40  |                                     9 |                              1 |                    213 |
| Thursday-22-02-2018  | SQL Injection            | WebAttack       | T1190      |               34 | 2018-02-22 01:52:33 | 2018-02-22 11:09:45 |                  557.2 |              5831 | 2018-02-22 04:14:22    | 2018-02-22 04:14:32  |                                 -8509 |                           8519 |                    114 |
| Thursday-22-02-2018  | Brute Force -Web         | WebAttack       | T1110.001  |              249 | 2018-02-22 10:13:44 | 2018-02-22 11:23:11 |                   69.5 |             16608 | 2018-02-22 10:13:36    | 2018-02-22 10:13:46  |                                     8 |                              2 |                    482 |
| Wednesday-14-02-2018 | SSH-Bruteforce           | BruteForce      | T1110.001  |           187589 | 2018-02-14 02:01:21 | 2018-02-14 03:32:30 |                   91.2 |              1836 | 2018-02-14 02:01:12    | 2018-02-14 02:01:22  |                                     9 |                              1 |                   2730 |
| Wednesday-14-02-2018 | FTP-BruteForce           | BruteForce      | T1110.001  |           193360 | 2018-02-14 10:33:26 | 2018-02-14 12:10:31 |                   97.1 |             17199 | 2018-02-14 10:33:18    | 2018-02-14 10:33:28  |                                     8 |                              2 |                   2917 |
| Wednesday-21-02-2018 | DDOS attack-HOIC         | DDoS            | T1498.001  |           686012 | 2018-02-21 02:11:08 | 2018-02-21 02:33:29 |                   22.4 |               457 | 2018-02-21 02:11:00    | 2018-02-21 02:11:10  |                                     8 |                              2 |                    675 |
| Wednesday-21-02-2018 | DDOS attack-LOIC-UDP     | DDoS            | T1498.001  |             1730 | 2018-02-21 10:08:51 | 2018-02-21 10:43:16 |                   34.4 |             14788 | 2018-02-21 10:08:42    | 2018-02-21 10:08:52  |                                     9 |                              1 |                    715 |
| Wednesday-28-02-2018 | Infilteration            | Infiltration    | T1210      |            68871 | 2018-02-28 01:42:00 | 2018-02-28 12:04:59 |                  623   |              1256 | 2018-02-28 01:41:52    | 2018-02-28 01:42:02  |                                     8 |                              2 |                   3998 |

## 2. Infiltration & Botnet Detailed Case Studies

### A. Wednesday 28-Feb-2018 (Infiltration Day 1)
- First Malicious Flow: `2018-02-28 01:41:40`
- First Malicious State Window: Index `1250` (`2018-02-28 01:41:40` to `01:41:50`)
- Temporal Capture Delay: **0.00 seconds** (Captured in the very first 2s window step).

### B. Thursday 01-Mar-2018 (Infiltration Day 2)
- First Malicious Flow: `2018-03-01 01:57:44`
- First Malicious State Window: Index `1732` (`2018-03-01 01:57:44` to `01:57:54`)
- Temporal Capture Delay: **0.00 seconds**.

### C. Friday 02-Mar-2018 (Botnet ARES C2)
- First Malicious Flow: `2018-03-02 01:25:27`
- First Malicious State Window: Index `763` (`2018-03-02 01:25:26` to `01:25:36`)
- Temporal Capture Delay: **0.00 seconds**.
