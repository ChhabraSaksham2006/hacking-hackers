# 16 — Event-Level Forensic Breakdown on Out-of-Distribution Test Episodes

| Event ID | Target Session Day | Ground Truth Attack Family | Specific Attack Label | Onset Window Index | Raw Threshold Detection | Tier 1 (10s Cooldown) Detection | Champion Aggregator Detection | Primary Attributed MITRE Technique | Lead Time Recorded |
|---|---|---|---|---|---|---|---|---|---|
| `EV_TEST_01` | Wednesday-28-02-2018 | Infiltration | Infilteration | 1,256 | **DETECTED** | **DETECTED** | Missed | T1071 (C2 Protocol) | 20.0s |
| `EV_TEST_02` | Thursday-01-03-2018 | Infiltration | Infilteration | 16,106 | **DETECTED** | **DETECTED** | Missed | T1071 (C2 Protocol) | 20.0s |
| `EV_TEST_03` | Thursday-01-03-2018 | Infiltration | Infilteration | 20,404 | **DETECTED** | **DETECTED** | Missed | T1071 (C2 Protocol) | 20.0s |
| `EV_TEST_04` | Thursday-01-03-2018 | Infiltration | Infilteration | 21,559 | **DETECTED** | **DETECTED** | Missed | T1071 (C2 Protocol) | 20.0s |
| `EV_TEST_05` | Friday-02-03-2018 | Botnet | Botnet Ares | 5,241 | **DETECTED** | **DETECTED** | **DETECTED** | T1071 (C2 Protocol) | 5.0s |
| `EV_TEST_06` | Friday-02-03-2018 | Botnet | Botnet Ares | 16,600 | **DETECTED** | **DETECTED** | Missed | T1110 (Brute Force) | 20.0s |
| `EV_TEST_07` | Friday-02-03-2018 | Botnet | Botnet Ares | 20,205 | **DETECTED** | **DETECTED** | **DETECTED** | T1071 (C2 Protocol) | 5.0s |
| **Total** | — | — | — | — | **7 / 7 (100.0%)**| **7 / 7 (100.0%)**| **2 / 7 (28.57%)** | — | **14.0s - 20.0s** |

### Interpretation

This event-by-event breakdown provides critical architectural insight: Raw thresholding and Tier 1 (10s cooldown) successfully detect all 7 out-of-distribution test attack episodes. However, the aggressive champion aggregator (2-consecutive + 60s cooldown) only retains Botnet episodes (2/7), missing Infiltration. This occurs because Infiltration manifests as brief, subtle precursor probing that does not maintain 2 consecutive windows above threshold.
