# 01 — Dataset Summary & Chronological Partitions

| Split | Capture Days Included | Flow Count | Total Windows | Attack Rate | Dominant Attack Families Present |
|---|---|---|---|---|---|
| **TRAIN** | Feb 14, Feb 15, Feb 16, Feb 21, Feb 22 | ~5.8M | 101,845 | 10.80% | FTP/SSH-BruteForce, DoS-GoldenEye/Slowloris/Hulk/SlowHTTPTest, DDoS-LOIC-HTTP |
| **VAL** | Feb 23 | ~1.0M | 21,536 | 5.99% | Brute Force -Web, Brute Force -XSS, SQL Injection |
| **TEST** | Feb 28, Mar 01, Mar 02 | ~1.5M | 64,608 | 29.12% | **Infiltration** (Dropbox exploit, portscan), **Botnet** (ARES C2 Ares botnet) |
| **Total** | 9 Canonical Capture Days | 8.28M | 188,520 | 16.51% | Complete CSE-CIC-IDS2018 Attack Taxonomy |

### Interpretation

The dataset partitioning follows a strict chronological split across real capture dates. Crucially, the Test split contains 100% Out-Of-Distribution (OOD) attack families (Infiltration and Botnet) that never appear in either the Training or Validation splits. Models evaluated on Test cannot rely on memorized signatures or specific IP addresses, providing a rigorous test of generalized early warning capabilities.
