# Chronological Split & Leakage Audit
## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
**Phase:** 5.5 | **Date:** 2026-09-08

---

### 1. Split Design Strategy
To ensure zero lookahead and zero data leakage:
1. **Temporal Chronological Ordering:** Models are trained strictly on calendar days occurring *before* the validation day, and evaluated on calendar days occurring *after* the validation day.
   - Train Days (Feb 14 – Feb 22, 2018): Days 1–5
   - Validation Day (Feb 23, 2018): Day 6 (Held-out tuning set)
   - Test Days (Feb 28 – Mar 02, 2018): Days 7–9 (Unseen evaluation set)
2. **Boundary Isolation:** No sequence crosses a day boundary. Each session's sliding windows begin at index 0 and terminate at `len(df) - 1 - K_max`.
3. **Leakage-Free Feature Scaling:** The `StandardScaler` is fitted *strictly* on training session features ($N=101,845$). Validation and Test vectors are transformed using frozen train moments ($\mu_{\text{train}}, \sigma_{\text{train}}$).
4. **Threshold Selection Separation:** Decision thresholds are selected *exclusively* on validation split distributions. Test sets are evaluated with frozen validation thresholds.

### 2. Attack Family & OOD Distribution Across Splits

| Split | Sessions | Total Seqs | Attack Seqs | Attack Rate | Attack Families Present | OOD Status |
|---|---|---|---|---|---|---|
| **TRAIN** | 5 | 101,845 | 11,001 | 10.8% | BruteForce (FTP, SSH), DoS (GoldenEye, Slowloris, SlowHTTPTest, Hulk), DDoS (LOIC-UDP, HOIC), WebAttack (partial) | In-Distribution Base |
| **VAL** | 1 | 21,536 | 1,289 | 6.0% | WebAttack (Brute Force - Web, Brute Force - XSS, SQL Injection) | In-Distribution Tuning |
| **TEST** | 3 | 64,608 | 18,815 | 29.1% | **Infiltration** (Feb 28, Mar 01), **Botnet** (Mar 02) | **Out-Of-Distribution (OOD)** |

### 3. Key Findings on OOD Evaluation
The test set features attack families that **never appear in the training split**:
- **Infiltration:** Multi-hour internal scanning and exploitation.
- **Botnet (ARES):** Multi-hour continuous communication and control traffic running through all of Friday March 02.

This explains why test set attack prevalence jumps to 29.1% and why models face genuine domain shifts during test evaluation.
