# Data Split & Benchmark Partitioning Protocol

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Episode-Aware, Chronological Partitioning for Settings A, B, and C**

---

## 1. Core Principles of Split Construction

1. **No Episode Fragmentation:** An attack episode $\mathcal{E}_j$ belongs entirely to one split. Windows from the same attack episode never appear in both training and test sets.
2. **Chronological Ordering:** Where multiple episodes of the same attack family exist on a capture day, the earliest 70% of episodes are assigned to Training, and the latest 30% are assigned to Testing.
3. **No Normalization Leakage:** All `StandardScaler` transformations are fitted strictly on the designated Training split.
4. **No Threshold Leakage:** Decision thresholds are calibrated strictly on designated Validation splits.

---

## 2. Specification of the Three Benchmark Settings

```
                                  CSE-CIC-IDS2018 (373 Attack Episodes)
                                                    │
                   ┌────────────────────────────────┼────────────────────────────────┐
                   ▼                                ▼                                ▼
      [SETTING A: SEEN ATTACKS]         [SETTING B: MIXED GENERALIZATION]   [SETTING C: STRICT OOD / ZERO-DAY]
      • Goal: Measure known precursor   • Goal: Measure enterprise triage   • Goal: Measure zero-day onset
        learning capability.              on mixed threat traffic.            generalization.
      • Train: First 70% of episodes    • Train: Days 1–5 (DoS, DDoS,       • Train: Days 1–5 (DoS, DDoS,
        per family (DoS/DDoS/Brute/Web).  BruteForce, WebAttacks).            BruteForce, WebAttacks).
      • Test: Remaining 30% episodes    • Test: Held-out episodes of known  • Val: Day 6 (Web Attacks).
        of the SAME families.             families + Infiltration/Botnet.   • Test: Days 7–9 (Infiltration &
      • Benchmark: 62 Test Onsets.      • Benchmark: 81 Test Onsets.          Botnet ONLY).
                                                                            • Benchmark: 7 Test Onsets.
```

---

## 3. Detailed Split Mappings

### SETTING A — Seen Attack Generalization (Primary Known Benchmark)
- **Training Days & Episodes:**
  - Feb 14 (BruteForce: 2 early episodes)
  - Feb 15 & 16 (DoS: 5 early episodes)
  - Feb 21 (DDoS: 26 early episodes)
  - Feb 22 & 23 (WebAttacks: 222 early episodes)
  - **Total Training Episodes:** 255 episodes (198 isolated onsets)
- **Validation Split:** 15% chronological holdout of each seen family (56 episodes / 44 isolated onsets).
- **Test Split:** Remaining chronologically latest 15% independent episodes of the same families (62 episodes / 50 isolated onsets).
- **Expected Outcome:** Measures whether the architecture can forecast recurring instances of known attack behaviors.

---

### SETTING B — Mixed Generalization (Realistic Multi-Threat Environment)
- **Training Split:** Complete sessions of Days 1–5 (Feb 14, 15, 16, 21, 22) covering BruteForce, DoS, DDoS, and early Web Attacks (171 episodes).
- **Validation Split:** Feb 23 Web Attacks (194 episodes).
- **Test Split:** Feb 28, Mar 01, Mar 02 containing both known Web Attack remnants and unseen Infiltration and Botnet episodes (8 test episodes total).
- **Evaluation Reporting:** Evaluates overall performance, and separates metrics into **Known Family Metrics** vs **Unseen Family Metrics**.

---

### SETTING C — Out-of-Distribution / Zero-Day Generalization (Strict Research Baseline)
- **Training Split:** 5 days (Feb 14, 15, 16, 21, 22) — 101,845 windows (89,027 pure-benign sequences). Attack types: Brute Force, DoS, DDoS.
- **Validation Split:** 1 day (Feb 23) — 21,536 windows (18,658 pure-benign sequences). Attack types: Web Attacks.
- **Test Split:** 3 days (Feb 28, Mar 01, Mar 02) — 64,608 windows (45,530 pure-benign sequences). Attack types: **Infiltration** and **Botnet** (100% unseen).
- **Test Onsets:** Exactly 7 isolated onsets (4 Infiltration, 3 Botnet).
- **Purpose:** Rigorous proof of generalized precursor modeling on zero-day attacks.
