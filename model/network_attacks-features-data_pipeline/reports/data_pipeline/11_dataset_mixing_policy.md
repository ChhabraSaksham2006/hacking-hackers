# 11 — Dataset Mixing Policy & Cross-Domain Validation Strategy
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Prohibition of Uncontrolled Multi-Dataset Concatenation

Direct concatenation of disparate datasets (CSE-CIC-IDS2018 + CIC-IDS2017 + DARPA 1998) is strictly prohibited because it forces the model to memorize dataset capture topology fingerprints rather than generalized attack progression.

---

## 2. Clean Two-Tier Validation Framework

1. **Primary In-Domain Training & Evaluation**: **CSE-CIC-IDS2018** (Chronological Day 1–6 train, Day 7 val, Days 8–10 test).
2. **External Out-of-Domain Zero-Shot Benchmark**: **CIC-IDS-2017** (cleanly processed with preserved chronological timestamps).
