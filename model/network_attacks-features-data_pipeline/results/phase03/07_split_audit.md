# Forensic Audit: Chronological Splitting & Out-of-Distribution Shift

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Partition Breakdown

| Partition | Daily Sessions | Sequences | Attack % | Primary Attack Families | Evaluation Role |
|---|---|---|---|---|---|
| **Train** | Days 1–5 (14, 15, 16, 21, 22 Feb) | 102,045 | 10.80% | BruteForce, DoS (4 types), DDoS (HOIC/LOIC) | Model fitting & dynamic state learning |
| **Validation** | Day 6 (23 Feb) | 21,576 | 5.97% | Web Attacks (BruteForce Web, XSS, SQLi) | Hyperparameter tuning & threshold selection |
| **Test** | Days 7–9 (28 Feb, 01 Mar, 02 Mar) | 64,728 | 29.13% | Multi-stage Infiltration & Botnet ARES C2 | **Out-of-Distribution & Zero-Shot Attack Family Generalization** |

## 2. Scientific Significance: Out-of-Distribution (OOD) Generalization

> [!IMPORTANT]
> This split is NOT a standard IID (independent and identically distributed) test. It evaluates whether a world model trained on network dynamics (volume surges, port entropy shifts, TCP connection state breakdown) can generalize to forecast **unseen, multi-stage attack types (Infiltration and Botnets)** strictly from behavioral state transitions.
