# Baseline Forecasting Dataset & Experimental Partition Summary

**Project:** SIH26153 — AI-Based Network Attack Forecasting
**Phase:** Phase 4 — Baseline Forecasting Model Suite

## 1. Sequence Partition Summary

| Partition | Daily Captures | Sequences | Attack Preval. (K=1) | Attack Preval. (K=10) | State Dim | History Span |
|---|---|---|---|---|---|---|
| **Train** | Days 1–5 (14, 15, 16, 21, 22 Feb) | 100,595 | 10.76% | 10.77% | 54 / 37 | 28.0s (10 steps) |
| **Validation** | Day 6 (23 Feb) | 21,286 | 6.06% | 6.06% | 54 / 37 | 28.0s (10 steps) |
| **Test (OOD)** | Days 7–9 (28 Feb, 01 Mar, 02 Mar) | 63,858 | 29.07% | 29.07% | 54 / 37 | 28.0s (10 steps) |
| **TOTAL** | **9 Days** | **185,739** | — | — | — | — |
