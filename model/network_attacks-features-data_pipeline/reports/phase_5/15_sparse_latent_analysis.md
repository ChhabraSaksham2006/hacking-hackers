# Phase 5M — Sparse Latent Structure & Sparsity Curve Analysis

## 1. Sparsity-Performance Curve (K=10, 20.0s Lead Time)

| Sparsity Variant | Active Coordinates | % Active | State MAE | State MSE | Attack F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|
| **100% (128D)** | 128 / 128 | 100.0% | 0.2953 | 0.635 | **0.2748** | 0.4352 | 0.2008 | 0.1068 | 0.5053 |
| **75% (96D)** | 96 / 128 | 75.0% | 0.2961 | 0.6336 | **0.3451** | 0.4477 | 0.2807 | 0.1419 | 0.511 |
| **50% (64D)** | 64 / 128 | 50.0% | 0.2933 | 0.6307 | **0.2909** | 0.4434 | 0.2165 | 0.1114 | 0.4912 |
| **25% (32D)** | 32 / 128 | 25.0% | 0.2901 | 0.6307 | **0.1613** | 0.7712 | 0.0901 | 0.011 | 0.4773 |
| **10% (13D)** | 13 / 128 | 10.0% | 0.3187 | 0.6662 | **0.0203** | 0.4089 | 0.0104 | 0.0062 | 0.3419 |

## 2. Top-10 Numerical Diagnosis & Latent Diagnostics

- **Active Latent Frequency:** Latent coordinates activate dynamically. Dead dimension count: 0 / 128.
- **Top-10 Stability:** With the multi-task loss and gradient clipping at 1.0, Top-10 (13 coordinates) trains stably without divergence.
