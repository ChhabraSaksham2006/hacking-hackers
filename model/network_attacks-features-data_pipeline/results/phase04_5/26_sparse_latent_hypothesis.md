# Phase 4.5 Forensic Audit: Report 26 — Sparse Latent Routing Hypothesis Formulation

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Hypothesis Formulation

Network traffic encompasses diverse distinct behavioral regimes (e.g. volumetric UDP flooding vs slow stealthy TCP reconnaissance vs benign web browsing). When a shared dense latent space models all regimes simultaneously, gradient updates from dominant high-volume attacks (DoS/DDoS) can degrade representations for subtle low-volume attacks (Infiltration).

**Hypothesis:** Conditioning latent state updates on sparse gating (e.g. top-$k$ latent routing or sparse activation penalties) enables the latent state space to partition into specialized sub-manifolds, preventing catastrophic interference between volumetric floods and stealthy scans.

## 2. Experimental Verification Plan

1. Establish Dense Gaussian RSSM baseline.
2. Implement Sparse Gated RSSM (e.g., Sparse Mixture of Latents or L1/KL-sparsity regularization).
3. Evaluate metrics: OOD Infiltration PR-AUC, Latent Activation Sparsity (Gini coefficient), and State Reconstruction Error across attack families.
