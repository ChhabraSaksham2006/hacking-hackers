# Forensic Audit: Duplicate Flow Retention Impact Analysis

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Forensic Finding

The raw CSE-CIC-IDS2018 dataset contains 266,423 duplicate flow rows (3.22% of total flows). In Phase 2A, an explicit design decision was made to **retain these duplicate flows** rather than discarding them.

## 2. Scientific Justification

1. **High-Frequency Brute-Force Bursts**: Automated attack tools (e.g. Patator on SSH port 22, Hydra on HTTP POST) open rapid successive TCP connections with identical flow feature signatures (packet count = 1, byte count = 0, duration = 0ms). Deduplicating these flows reduces a 1,000 req/sec brute force attack to a single flow, destroying volumetric velocity signals.
2. **Volumetric Flood Fidelity**: In DDoS (HOIC/LOIC) and DoS Hulk floods, bots generate thousands of identical SYN / HTTP GET packet bursts per second. Eliminating duplicates artificially dampens flow rates by up to 94%.
3. **State Aggregator Invariance**: Because our pipeline aggregates micro-flows into macro-state windows ($S_t$), duplicate flows correctly register as genuine volume and rate spikes ($N_t$, $\text{byte\_rate}$, $\text{pkt\_rate}$), exactly as observed in real SOC telemetry.
