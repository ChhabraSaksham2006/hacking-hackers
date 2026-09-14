# Forensic Audit: Multi-Horizon Target Formulation & Ground Truth Semantics

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Multi-Horizon Targets

For lookahead horizons $K \in \{1, 3, 5, 10\}$ (corresponding to $+2\text{s}, +6\text{s}, +10\text{s}, +20\text{s}$ ahead):

1. **Continuous Future State ($S_{t+K} \in \mathbb{R}^{54}$)**: The exact macro-state vector at future step $t+K$.
2. **Binary Attack Occurrence ($y_{t+K} \in \{0, 1\}$)**: 1 if future window $[t+K]$ contains any non-benign flow; 0 otherwise.
3. **Multiclass Attack Family ($c_{t+K} \in \{0, \dots, 6\}$)**: The dominant attack family in window $[t+K]$ (`Benign`, `BruteForce`, `DoS`, `DDoS`, `WebAttack`, `Infiltration`, `Botnet`).
4. **Time-to-Attack Onset ($\tau_t \in [0, 300]$ seconds)**: Continuous seconds from step $t$ until the onset of the next attack window in the current session (0.0 if currently under attack, capped at 300.0s if no attack within 5 minutes or remaining day).

## 2. Resolution of Mixed Windows

- If a window contains both benign and attack flows, `is_attack = 1`.
- `attack_fraction` captures the precise proportion of malicious flows in $[0.0, 1.0]$.
- `dominant_attack_family` is selected as the majority attack label among all non-benign flows in the window.
