# 20 — The Four Core Final System Outputs

| System Output Channel | Output Description | Mathematical Definition | Physical Interpretation | Consumer System |
|---|---|---|---|---|
| **Output 1** | Future Network State | $\hat{S}_{t+10} \in \mathbb{R}^{54}$ | Predicted physical telemetry vector 20s into the future | SOC Telemetry Radar Display |
| **Output 2** | Attack Onset Probability | $P_{	ext{onset}} \in [0.0, 1.0]$ | Calibrated likelihood of an attack starting within 20s | Automated Firewall Staging / Alerts |
| **Output 3** | Candidate MITRE Technique | Technique ID & Confidence | Evidence-based MITRE ATT&CK candidate (e.g. T1071 C2) | SOC Threat Intelligence Queue |
| **Output 4** | Behavioral Attribution Vector| $\Delta S = \hat{S}_{t+10} - S_t$ | Feature-level physical deviations driving the alert | Analyst Root-Cause Explainability UI |

### Interpretation

The final system produces 4 distinct output streams simultaneously from a single forward rollout pass. Unlike black-box classifiers that output only an attack probability, this temporal world model forecasts both the discrete attack probability and the continuous physical state of the network, enabling deterministic evidence-based explanation.
