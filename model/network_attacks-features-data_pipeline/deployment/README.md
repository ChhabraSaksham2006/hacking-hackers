# SIH26153 — Production Model Deployment Package

## Phase 7: Operational Early-Warning & Behavioral Attribution

**Git Commit:** `d2c7da5` | **Branch:** `features/data_pipeline` | **Status:** RESEARCH FROZEN

---

## Package Contents

```
deployment/
├── README.md                    # This file
├── MODEL_CARD.md                # Full model documentation
├── inference.py                 # Production inference engine
├── config.json                  # Model configuration & operational settings
├── state_schema.json            # Authoritative 54-D state documentation
├── inference_api_contract.json  # Input/output API contract
├── requirements.txt             # Python dependencies
├── example_input.json           # Example normalized input (10×54)
├── example_output.json          # Example structured output
├── model/
│   └── model.pt                 # SparseRSSM weights (seed=42, 213,820 params)
└── preprocessing/
    └── scaler.pkl               # StandardScaler fitted on 5 training days
```

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Inference on Example Input
```bash
# From deployment/ directory:
python inference.py --state-file example_input.json

# Or from repo root:
python deployment/inference.py --state-file deployment/example_input.json
```

### 3. Run on Your Own Data
```python
import json, pickle, numpy as np
import sys; sys.path.insert(0, '..')  # Add repo root

from deployment.inference import run_inference

# Build your 10×54 raw feature matrix from 10 consecutive 2-second windows
raw_features = np.zeros((10, 54), dtype=np.float32)  # Replace with real data

# Apply scaler
with open('preprocessing/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)
normalized = scaler.transform(raw_features)

# Run inference
result = run_inference(normalized.tolist(), model_dir='.', already_normalized=True)
print(f"Onset probability: {result['onset_probability']:.4f}")
print(f"Risk level: {result['risk_level']}")
print(f"Is alert: {result['is_alert']}")
```

---

## Input Specification

```
Input tensor shape: (1, 10, 54)
  - 1:  batch size (single sequence)
  - 10: lookback steps P (10 × 2-second windows = 20-second history)
  - 54: feature dimensions (37 base + 17 delta, see state_schema.json)

REQUIREMENTS:
  1. All 10 history windows must be pure-benign (zero attack traffic)
  2. Features must be normalized with scaler.pkl (StandardScaler)
  3. Feature ordering must match state_schema.json exactly
```

---

## Output Specification

```json
{
  "onset_probability": 0.04-1.0,   // Attack onset probability in next 20s
  "risk_level": "NORMAL|...|CRITICAL_ATTACK_IMMINENT",
  "lead_time_seconds": 20.0,        // Forecast horizon (when alert=true)
  "is_alert": true/false,           // prob >= 0.04 threshold
  "mitre_candidates": [...],        // Evidence-based MITRE technique scoring
  "forecasted_state_delta": [...],  // 54-D physical state change forecast
  "current_state": [...],           // Current (last) normalized state
  "forecasted_state": [...]         // Forecasted state at t+20s
}
```

---

## Operational Tiers

| Tier | Alert Strategy | Event Recall | FA/hr | Use Case |
|------|---------------|-------------|-------|---------|
| **Tier 1** | 10s cooldown | **100%** (7/7) | 229 | Maximum coverage |
| **Tier 2** | 30s cooldown | 71.43% (5/7) | 79 | Balanced |
| **Tier 3** | 60s cooldown | 57.14% (4/7) | 40 | Low noise |

*All tiers use raw threshold = 0.04 (calibrated on validation)*

---

## MITRE Attribution Note

> ⚠️ The MITRE ATT&CK technique mapping is a **deterministic heuristic evidence-scoring system**, NOT a trained MITRE classifier. Confidence values represent relative physical evidence weights, not learned class probabilities. A qualified security analyst should review all attributions before taking action.

---

## Performance Summary

- **State Forecasting MAE:** 0.2766 (normalized 54-D space)
- **Test events:** 7 (4 Infiltration + 3 Botnet — all fully OOD)
- **Model parameters:** 213,820
- **Inference device:** CPU (default) — GPU supported via `torch.cuda`

See [MODEL_CARD.md](MODEL_CARD.md) for complete documentation.
