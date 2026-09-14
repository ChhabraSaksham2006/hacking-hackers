# Final Trained Model Specification & Verification

## Model Identity
- **Model Class:** `SparseRSSM`
- **Trained Parameters:** 213,820 weights
- **Source Checkpoint:** `artifacts/phase7/model.pt` (MD5: `a07a102c3b0f5aa4730a0659cb14dfb5`, 862,047 bytes)
- **Deployment Checkpoint:** `deployment/model/model.pt` (MD5: `a07a102c3b0f5aa4730a0659cb14dfb5`)
- **Authoritative Archive:** `models/final/model.pt` (MD5: `a07a102c3b0f5aa4730a0659cb14dfb5`)
- **Training Phase:** Phase 7 Final Freeze / Phase 6 Champion Architecture
- **Winning Experiment ID:** `E602_PrecursorWeight_10x` / `P7_SparseRSSM_Champ`
- **Random Seed:** 42

---

## Artifact Inventory

```
models/final/
├── README.md             # This document
├── model.pt              # PyTorch state dict (213,820 params, 862,047 bytes)
├── scaler.pkl            # StandardScaler fitted on 5 training days (54 features)
├── config.json           # Model hyperparameters & operational thresholds
├── metadata.json         # Evaluation metrics, git commit lineage, and dates
└── feature_schema.json   # Canonical 54 feature names and physical descriptions
```

---

## Verification & Lineage

1. **Exact Architecture:**
   - Input: $(B, P=10, D=54)$
   - MLP Encoder: $54 \to 128 \to 128 \to 128$ with LayerNorm and GELU
   - Recurrent Cell: PyTorch `GRUCell(128, 128)`
   - Transition MLP: $256 \to 128 \to 128$
   - Continuous State Decoder: $128 \to 128 \to 54$ (reconstructs physical state)
   - Discrete Attack Prediction Head: Linear $(256 \to 1)$ logit

2. **Empirical Performance on Out-of-Distribution Test Set (Feb 28 – Mar 02 2018):**
   - **Continuous State MAE:** 0.2766
   - **Continuous State MSE:** 0.6155
   - **Tier 1 Operational Recall:** **100.0%** (7 / 7 unseen attack episodes detected in advance)
   - **Tier 1 Median Lead Time:** **14.0 seconds** (Earliest detection up to 20.0s)
   - **Tier 1 False Alarm Rate:** **229.02 false alarms / hour** (79.1% reduction vs raw)
   - **Tier 3 False Alarm Rate:** **39.89 false alarms / hour** (96.4% reduction vs raw)
