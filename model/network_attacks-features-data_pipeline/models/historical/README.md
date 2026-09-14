# Historical Research Model Checkpoints

This directory archives the scientifically important model checkpoints from previous phases.

```
models/historical/
├── phase5_5/   # Phase 5.5 Champion Model (K=10 Horizon Forecaster, Exp E004)
├── phase6/     # Phase 6 Champion Model (Precursor Weighted 10x, Exp E602)
└── phase7/     # Phase 7 Production Freeze Artifacts (Operational Aggregation)
```

## Model Lineage Table

| Phase | Directory | Winning Exp ID | Checkpoint Size | MD5 Checksum | Key Contribution |
|---|---|---|---|---|---|
| **Phase 5.5** | `models/historical/phase5_5/` | `E004_K10_lam5p0_pwyes` | 863,797 bytes | `cf543b5a6f7df246316d92d2b5d11725` | Validated non-zero gradient flow; matched $K_{\text{train}}=K_{\text{eval}}$ |
| **Phase 6** | `models/historical/phase6/` | `E602_PrecursorWeight_10x` | 862,303 bytes | `1df025d4cbb7d7a2ef8cb966c3735b05` | 100% pre-onset event recall on pure-benign history |
| **Phase 7** | `models/historical/phase7/` | `Phase 7 Final Freeze` | 862,047 bytes | `a07a102c3b0f5aa4730a0659cb14dfb5` | Operational alert cooldowns & MITRE behavioral attribution |
