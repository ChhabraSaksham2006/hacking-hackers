# Master Results Archive & Evidence Index

## SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data

This directory archives the primary empirical results and evaluation artifacts across all research phases.

```
results/
├── README.md       # This index
├── phase01/        # Exploratory feature and label audits
├── phase02/        # Canonical dataset conversion & per-flow baseline audits
├── phase03/        # 54-D temporal state design & leakage verification reports
├── phase04/        # Baseline forecasting suite benchmarks
├── phase04_5/      # Comprehensive 24-section forensic audit & persistence forensics
├── phase05/        # Phase 5 RSSM multi-horizon benchmarks (Invalidated / historical)
├── phase05_5/      # Corrected Phase 5.5 benchmark & multi-seed confirmations
├── phase06/        # Pre-attack onset forecasting, episode forensics & multi-horizon
└── phase07/        # Operational alert aggregation, hard negative mining & MITRE attribution
```

---

## Phase Results Master Index

| Phase | Directory | Primary Result File | Purpose | Authoritative? | Used in Paper? | Key Reported Metrics |
|---|---|---|---|---|---|---|
| **Phase 1** | `results/phase01/` | `09_dataset_comparison.csv` | Initial dataset provenance comparison | Historical | Context only | 5 dataset comparisons |
| **Phase 2** | `results/phase02/` | `14_canonical_dataset_statistics.csv` | Canonical parquet flow statistics | Authoritative | Yes | 8.28M flows, 9 capture days |
| **Phase 3** | `results/phase03/` | `02_state_feature_design.md` | 54-D temporal state definition | Authoritative | Yes | 37 base + 17 delta features |
| **Phase 4** | `results/phase04/` | `06_multihorizon_comparison.csv` | Initial multi-horizon baselines | Superseded | Context only | Persistence F1=0.9996 continuation |
| **Phase 4.5** | `results/phase04_5/` | `master_metrics.csv` | Full forensic audit master metrics | Authoritative | Yes | Identified 3 critical bugs |
| **Phase 5** | `results/phase05/` | `05_dense_rssm_results.csv` | Pre-fix Dense RSSM benchmarks | **INVALIDATED** | No (Ablation warning) | Flat F1~0.554 (untrained head) |
| **Phase 5.5** | `results/phase05_5/` | `authoritative_experiment_results.csv`| Post-fix loss ablation & multi-horizon | Authoritative | Yes | F1=0.4832 at K=10, Prec=84.66% |
| **Phase 6** | `results/phase06/` | `authoritative_onset_results.csv` | Pure-benign onset early warning | Authoritative | Yes | 100% event recall (7/7), 20s lead |
| **Phase 7** | `results/phase07/` | `10_final_model_comparison.csv` | Operational aggregation & MITRE | Authoritative | Yes | 100% recall @ 229 FA/hr (Tier 1) |
