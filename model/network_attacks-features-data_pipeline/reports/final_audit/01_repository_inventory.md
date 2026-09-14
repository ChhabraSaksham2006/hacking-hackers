# 01 — Repository Inventory & Component Classification

## 1. Directory Tree Structure

```text
C:\CyberSecurityNetworkingAttackPredictionModel
├── configs/
│   ├── baselines.yaml                  [CONFIG] Baseline model hyperparams & split
│   ├── dataset.yaml                    [CONFIG] Dataset paths & split definitions
│   ├── features.yaml                   [CONFIG] Flow feature selection metadata
│   └── temporal.yaml                   [CONFIG] 54-D temporal state design & windows
├── data/
│   ├── interim/
│   │   └── cse_cic_ids2018/            [DATA] 9 canonical cleaned flow Parquets (8.28M flows)
│   ├── metadata/
│   │   ├── attack_timelines.csv        [METADATA] Ground-truth attack start/end durations
│   │   ├── canonical_schema.yaml       [METADATA] 80-feature data dictionary & types
│   │   ├── cleaning_manifest.csv       [METADATA] Cleaning logs, dropped rows, SHA-256
│   │   ├── dataset_provenance.yaml     [METADATA] Dataset provenance & AWS S3 origins
│   │   ├── download_manifest.csv       [METADATA] Raw AWS S3 file hashes & URLs
│   │   ├── mitre_mapping.csv           [METADATA] 14-attack to MITRE ATT&CK technique mapping
│   │   └── temporal_states_manifest.csv[METADATA] 9 daily temporal state parquets summary
│   └── processed/
│       └── temporal_states/            [DATA] 9 daily 54-D temporal state Parquets (188.5K states)
├── models/                             [MODEL] Legacy model checkpoints (.pt)
├── notebooks/                          [NOTEBOOK] Exploratory & visualizer notebooks
├── reports/                            [REPORT] Scientific audits, benchmark reports
│   ├── baselines/                      [REPORT] Phase 4 baseline evaluation CSVs & summaries
│   ├── dataset_selection/              [REPORT] Dataset comparative evaluation reports
│   ├── data_pipeline/                  [REPORT] Ingestion & canonicalization audits
│   ├── phase_4_5/                      [REPORT] Persistence paradox & temporal forensics
│   └── final_audit/                    [REPORT] Complete forensic repository audit suite
├── results*/                           [EVALUATION] Execution logs, JSON metrics, probabilities
│   ├── results_final_selected_k/       [EVALUATION] Final K-step (1, 100, 200, 250, 300) evaluations
│   └── results_selected_benchmark/     [EVALUATION] Baseline suite & Sparse RSSM benchmark logs
├── scripts/
│   ├── audit/                          [AUDIT] Dataset & forensic analysis scripts
│   ├── download/                       [DATA] S3 ingestion scripts
│   ├── experiments/                    [TRAINING/EVAL] Benchmark & model execution scripts
│   ├── preprocessing/                  [DATA] Raw-to-canonical & state aggregation scripts
│   └── verification/                   [TEST] Parquet schema & state integrity verifiers
├── src/
│   ├── evaluation/                     [EVALUATION] Metrics (F1, PR-AUC, ROC-AUC, MAE, Tau)
│   ├── models/                         [MODEL] Dense RSSM, Sparse RSSM, Baselines (GRU, RF, etc.)
│   ├── temporal/                       [SOURCE CODE] State aggregator (54-D) & Sequence dataset builder
│   ├── training/                       [TRAINING] Model trainer & optimization loop
│   └── inference_*.py                  [INFERENCE] Streaming & batch alert engines
└── tests/                              [TEST] Unit tests for aggregators & models
```

## 2. Comprehensive Component Classification & Lifecycle Status

| Component Path | Category | Role & Purpose | Current Usage | Consumed By | Input Data | Status |
|---|---|---|---|---|---|---|
| `configs/temporal.yaml` | CONFIG | Canonical 54-D state specification | Active | State aggregator, sequence builder | Configuration | CURRENT |
| `configs/baselines.yaml` | CONFIG | Baseline model hyperparameter suite | Active | `run_baseline_suite.py` | Configuration | CURRENT |
| `data/interim/cse_cic_ids2018/` | DATA | 9 canonical cleaned flow Parquets | Active | `build_temporal_states.py` | Raw S3 CSVs | CURRENT |
| `data/processed/temporal_states/`| DATA | 9 daily 54-D state Parquets | Active | Model trainers & baseline runners | Canonical Parquets | CURRENT |
| `src/temporal/state_aggregator.py`| SOURCE CODE| Vectorized rolling window aggregator (54-D)| Active | `build_temporal_states.py` | Flow DataFrames | CURRENT |
| `src/temporal/dataset_builder.py` | SOURCE CODE| Sliding lookback sequence builder (P=10) | Active | All training & baseline runners | State Parquets | CURRENT |
| `src/models/sparse_rssm.py` | MODEL | Sparse RSSM world model & rollout | Active | `run_sparse_rssm.py` | Lookback tensors | CURRENT (FLAWED LOSS) |
| `src/models/sparse_latent.py` | MODEL | Top-K straight-through latent router | Active | Sparse RSSM | Dense latents | CURRENT |
| `src/models/baselines/` | MODEL | Baseline implementations (RF, GRU, etc.)| Active | `run_baseline_suite.py` | Lookback / Static | CURRENT |
| `src/evaluation/metrics.py` | EVALUATION | Multi-metric calculation engine | Active | All evaluators | Model predictions | CURRENT |
| `scripts/experiments/run_sparse_rssm.py` | TRAINING | Runner for Sparse & Dense RSSM | Active | Experiment execution | State Parquets | CURRENT |
| `scripts/experiments/run_baseline_suite.py`| TRAINING | Runner for baselines across horizons | Active | Baseline reports | State Parquets | CURRENT |
| `src/world_model.py` | MODEL | Legacy LSTM/Transformer world model | Inactive | Legacy scripts | 47-D DARPA/CIC | HISTORICAL / OBSOLETE |
