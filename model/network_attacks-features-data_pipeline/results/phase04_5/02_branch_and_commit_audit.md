# 02 — Git Branch and Commit History Audit

## 1. Branch Inventory

| Branch Name | Scope | Latest Commit | Relationship to Current Branch | Unique Work Contained | Classification |
|---|---|---|---|---|---|
| `features/llm_pipeline` (HEAD) | Local / Remote | `90f9624` | Current active branch | Added LLM pipeline, expanded benchmarks | ACTIVE / CURRENT |
| `feature/data-pipeline` | Local / Remote | `fcf1749` | Direct parent of `features/llm_pipeline` | Complete 54-D pipeline, Phase 4 & 4.5 | STABLE BASE |
| `feature/world-model-dataset-darpaWithCICIDS` | Local / Remote | `a03c477` | Diverged earlier ancestor | Legacy 47-D DARPA + CIC-2017 world model | HISTORICAL / OBSOLETE |
| `features/lakshay_ml` | Local / Remote | `d03a94f` | Independent initial branch | Initial EDA, logistic regression baseline | HISTORICAL |
| `main` | Local / Remote | `6b422e7` | Initial root commit | Initial empty commit | HISTORICAL |

## 2. Chronological Commit History & Architectural Evolution

1. **`6b422e7` (main)**: Initial repository commit.
2. **`d03a94f` (features/lakshay_ml)**: Initial exploratory data analysis (EDA), anomaly audit, and single-flow Logistic Regression baseline.
3. **`589dbda` -> `a03c477` (feature/world-model-dataset-darpaWithCICIDS)**: First world model iteration combining DARPA 1998 and CIC-IDS2017 into a 47-D representation with an LSTM world model.
4. **`4a98501` (feature/data-pipeline)**: Complete architectural pivot to CSE-CIC-IDS2018; introduced the canonical 54-D temporal state aggregation (37 base + 17 deltas) with 10s window and 2s stride.
5. **`748483b`**: Comprehensive Phase 3C temporal dataset forensic audit.
6. **`e3b6a20`**: Phase 4 baseline model suite implementation (Majority, Persistence, LR, RF, GRU, Transformer).
7. **`d80ef1f`**: Phase 4.5 forensic audit revealing the "Persistence Paradox" and formulating the Sparse RSSM requirements.
8. **`0ecf7c3` -> `fcf1749`**: Removal and cleanup of legacy DARPA / CIC-2017 dependencies.
9. **`90f9624` (features/llm_pipeline - Current HEAD)**: Implementation of `SparseRSSM`, `TopKSparseLatent`, long-horizon benchmark scripts (K=1 to 300), and LLM pipeline integration.
