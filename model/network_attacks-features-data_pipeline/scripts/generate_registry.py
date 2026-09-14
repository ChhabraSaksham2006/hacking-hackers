import csv, os, json

fields = [
    "Experiment ID", "Phase", "Date/Commit", "Objective", "Research Question",
    "Dataset", "Train Split", "Validation Split", "Test Split", "Input Representation",
    "State Dimension", "History Length", "Window Size", "Stride", "Forecast Horizon K",
    "Forecast Seconds", "Model", "Architecture", "Loss", "Lambda State",
    "Lambda Attack", "Class Weighting", "Precursor Weight", "Tau", "Focal Gamma",
    "Threshold", "Seed", "Epochs", "Batch Size", "Learning Rate",
    "Optimizer", "Hidden Dimension", "Latent Dimension", "Dropout", "Other Hyperparameters",
    "Precision", "Recall", "F1", "PR-AUC", "ROC-AUC",
    "FPR", "False Alarms/Hour", "Event Recall", "Events Detected", "Median Lead Time",
    "State MAE", "State MSE", "Scientific Status", "Selected?", "Reason",
    "Next Experiment", "Source Artifact"
]

rows = []

# 1. Historical Phase 4 baselines from master_metrics.csv
if os.path.exists("reports/final_audit/master_metrics.csv"):
    with open("reports/final_audit/master_metrics.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            exp_id = f"P4_{r['Model']}_{r['Variant']}_K{r['K']}"
            rows.append({
                "Experiment ID": exp_id,
                "Phase": "Phase 4",
                "Date/Commit": "e3b6a20 (2026-09-08)",
                "Objective": f"Benchmark baseline model {r['Model']} on temporal state forecasting",
                "Research Question": "Can standard ML/DL models predict attacks across horizons K=1, 50, 100?",
                "Dataset": "CSE-CIC-IDS2018",
                "Train Split": "5 days (Feb 14, 15, 16, 21, 22)",
                "Validation Split": "1 day (Feb 23)",
                "Test Split": "3 days (Feb 28, Mar 01, Mar 02)",
                "Input Representation": "54-D temporal state sequence",
                "State Dimension": "54",
                "History Length": "10",
                "Window Size": "10s",
                "Stride": "2s",
                "Forecast Horizon K": r['K'],
                "Forecast Seconds": r['Horizon_sec'],
                "Model": r['Model'],
                "Architecture": r['Variant'],
                "Loss": "BCE / LogLoss / MSE depending on baseline",
                "Lambda State": "N/A",
                "Lambda Attack": "N/A",
                "Class Weighting": "NOT FOUND IN REPOSITORY",
                "Precursor Weight": "1.0",
                "Tau": "N/A",
                "Focal Gamma": "N/A",
                "Threshold": "0.50 (uncalibrated)",
                "Seed": "42",
                "Epochs": "10 (if DL)",
                "Batch Size": "NOT FOUND IN REPOSITORY",
                "Learning Rate": "NOT FOUND IN REPOSITORY",
                "Optimizer": "Adam / L-BFGS",
                "Hidden Dimension": "NOT FOUND IN REPOSITORY",
                "Latent Dimension": "NOT FOUND IN REPOSITORY",
                "Dropout": "NOT FOUND IN REPOSITORY",
                "Other Hyperparameters": f"Task={r.get('Task','Continuation')}",
                "Precision": r.get('Precision', 'NOT FOUND IN REPOSITORY'),
                "Recall": r.get('Recall', 'NOT FOUND IN REPOSITORY'),
                "F1": r.get('F1', 'NOT FOUND IN REPOSITORY'),
                "PR-AUC": r.get('PR_AUC', 'NOT FOUND IN REPOSITORY'),
                "ROC-AUC": r.get('ROC_AUC', 'NOT FOUND IN REPOSITORY'),
                "FPR": r.get('FPR', 'NOT FOUND IN REPOSITORY'),
                "False Alarms/Hour": "NOT FOUND IN REPOSITORY",
                "Event Recall": "NOT FOUND IN REPOSITORY",
                "Events Detected": "NOT FOUND IN REPOSITORY",
                "Median Lead Time": "0s (continuation task)",
                "State MAE": "N/A",
                "State MSE": r.get('State_MSE', 'N/A'),
                "Scientific Status": "SUPERSEDED (Phase 4 legacy evaluation)",
                "Selected?": "No",
                "Reason": "Evaluated on continuation-dominated dataset prior to forensic corrections",
                "Next Experiment": "Phase 4.5 Forensic Audit",
                "Source Artifact": "reports/final_audit/master_metrics.csv"
            })

# 2. Phase 5.5 authoritative results
if os.path.exists("reports/phase_5_5/authoritative_experiment_results.csv"):
    with open("reports/phase_5_5/authoritative_experiment_results.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            is_winner = "Yes" if "pwyes" in r['experiment_id'] and r['K'] == '10' else ("Yes" if r['experiment_id'] == "E002_K1_lam5p0_nopw" else "No")
            rows.append({
                "Experiment ID": r['experiment_id'],
                "Phase": "Phase 5.5",
                "Date/Commit": f"{r['git_commit']} (2026-09-09)",
                "Objective": "Controlled loss weighting and horizon evaluation under verified non-zero gradient flow",
                "Research Question": "How does SparseRSSM perform when K_train=K_eval and attack BCE loss is backpropagated?",
                "Dataset": "CSE-CIC-IDS2018",
                "Train Split": "5 days (Feb 14, 15, 16, 21, 22) - 101,845 seqs",
                "Validation Split": "1 day (Feb 23) - 21,536 seqs",
                "Test Split": "3 days (Feb 28, Mar 01, Mar 02) - 64,608 seqs",
                "Input Representation": "54-D temporal state sequence",
                "State Dimension": "54",
                "History Length": "10",
                "Window Size": "10s",
                "Stride": "2s",
                "Forecast Horizon K": r['K'],
                "Forecast Seconds": r['horizon_seconds'],
                "Model": r['model'],
                "Architecture": "SparseRSSM (sparsity_ratio=1.0)",
                "Loss": "Recon MSE + Rollout MSE + BCEWithLogits",
                "Lambda State": "1.0",
                "Lambda Attack": r.get('lambda_attack', '1.0'),
                "Class Weighting": r.get('positive_weighting', 'False'),
                "Precursor Weight": "1.0",
                "Tau": "N/A",
                "Focal Gamma": "N/A",
                "Threshold": r.get('threshold', '0.50'),
                "Seed": r.get('seed', '42'),
                "Epochs": "5",
                "Batch Size": "256",
                "Learning Rate": "0.001",
                "Optimizer": "Adam",
                "Hidden Dimension": "128",
                "Latent Dimension": "128",
                "Dropout": "0.0",
                "Other Hyperparameters": f"K_train={r.get('K_train', r['K'])}, K_eval={r.get('K_eval', r['K'])}",
                "Precision": r.get('precision', 'NOT FOUND IN REPOSITORY'),
                "Recall": r.get('recall', 'NOT FOUND IN REPOSITORY'),
                "F1": r.get('F1', 'NOT FOUND IN REPOSITORY'),
                "PR-AUC": r.get('PR_AUC', 'NOT FOUND IN REPOSITORY'),
                "ROC-AUC": r.get('ROC_AUC', 'NOT FOUND IN REPOSITORY'),
                "FPR": r.get('FPR', 'NOT FOUND IN REPOSITORY'),
                "False Alarms/Hour": r.get('false_alarms_per_hour', 'NOT FOUND IN REPOSITORY'),
                "Event Recall": r.get('onset_recall', 'see_onset_table'),
                "Events Detected": "NOT FOUND IN REPOSITORY",
                "Median Lead Time": r.get('median_lead_time', 'NOT FOUND IN REPOSITORY'),
                "State MAE": r.get('state_MAE', 'N/A'),
                "State MSE": r.get('state_MSE', 'N/A'),
                "Scientific Status": "AUTHORITATIVE (Phase 5.5)",
                "Selected?": is_winner,
                "Reason": "Selected on validation F1 under controlled ablation" if is_winner == "Yes" else "Ablation candidate",
                "Next Experiment": "E003 positive weighting" if "E002" in r['experiment_id'] else ("E004 multi-horizon" if "E003" in r['experiment_id'] else "Phase 6 Pre-Attack Onset"),
                "Source Artifact": "reports/phase_5_5/authoritative_experiment_results.csv"
            })

# 3. Phase 6 authoritative onset results
if os.path.exists("reports/phase_6/authoritative_onset_results.csv"):
    with open("reports/phase_6/authoritative_onset_results.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            is_champ = "Yes" if r['experiment_id'] == "E602_PrecursorWeight_10x" else "No"
            rows.append({
                "Experiment ID": r['experiment_id'],
                "Phase": "Phase 6",
                "Date/Commit": "9d53bf1 (2026-09-09)",
                "Objective": "Evaluate early warning on pure-benign history sequences before attack onset",
                "Research Question": "Can temporal world model learn precursor signatures before attack flows appear?",
                "Dataset": "CSE-CIC-IDS2018 (Pure-Benign History Filtered)",
                "Train Split": "5 days (Feb 14-22) - 89,027 pure-benign seqs",
                "Validation Split": "1 day (Feb 23) - 18,658 pure-benign seqs",
                "Test Split": "3 days (Feb 28-Mar 02) - 45,530 pure-benign seqs",
                "Input Representation": "54-D temporal state sequence (max y_{t-9:t} = 0)",
                "State Dimension": "54",
                "History Length": "10",
                "Window Size": "10s",
                "Stride": "2s",
                "Forecast Horizon K": str(int(r['horizon']) // 2),
                "Forecast Seconds": str(r['horizon']),
                "Model": r['model'],
                "Architecture": "SparseRSSM (sparsity_ratio=1.0)" if r['model'] == "SparseRSSM" else r['model'],
                "Loss": r['loss_type'],
                "Lambda State": "1.0" if r['model'] == "SparseRSSM" else "N/A",
                "Lambda Attack": str(r.get('lambda_onset', '1.0')),
                "Class Weighting": "8.26 (train ratio)",
                "Precursor Weight": str(r.get('precursor_weight', '1.0')),
                "Tau": str(r.get('precursor_window', 'N/A')),
                "Focal Gamma": str(r.get('focal_gamma', 'N/A')),
                "Threshold": str(r.get('threshold', 'NOT FOUND IN REPOSITORY')),
                "Seed": str(r.get('seed', '42')),
                "Epochs": "5" if r['model'] == "SparseRSSM" else "N/A",
                "Batch Size": "1024" if r['model'] == "SparseRSSM" else "N/A",
                "Learning Rate": "0.001" if r['model'] == "SparseRSSM" else "N/A",
                "Optimizer": "AdamW (weight_decay=1e-4)" if r['model'] == "SparseRSSM" else "N/A",
                "Hidden Dimension": "128" if r['model'] == "SparseRSSM" else "N/A",
                "Latent Dimension": "128" if r['model'] == "SparseRSSM" else "N/A",
                "Dropout": "0.0",
                "Other Hyperparameters": f"PrecursorDecayTau={r.get('precursor_window','N/A')}",
                "Precision": str(r.get('precision', 'NOT FOUND IN REPOSITORY')),
                "Recall": str(r.get('recall', 'NOT FOUND IN REPOSITORY')),
                "F1": str(r.get('F1', 'NOT FOUND IN REPOSITORY')),
                "PR-AUC": str(r.get('PR_AUC', 'NOT FOUND IN REPOSITORY')),
                "ROC-AUC": str(r.get('ROC_AUC', 'NOT FOUND IN REPOSITORY')),
                "FPR": str(r.get('FPR', 'NOT FOUND IN REPOSITORY')),
                "False Alarms/Hour": str(r.get('false_alarms_per_hour', 'NOT FOUND IN REPOSITORY')),
                "Event Recall": str(r.get('event_recall', 'NOT FOUND IN REPOSITORY')),
                "Events Detected": f"{round(float(r.get('event_recall', 0))*int(r.get('event_count', 7)))}/{r.get('event_count', 7)}",
                "Median Lead Time": f"{r.get('median_lead_time', '0')}s",
                "State MAE": str(r.get('state_MAE', 'N/A')),
                "State MSE": str(r.get('state_MSE', 'N/A')),
                "Scientific Status": "AUTHORITATIVE (Phase 6)",
                "Selected?": is_champ,
                "Reason": "Validation Best F1 winner (val_F1=0.1540); 100% event recall, 20.0s lead time" if is_champ == "Yes" else "Ablation study",
                "Next Experiment": "E603 tau sweep" if "E602" in r['experiment_id'] else ("E604 loss balance" if "E603" in r['experiment_id'] else ("E605 focal" if "E604" in r['experiment_id'] else ("E606 multi-horizon" if "E605" in r['experiment_id'] else "Phase 7 Operational Aggregation"))),
                "Source Artifact": "reports/phase_6/authoritative_onset_results.csv"
            })

# 4. Phase 7 Alert Aggregation experiments
if os.path.exists("reports/phase_7/04_alert_aggregation_results.csv"):
    with open("reports/phase_7/04_alert_aggregation_results.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            exp_id = f"P7_Agg_{r['strategy_category']}_{r['strategy_name']}"
            is_champ = "Yes" if r['strategy_name'] == "Consecutive-2 + Cooldown 60s" else ("Tier 1" if r['strategy_name'] == "Cooldown 10s" else "No")
            rows.append({
                "Experiment ID": exp_id,
                "Phase": "Phase 7",
                "Date/Commit": "d2c7da5 (2026-09-11)",
                "Objective": "Suppress false alarms while preserving pre-attack early warning lead time",
                "Research Question": "Can sequential temporal alert filters mitigate raw false positives?",
                "Dataset": "CSE-CIC-IDS2018 (Pure-Benign History Filtered)",
                "Train Split": "5 days (Feb 14-22) - 89,027 pure-benign seqs",
                "Validation Split": "1 day (Feb 23) - 18,658 pure-benign seqs",
                "Test Split": "3 days (Feb 28-Mar 02) - 45,530 pure-benign seqs",
                "Input Representation": "54-D temporal state sequence",
                "State Dimension": "54",
                "History Length": "10",
                "Window Size": "10s",
                "Stride": "2s",
                "Forecast Horizon K": "10",
                "Forecast Seconds": "20.0s",
                "Model": "SparseRSSM",
                "Architecture": "SparseRSSM (sparsity_ratio=1.0) + Aggregator",
                "Loss": "Weighted Precursor (10x, tau=60s)",
                "Lambda State": "1.0",
                "Lambda Attack": "1.0",
                "Class Weighting": "8.26 (train ratio)",
                "Precursor Weight": "10.0",
                "Tau": "60s",
                "Focal Gamma": "N/A",
                "Threshold": str(r.get('threshold', '0.04')),
                "Seed": "42",
                "Epochs": "5",
                "Batch Size": "1024",
                "Learning Rate": "0.001",
                "Optimizer": "AdamW (weight_decay=1e-4)",
                "Hidden Dimension": "128",
                "Latent Dimension": "128",
                "Dropout": "0.0",
                "Other Hyperparameters": f"Aggregation={r['strategy_name']}, Params={r.get('parameters','None')}",
                "Precision": str(r.get('precision', 'NOT FOUND IN REPOSITORY')),
                "Recall": str(r.get('recall', 'NOT FOUND IN REPOSITORY')),
                "F1": str(r.get('f1', 'NOT FOUND IN REPOSITORY')),
                "PR-AUC": str(r.get('pr_auc', 'NOT FOUND IN REPOSITORY')),
                "ROC-AUC": str(r.get('roc_auc', 'NOT FOUND IN REPOSITORY')),
                "FPR": str(r.get('fpr', 'NOT FOUND IN REPOSITORY')),
                "False Alarms/Hour": str(r.get('false_alarms_per_hour', 'NOT FOUND IN REPOSITORY')),
                "Event Recall": str(r.get('event_recall', 'NOT FOUND IN REPOSITORY')),
                "Events Detected": f"{r.get('events_detected', '0')}/{r.get('event_count', '7')}",
                "Median Lead Time": f"{r.get('lead_time_median_sec', '0')}s",
                "State MAE": "0.2766",
                "State MSE": "0.6155",
                "Scientific Status": "AUTHORITATIVE (Phase 7)",
                "Selected?": is_champ,
                "Reason": "Selected champion operational aggregator (cuts FA/hr by 96.4% to 39.57)" if is_champ == "Yes" else ("Tier 1 100% recall operating point" if is_champ == "Tier 1" else "Operational filter evaluation"),
                "Next Experiment": "Behavioral MITRE Attribution & Model Deployment Packaging",
                "Source Artifact": "reports/phase_7/04_alert_aggregation_results.csv"
            })

# Write CSV
out_csv = "research_archive/experiment_registry.csv"
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

# Write Markdown table
out_md = "research_archive/EXPERIMENT_REGISTRY.md"
with open(out_md, "w", encoding="utf-8") as f:
    f.write("# Master Experiment Registry (SIH26153)\n\n")
    f.write(f"Total experiments cataloged: **{len(rows)}**\n\n")
    f.write("Authoritative research log covering Phases 4, 5.5, 6, and 7.\n\n")
    f.write("| Exp ID | Phase | Model | Horizon | Loss | Thresh | Seed | Prec | Rec | F1 | FPR | FA/hr | Ev Recall | Lead (s) | Selected? | Source |\n")
    f.write("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
    for r in rows:
        f.write(f"| {r['Experiment ID']} | {r['Phase']} | {r['Model']} | {r['Forecast Seconds']}s | {r['Loss']} | {r['Threshold']} | {r['Seed']} | {r['Precision']} | {r['Recall']} | {r['F1']} | {r['FPR']} | {r['False Alarms/Hour']} | {r['Event Recall']} | {r['Median Lead Time']} | {r['Selected?']} | `{r['Source Artifact']}` |\n")

print(f"Generated {out_csv} and {out_md} with {len(rows)} experiment records.")
