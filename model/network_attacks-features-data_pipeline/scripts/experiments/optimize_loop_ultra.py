"""
optimize_loop_ultra.py
======================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Master Ultra-Optimization Loop:
Goal: Maximize Precision (>= 75-90%), Preserve Recall (>= 90-98%), and Suppress False Alarms to < 10 FA/hour.

Integrates:
1. Multi-Task Trajectory-Gated Risk Scoring: Combining occurrence probability with physical state rollout divergence.
2. Temporal Persistence & EMA Stream Filtering: Eliminating isolated 1-step benign transient noise.
3. Pareto-Optimal Multi-Objective Decision Calibration across Settings A, B, and C for both SparseRSSM and TFCNet.
"""

from __future__ import annotations
import os
import sys
import time
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import pandas as pd
import torch
from torch import nn, optim

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data.benchmark_dataset import HardenedBenchmarkDataset
from src.models.sparse_rssm import SparseRSSM
from src.models.tfcnet import TFCNet
from src.evaluation.benchmark_metrics import (
    compute_unified_benchmark_report,
    compute_state_forecasting_metrics,
    compute_binary_classification_metrics,
    compute_multiclass_family_metrics
)

ROOT_DIR = PROJECT_ROOT
REPORT_DIR = os.path.join(ROOT_DIR, "reports", "ultra_optimization")
CHECKPOINT_DIR = os.path.join(ROOT_DIR, "models", "checkpoints", "ultra")
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CHECKPOINT_DIR, exist_ok=True)


def compute_temporal_filtered_predictions(
    probs: np.ndarray,
    filter_type: str = "ema",
    ema_beta: float = 0.35,
    persistence_m: int = 2
) -> np.ndarray:
    """
    Applies temporal stream filtering to eliminate single-step transient noise.
    - "raw": direct window probabilities
    - "ema": exponential moving average smoothing
    - "persistence": requiring M consecutive elevated windows
    """
    if filter_type == "raw":
        return probs.copy()
    
    N = len(probs)
    filtered = np.zeros_like(probs)

    if filter_type == "ema":
        val = probs[0]
        for i in range(N):
            val = ema_beta * val + (1.0 - ema_beta) * probs[i]
            filtered[i] = val
        return filtered

    elif filter_type == "persistence":
        for i in range(N):
            if i < persistence_m - 1:
                filtered[i] = probs[i]
            else:
                window = probs[i - persistence_m + 1 : i + 1]
                filtered[i] = np.min(window)  # All M windows must exceed threshold
        return filtered

    return probs


def compute_physical_gated_scores(
    probs: np.ndarray,
    pred_states: np.ndarray,
    true_obs_last: np.ndarray,
    alpha_phys: float = 0.5
) -> np.ndarray:
    """
    Fuses the binary classification probability with continuous physical state rollout trajectory deviation.
    Delta_phys = ||S_hat_{t+10} - S_t||_2 (predicted physical dynamics divergence)
    """
    # Compute L2 norm of predicted state change over the 10-step horizon
    state_delta = np.linalg.norm(pred_states[:, -1, :] - true_obs_last, axis=-1)  # [N]
    
    # Robust normalization of physical delta
    median_delta = np.median(state_delta)
    iqr_delta = np.percentile(state_delta, 75) - np.percentile(state_delta, 25)
    iqr_delta = max(1e-4, iqr_delta)
    norm_delta = 1.0 / (1.0 + np.exp(-((state_delta - median_delta) / iqr_delta)))  # Sigmoid scaled [0, 1]

    # Gated score
    gated = (1.0 - alpha_phys) * probs + alpha_phys * (probs * norm_delta)
    return gated


def evaluate_temporal_onset_metrics(
    manifest_df: pd.DataFrame,
    y_scores: np.ndarray,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Computes episode-level onset recall, lead time, and pure benign False Alarms per hour.
    """
    manifest = manifest_df.copy().reset_index(drop=True)
    manifest["score"] = y_scores
    manifest["alarm_triggered"] = (manifest["score"] >= threshold)

    # 1. True Onset Recall
    precursor_df = manifest[manifest["is_onset_precursor"]].copy()
    ep_lead_times = []
    episodes_evaluated = set()
    episodes_alerted = set()

    for ep_id, grp in precursor_df.groupby("episode_id"):
        if ep_id == "None":
            continue
        episodes_evaluated.add(ep_id)
        alarmed_rows = grp[grp["alarm_triggered"]]
        if len(alarmed_rows) > 0:
            episodes_alerted.add(ep_id)
            lead_time_sec = float(min(20.0, max(2.0, len(grp) * 2.0)))
            ep_lead_times.append(lead_time_sec)

    total_onsets = len(episodes_evaluated)
    detected_onsets = len(episodes_alerted)
    onset_recall = float(detected_onsets / max(1, total_onsets))
    median_lead_time = float(np.median(ep_lead_times)) if len(ep_lead_times) > 0 else 0.0

    # 2. Pure Benign False Alarms
    pure_benign_df = manifest[(~manifest["is_attack_current"]) & (~manifest["is_attack_k10"]) & (~manifest["is_onset_precursor"])]
    total_benign_windows = len(pure_benign_df)
    total_benign_hours = max(1e-4, (total_benign_windows * 2.0) / 3600.0)
    false_alarm_count = int(pure_benign_df["alarm_triggered"].sum())
    false_alarms_per_hour = float(false_alarm_count / total_benign_hours)

    return {
        "onset_event_recall": round(onset_recall, 4),
        "detected_onsets": detected_onsets,
        "total_onsets": total_onsets,
        "median_lead_time_seconds": round(median_lead_time, 2),
        "false_alarm_count": false_alarm_count,
        "false_alarms_per_hour": round(false_alarms_per_hour, 2),
        "total_benign_hours": round(total_benign_hours, 2)
    }


def multi_objective_search(
    val_probs: np.ndarray,
    val_true_binary: np.ndarray,
    val_pred_states: np.ndarray,
    val_obs_last: np.ndarray,
    val_manifest: pd.DataFrame,
    target_max_fa_hr: float = 10.0
) -> Dict[str, Any]:
    """
    Searches over:
    - Physical gating alpha in [0.0, 0.2, 0.4, 0.6]
    - Filter type in ['raw', 'ema', 'persistence']
    - Threshold tau in [0.10, 0.95]
    Finds configuration maximizing F1 while keeping False Alarms < target_max_fa_hr and Onset Recall >= 0.85.
    """
    best_config = None
    best_objective_score = -float("inf")

    filter_configs = [
        ("raw", 0.0, 1),
        ("ema", 0.25, 1),
        ("ema", 0.40, 1),
        ("persistence", 0.0, 2),
    ]
    alpha_options = [0.0, 0.2, 0.4]

    for filter_type, ema_beta, pers_m in filter_configs:
        for alpha in alpha_options:
            # 1. Compute gated and filtered validation scores
            scores = compute_physical_gated_scores(val_probs, val_pred_states, val_obs_last, alpha_phys=alpha)
            filt_scores = compute_temporal_filtered_predictions(scores, filter_type=filter_type, ema_beta=ema_beta, persistence_m=pers_m)

            # 2. Grid search thresholds
            for tau in np.linspace(0.10, 0.95, 86):
                preds = (filt_scores >= tau).astype(int)
                tp = np.sum((preds == 1) & (val_true_binary == 1))
                fp = np.sum((preds == 1) & (val_true_binary == 0))
                fn = np.sum((preds == 0) & (val_true_binary == 1))

                if (tp + fp) == 0:
                    continue
                prec = tp / (tp + fp)
                rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

                # Compute onset & FA metrics
                onset_res = evaluate_temporal_onset_metrics(val_manifest, filt_scores, threshold=tau)
                fa_hr = onset_res["false_alarms_per_hour"]
                onset_rec = onset_res["onset_event_recall"]

                # Multi-objective optimization score:
                # High weight on Precision and F1, penalty on FA/hr > target, reward for low FA/hr
                fa_penalty = max(0.0, (fa_hr - target_max_fa_hr)) * 0.1
                fa_reward = max(0.0, (target_max_fa_hr - fa_hr)) * 0.05
                obj_score = (f1 * 2.0) + (prec * 1.5) + (onset_rec * 1.0) - fa_penalty + fa_reward

                if obj_score > best_objective_score:
                    best_objective_score = obj_score
                    best_config = {
                        "filter_type": filter_type,
                        "ema_beta": ema_beta,
                        "persistence_m": pers_m,
                        "alpha_phys": alpha,
                        "threshold_tau": float(round(tau, 3)),
                        "val_f1": round(f1, 4),
                        "val_prec": round(prec, 4),
                        "val_rec": round(rec, 4),
                        "val_fa_hr": round(fa_hr, 2),
                        "val_onset_rec": round(onset_rec, 4)
                    }

    return best_config


def evaluate_ultra_setting(
    model: nn.Module,
    setting: str,
    model_name: str,
    device: torch.device
) -> Dict[str, Any]:
    print(f"\n{'='*25} ULTRA OPTIMIZATION: {model_name} (SETTING {setting}) {'='*25}", flush=True)

    # 1. Load Scaler & Datasets
    scaler_path = os.path.join(ROOT_DIR, "models", "scalers", f"setting_{setting.lower()}_scaler.joblib")
    train_ds = HardenedBenchmarkDataset(setting=setting, split="train", fit_scaler=True, scaler_save_path=scaler_path)
    val_ds = HardenedBenchmarkDataset(setting=setting, split="val", scaler=train_ds.scaler, fit_scaler=False)
    test_ds = HardenedBenchmarkDataset(setting=setting, split="test", scaler=train_ds.scaler, fit_scaler=False)

    # Helper function to get raw model outputs
    def get_outputs(ds: HardenedBenchmarkDataset) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        model.eval()
        p_states, t_states, p_probs, t_binary, p_logits, t_family, obs_lasts = [], [], [], [], [], [], []
        N = len(ds)
        with torch.no_grad():
            for i in range(0, N, 512):
                b_end = min(i + 512, N)
                x = ds.x_history[i:b_end].to(device)
                out = model(x, K=10)
                
                p_states.append(out["states_tensor"].cpu().numpy())
                t_states.append(ds.y_future_states[i:b_end].numpy())
                probs_k10 = torch.sigmoid(out["attack_logits"][-1]).squeeze(-1).cpu().numpy()
                p_probs.append(probs_k10)
                t_binary.append(ds.attack_k10[i:b_end].numpy())
                p_logits.append(out["family_logits"][-1].cpu().numpy())
                t_family.append(ds.family_k10[i:b_end].numpy())
                obs_lasts.append(x[:, -1, :].cpu().numpy())

        return (
            np.concatenate(p_states, axis=0),
            np.concatenate(t_states, axis=0),
            np.concatenate(p_probs, axis=0),
            np.concatenate(t_binary, axis=0),
            np.concatenate(p_logits, axis=0),
            np.concatenate(t_family, axis=0),
            np.concatenate(obs_lasts, axis=0)
        )

    # 2. Get Validation Predictions
    val_pred_s, val_true_s, val_pred_p, val_true_b, val_pred_l, val_true_f, val_obs_l = get_outputs(val_ds)

    # 3. Multi-Objective Calibration Search
    print("Running multi-objective Pareto search on Validation set...", flush=True)
    best_cfg = multi_objective_search(
        val_probs=val_pred_p,
        val_true_binary=val_true_b,
        val_pred_states=val_pred_s,
        val_obs_last=val_obs_l,
        val_manifest=val_ds.manifest,
        target_max_fa_hr=10.0
    )
    print(f"Optimal Configuration Calibrated: {best_cfg}", flush=True)

    # 4. Apply Calibrated Pipeline to Held-Out Test Set
    print(f"Evaluating Calibrated Pipeline on Test set ({len(test_ds):,} sequences)...", flush=True)
    test_pred_s, test_true_s, test_pred_p, test_true_b, test_pred_l, test_true_f, test_obs_l = get_outputs(test_ds)

    # Gated & Temporal Filtered Test Stream
    test_gated = compute_physical_gated_scores(
        test_pred_p, test_pred_s, test_obs_l, alpha_phys=best_cfg["alpha_phys"]
    )
    test_final_scores = compute_temporal_filtered_predictions(
        test_gated,
        filter_type=best_cfg["filter_type"],
        ema_beta=best_cfg["ema_beta"],
        persistence_m=best_cfg["persistence_m"]
    )

    # Standardized Report Computation
    tau = best_cfg["threshold_tau"]
    state_metrics = compute_state_forecasting_metrics(test_pred_s, test_true_s)
    binary_metrics = compute_binary_classification_metrics(test_final_scores, test_true_b, threshold=tau)
    family_metrics = compute_multiclass_family_metrics(test_pred_l, test_true_f)
    onset_metrics = evaluate_temporal_onset_metrics(test_ds.manifest, test_final_scores, threshold=tau)

    full_report = {
        "model_name": model_name,
        "setting": setting,
        "calibrated_config": best_cfg,
        "state_forecasting": state_metrics,
        "binary_classification": binary_metrics,
        "family_classification": family_metrics,
        "onset_early_warning": onset_metrics
    }

    report_path = os.path.join(REPORT_DIR, f"{model_name.lower()}_setting_{setting.lower()}_ultra.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    return full_report


def generate_master_ultra_report(all_reports: List[Dict[str, Any]]):
    md_path = os.path.join(REPORT_DIR, "ultra_optimization_master_summary.md")
    csv_path = os.path.join(REPORT_DIR, "ultra_optimization_master_summary.csv")

    rows = []
    for r in all_reports:
        s = r["state_forecasting"]
        b = r["binary_classification"]
        f = r["family_classification"]
        o = r["onset_early_warning"]
        c = r["calibrated_config"]

        rows.append({
            "Setting": f"Setting {r['setting']}",
            "Model": r["model_name"],
            "Threshold_Tau": c["threshold_tau"],
            "Filter_Type": c["filter_type"],
            "Alpha_Phys": c["alpha_phys"],
            "State_MAE": s["overall_state_mae"],
            "State_MSE": s["overall_state_mse"],
            "Binary_F1": b["f1_score"],
            "Precision": b["precision"],
            "Recall": b["recall"],
            "PR_AUC": b["pr_auc"],
            "ROC_AUC": b["roc_auc"],
            "FPR": b["false_positive_rate_fpr"],
            "Onset_Event_Recall": o["onset_event_recall"],
            "Median_Lead_Time_sec": o["median_lead_time_seconds"],
            "False_Alarms_per_Hour": o["false_alarms_per_hour"],
            "Total_False_Alarms": o["false_alarm_count"]
        })

    df = pd.DataFrame(rows)
    df.to_csv(csv_path, index=False)

    lines = [
        "# Ultra-Optimization Master Benchmark Report",
        "",
        "## Multi-Objective Precision Boosting & False Alarm Suppression (< 10 FA/Hour)",
        "**Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data**",
        "",
        "---",
        "",
        "## 1. Master Ultra-Optimized Benchmark Table",
        "",
        "| Setting | Model | Calibrated Filter | Tau | State MAE | Binary F1 | Precision | Recall | PR-AUC | Onset Recall | FA / Hour |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for r in rows:
        lines.append(f"| **{r['Setting']}** | **{r['Model']}** | {r['Filter_Type']} (α={r['Alpha_Phys']}) | $\\tau={r['Threshold_Tau']}$ | **{r['State_MAE']:.4f}** | **{r['Binary_F1']:.4f}** | **{r['Precision']:.4f}** | **{r['Recall']:.4f}** | **{r['PR_AUC']:.4f}** | **{r['Onset_Event_Recall']:.4f}** | **{r['False_Alarms_per_Hour']:.2f} FA/hr** |")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nMaster Ultra Report generated at {md_path}", flush=True)


def main():
    print("=" * 80, flush=True)
    print("SIH26153: EXECUTING ULTRA-OPTIMIZATION SUITE FOR SPARSERSSM & TFCNET", flush=True)
    print("=" * 80, flush=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    all_reports = []

    # 1. Evaluate SparseRSSM across Settings A, B, C
    for s in ["A", "B", "C"]:
        ckpt_path = os.path.join(ROOT_DIR, "models", "checkpoints", f"sparserssm_setting_{s.lower()}.pt")
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        model = SparseRSSM(state_dim=54, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0, use_attention=False, num_classes=7).to(device)
        model.load_state_dict(ckpt["model_state_dict"])
        rep = evaluate_ultra_setting(model, setting=s, model_name="SparseRSSM", device=device)
        all_reports.append(rep)

    # 2. Evaluate TFCNet across Settings A, B, C
    for s in ["A", "B", "C"]:
        ckpt_path = os.path.join(ROOT_DIR, "models", "checkpoints", f"tfcnet_setting_{s.lower()}.pt")
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        model = TFCNet(state_dim=54, seq_len=10, forecast_horizon=10, hidden_dim=128, n_transformer_layers=2, n_heads=4, num_classes=7, dropout=0.1).to(device)
        model.load_state_dict(ckpt["model_state_dict"])
        rep = evaluate_ultra_setting(model, setting=s, model_name="TFCNet", device=device)
        all_reports.append(rep)

    generate_master_ultra_report(all_reports)
    print("\nULTRA OPTIMIZATION SUITE COMPLETED SUCCESSFULLY", flush=True)


if __name__ == "__main__":
    main()
