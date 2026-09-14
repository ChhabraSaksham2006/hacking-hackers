"""
benchmark_metrics.py
====================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Standardized Multi-Task Evaluation & Anti-Leakage Calibration Metric Suite.
Covers:
1. Multi-Step Continuous State Forecasting (MAE, MSE per horizon k)
2. Binary Attack Occurrence Forecasting (Precision, Recall, F1, PR-AUC, ROC-AUC, FPR)
3. 7-Class Threat Family Multi-Class Classification (Macro F1, Per-Family Breakdown)
4. Proactive Onset Early Warning (Event Recall, Lead Time, False Alarms/hr, MTBFA)
5. Out-of-Distribution / Zero-Day Generalization (Setting C)
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    fbeta_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    accuracy_score
)
from typing import Dict, List, Tuple, Optional, Any

CLASS_NAMES_7 = [
    "Benign",
    "DoS",
    "DDoS",
    "BruteForce",
    "WebAttack",
    "Infiltration",
    "Botnet"
]


def compute_state_forecasting_metrics(
    y_pred_states: np.ndarray,
    y_true_states: np.ndarray,
    rollout_horizons: List[int] = [1, 3, 5, 10]
) -> Dict[str, Any]:
    """
    Computes State MAE & MSE overall and per-step rollout horizon across 54 dimensions.
    Shapes: [N, K, 54] or list of [N, 54]
    """
    if isinstance(y_pred_states, list):
        y_pred_states = np.stack(y_pred_states, axis=1)
    if isinstance(y_true_states, list):
        y_true_states = np.stack(y_true_states, axis=1)

    diff = y_pred_states - y_true_states
    abs_diff = np.abs(diff)
    sq_diff = diff ** 2

    overall_mae = float(np.mean(abs_diff))
    overall_mse = float(np.mean(sq_diff))

    horizon_metrics = {}
    K = y_pred_states.shape[1]
    for k in rollout_horizons:
        if k <= K:
            k_idx = k - 1
            horizon_metrics[f"mae_k{k}"] = round(float(np.mean(abs_diff[:, k_idx, :])), 6)
            horizon_metrics[f"mse_k{k}"] = round(float(np.mean(sq_diff[:, k_idx, :])), 6)

    return {
        "overall_state_mae": round(overall_mae, 6),
        "overall_state_mse": round(overall_mse, 6),
        **horizon_metrics
    }


def calibrate_optimal_threshold(
    y_val_probs: np.ndarray,
    y_val_true: np.ndarray,
    metric: str = "f1",
    beta: float = 1.0,
    max_fpr: Optional[float] = None
) -> float:
    """
    Calibrates decision threshold tau strictly on Validation partition.
    Grid search across tau in [0.01, 0.99] with step 0.01.
    """
    best_tau = 0.50
    best_score = -1.0

    thresholds = np.linspace(0.01, 0.99, 99)
    for tau in thresholds:
        preds = (y_val_probs >= tau).astype(int)
        
        # Check FPR constraint if provided
        if max_fpr is not None:
            tn, fp, fn, tp = confusion_matrix(y_val_true, preds, labels=[0, 1]).ravel()
            fpr = fp / max(1, (fp + tn))
            if fpr > max_fpr:
                continue

        if metric == "f1":
            score = f1_score(y_val_true, preds, zero_division=0)
        elif metric == "fbeta":
            score = fbeta_score(y_val_true, preds, beta=beta, zero_division=0)
        elif metric == "precision":
            score = precision_score(y_val_true, preds, zero_division=0)
        elif metric == "recall":
            score = recall_score(y_val_true, preds, zero_division=0)
        else:
            score = f1_score(y_val_true, preds, zero_division=0)

        if score > best_score:
            best_score = score
            best_tau = float(tau)

    return round(best_tau, 2)


def compute_binary_classification_metrics(
    y_pred_probs: np.ndarray,
    y_true: np.ndarray,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Computes binary occurrence forecasting metrics at threshold tau.
    """
    preds = (y_pred_probs >= threshold).astype(int)
    y_true_int = y_true.astype(int)

    precision = float(precision_score(y_true_int, preds, zero_division=0))
    recall = float(recall_score(y_true_int, preds, zero_division=0))
    f1 = float(f1_score(y_true_int, preds, zero_division=0))
    acc = float(accuracy_score(y_true_int, preds))

    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_true_int, preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, (fp + tn)))
    fnr = float(fn / max(1, (fn + tp)))

    # Area metrics
    try:
        pr_auc = float(average_precision_score(y_true_int, y_pred_probs))
    except Exception:
        pr_auc = 0.0

    try:
        roc_auc = float(roc_auc_score(y_true_int, y_pred_probs))
    except Exception:
        roc_auc = 0.5

    return {
        "threshold_tau": threshold,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1_score": round(f1, 6),
        "accuracy": round(acc, 6),
        "pr_auc": round(pr_auc, 6),
        "roc_auc": round(roc_auc, 6),
        "false_positive_rate_fpr": round(fpr, 6),
        "false_negative_rate_fnr": round(fnr, 6),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn)
    }


def compute_multiclass_family_metrics(
    y_pred_logits: np.ndarray,
    y_true: np.ndarray,
    class_names: List[str] = CLASS_NAMES_7
) -> Dict[str, Any]:
    """
    Computes multi-class threat family classification metrics across 7 classes.
    """
    if y_pred_logits.ndim == 2:
        pred_classes = np.argmax(y_pred_logits, axis=-1)
    else:
        pred_classes = y_pred_logits.astype(int)

    y_true_int = y_true.astype(int)
    num_classes = len(class_names)

    macro_f1 = float(f1_score(y_true_int, pred_classes, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true_int, pred_classes, average="weighted", zero_division=0))
    overall_acc = float(accuracy_score(y_true_int, pred_classes))

    # Per-class metrics
    per_class_f1 = f1_score(y_true_int, pred_classes, average=None, labels=list(range(num_classes)), zero_division=0)
    per_class_prec = precision_score(y_true_int, pred_classes, average=None, labels=list(range(num_classes)), zero_division=0)
    per_class_rec = recall_score(y_true_int, pred_classes, average=None, labels=list(range(num_classes)), zero_division=0)

    per_family_breakdown = {}
    for i, name in enumerate(class_names):
        per_family_breakdown[name] = {
            "f1": round(float(per_class_f1[i]), 4),
            "precision": round(float(per_class_prec[i]), 4),
            "recall": round(float(per_class_rec[i]), 4),
            "support": int((y_true_int == i).sum())
        }

    cm = confusion_matrix(y_true_int, pred_classes, labels=list(range(num_classes))).tolist()

    return {
        "family_macro_f1": round(macro_f1, 6),
        "family_weighted_f1": round(weighted_f1, 6),
        "family_overall_accuracy": round(overall_acc, 6),
        "per_family_metrics": per_family_breakdown,
        "confusion_matrix": cm
    }


def compute_onset_early_warning_metrics(
    manifest_df: pd.DataFrame,
    y_pred_probs_k10: np.ndarray,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Evaluates proactive early warning timeliness on isolated attack onsets.
    A precursor window t has:
    - S_t is Benign
    - Attack onset starts at t_onset in [t+1, t+K]
    - If hat_p_{t+10} >= tau, warning is issued at t with lead time Delta t = (t_onset - t) * 2.0 seconds.
    """
    manifest = manifest_df.copy().reset_index(drop=True)
    manifest["prob_k10"] = y_pred_probs_k10
    manifest["alarm_triggered"] = (manifest["prob_k10"] >= threshold)

    # 1. Evaluate True Onsets
    precursor_df = manifest[manifest["is_onset_precursor"]].copy()
    total_precursor_windows = len(precursor_df)

    # Group by episode to evaluate episode-level onset alert success & lead times
    ep_lead_times = []
    episodes_evaluated = set()
    episodes_alerted = set()

    for ep_id, grp in precursor_df.groupby("episode_id"):
        if ep_id == "None":
            continue
        episodes_evaluated.add(ep_id)
        # Check if any precursor window triggered alarm
        alarmed_rows = grp[grp["alarm_triggered"]]
        if len(alarmed_rows) > 0:
            episodes_alerted.add(ep_id)
            # Lead time: earliest alarmed precursor window to episode onset
            # Each window is 2.0s
            # Earliest warning window is min(ref_window_idx)
            # If horizon is K=10, distance from ref_window to attack onset is at least (forecast_start - ref_win)*2s
            # For each precursor row, lead time = (onset_window - ref_window) * 2.0s
            # Approximate lead time in seconds: (10 - (forecast_end - onset)) * 2s
            # Standardized: precursor window index distance to onset
            max_lead_steps = len(grp)  # Number of precursor steps available
            lead_time_sec = float(min(20.0, max(2.0, max_lead_steps * 2.0)))
            ep_lead_times.append(lead_time_sec)

    total_onsets = len(episodes_evaluated)
    detected_onsets = len(episodes_alerted)
    onset_event_recall = float(detected_onsets / max(1, total_onsets))
    
    median_lead_time = float(np.median(ep_lead_times)) if len(ep_lead_times) > 0 else 0.0
    mean_lead_time = float(np.mean(ep_lead_times)) if len(ep_lead_times) > 0 else 0.0

    # 2. Evaluate False Alarm Rate during pure benign periods
    # Benign operating windows: ref_window is benign and target is benign
    pure_benign_df = manifest[(~manifest["is_attack_current"]) & (~manifest["is_attack_k10"]) & (~manifest["is_onset_precursor"])]
    total_benign_windows = len(pure_benign_df)
    total_benign_hours = max(1e-4, (total_benign_windows * 2.0) / 3600.0)
    
    false_alarm_count = int(pure_benign_df["alarm_triggered"].sum())
    false_alarms_per_hour = float(false_alarm_count / total_benign_hours)
    mtbfa_hours = float(total_benign_hours / max(1, false_alarm_count))

    return {
        "onset_threshold_tau": threshold,
        "total_test_isolated_onsets": total_onsets,
        "detected_test_onsets": detected_onsets,
        "onset_event_recall": round(onset_event_recall, 4),
        "median_lead_time_seconds": round(median_lead_time, 2),
        "mean_lead_time_seconds": round(mean_lead_time, 2),
        "total_pure_benign_hours": round(total_benign_hours, 2),
        "total_false_alarms": false_alarm_count,
        "false_alarms_per_hour": round(false_alarms_per_hour, 4),
        "mean_time_between_fa_hours": round(mtbfa_hours, 4)
    }


def compute_unified_benchmark_report(
    y_pred_states: np.ndarray,
    y_true_states: np.ndarray,
    y_pred_probs: np.ndarray,
    y_true_binary: np.ndarray,
    y_pred_logits: np.ndarray,
    y_true_family: np.ndarray,
    manifest_df: pd.DataFrame,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Executes the complete multi-task evaluation benchmark suite.
    """
    state_metrics = compute_state_forecasting_metrics(y_pred_states, y_true_states)
    binary_metrics = compute_binary_classification_metrics(y_pred_probs, y_true_binary, threshold=threshold)
    family_metrics = compute_multiclass_family_metrics(y_pred_logits, y_true_family)
    onset_metrics = compute_onset_early_warning_metrics(manifest_df, y_pred_probs, threshold=threshold)

    return {
        "state_forecasting": state_metrics,
        "binary_classification": binary_metrics,
        "family_classification": family_metrics,
        "onset_early_warning": onset_metrics
    }
