"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.evaluation.metrics

Comprehensive Evaluation & Multi-Metric Suite for Temporal Attack Forecasting.
Computes binary classification metrics, optimal validation thresholds,
continuous state forecasting metrics, attack family multiclass metrics,
and time-to-attack onset metrics with censoring awareness.
"""

from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
    mean_absolute_error,
    mean_squared_error
)

from src.temporal.state_aggregator import FAMILY_TO_IDX

IDX_TO_FAMILY = {v: k for k, v in FAMILY_TO_IDX.items()}


def find_optimal_threshold(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    metric: str = "f1",
    num_thresholds: int = 101
) -> Tuple[float, Dict[str, float]]:
    """
    Finds the optimal decision threshold strictly on validation data.
    """
    y_true = np.asarray(y_true).astype(int)
    y_probs = np.asarray(y_probs).astype(float)

    # Edge cases
    if len(np.unique(y_true)) < 2:
        return 0.5, compute_binary_metrics(y_true, (y_probs >= 0.5).astype(int), y_probs)

    best_thresh = 0.5
    best_score = -1.0
    best_metrics = {}

    thresholds = np.linspace(0.01, 0.99, num_thresholds)
    for t in thresholds:
        preds = (y_probs >= t).astype(int)
        if metric == "f1":
            score = f1_score(y_true, preds, zero_division=0)
        elif metric == "precision":
            score = precision_score(y_true, preds, zero_division=0)
        elif metric == "recall":
            score = recall_score(y_true, preds, zero_division=0)
        else:
            score = f1_score(y_true, preds, zero_division=0)

        if score > best_score:
            best_score = score
            best_thresh = float(t)

    best_preds = (y_probs >= best_thresh).astype(int)
    best_metrics = compute_binary_metrics(y_true, best_preds, y_probs)
    best_metrics["optimal_threshold"] = best_thresh
    return best_thresh, best_metrics


def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_probs: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    """
    Computes comprehensive binary classification metrics for attack presence.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = [int(x) for x in cm.ravel()]
    else:
        tn, fp, fn, tp = int(cm[0, 0]), 0, 0, 0

    # ROC-AUC & PR-AUC
    roc_auc = 0.5
    pr_auc = float(np.mean(y_true == 1))
    if y_probs is not None and len(np.unique(y_true)) > 1:
        try:
            roc_auc = float(roc_auc_score(y_true, y_probs))
        except Exception:
            roc_auc = 0.5
        try:
            p_curve, r_curve, _ = precision_recall_curve(y_true, y_probs)
            pr_auc = float(auc(r_curve, p_curve))
        except Exception:
            pr_auc = 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def compute_state_forecasting_metrics(
    y_true_states: np.ndarray,
    y_pred_states: np.ndarray
) -> Dict[str, float]:
    """
    Computes continuous state vector forecasting accuracy across 54 dimensions.
    """
    y_true = np.asarray(y_true_states, dtype=np.float32)
    y_pred = np.asarray(y_pred_states, dtype=np.float32)

    mae = float(mean_absolute_error(y_true, y_pred))
    rmse = float(np.sqrt(mean_squared_error(y_true, y_pred)))
    return {
        "state_mae": round(mae, 4),
        "state_rmse": round(rmse, 4)
    }


def compute_family_classification_metrics(
    y_true_family: np.ndarray,
    y_pred_family: np.ndarray
) -> Dict[str, Any]:
    """
    Computes multiclass attack family metrics on attack-containing targets.
    """
    y_true = np.asarray(y_true_family).astype(int)
    y_pred = np.asarray(y_pred_family).astype(int)

    # Filter strictly to attack instances (family > 0)
    atk_mask = y_true > 0
    if np.sum(atk_mask) == 0:
        return {
            "family_macro_f1": 0.0,
            "family_weighted_f1": 0.0,
            "per_family_f1": {}
        }

    y_true_atk = y_true[atk_mask]
    y_pred_atk = y_pred[atk_mask]

    macro_f1 = float(f1_score(y_true_atk, y_pred_atk, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true_atk, y_pred_atk, average="weighted", zero_division=0))

    per_fam = {}
    for fam_name, fam_idx in FAMILY_TO_IDX.items():
        if fam_idx == 0:
            continue
        mask = y_true_atk == fam_idx
        if np.sum(mask) > 0:
            f1_fam = f1_score((y_true_atk == fam_idx).astype(int), (y_pred_atk == fam_idx).astype(int), zero_division=0)
            per_fam[fam_name] = round(float(f1_fam), 4)

    return {
        "family_macro_f1": round(macro_f1, 4),
        "family_weighted_f1": round(weighted_f1, 4),
        "per_family_f1": per_fam
    }


def compute_tau_metrics(
    tau_true: np.ndarray,
    tau_pred: np.ndarray
) -> Dict[str, float]:
    """
    Computes onset timer accuracy with separate handling for event vs censored windows.
    """
    y_t = np.asarray(tau_true, dtype=np.float32)
    y_p = np.asarray(tau_pred, dtype=np.float32)
    y_p = np.clip(y_p, 0.0, 300.0)

    overall_mae = float(np.mean(np.abs(y_t - y_p)))
    overall_med_ae = float(np.median(np.abs(y_t - y_p)))

    # Event windows (attack occurs within 300s)
    event_mask = y_t < 300.0
    event_mae = float(np.mean(np.abs(y_t[event_mask] - y_p[event_mask]))) if np.sum(event_mask) > 0 else 0.0

    # Censored windows (no attack within session / ceiling)
    censored_mask = y_t == 300.0
    censored_mae = float(np.mean(np.abs(y_t[censored_mask] - y_p[censored_mask]))) if np.sum(censored_mask) > 0 else 0.0

    return {
        "tau_overall_mae": round(overall_mae, 2),
        "tau_overall_med_ae": round(overall_med_ae, 2),
        "tau_event_mae": round(event_mae, 2),
        "tau_censored_mae": round(censored_mae, 2)
    }
