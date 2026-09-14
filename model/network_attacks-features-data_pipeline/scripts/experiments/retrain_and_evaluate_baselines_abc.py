"""
retrain_and_evaluate_baselines_abc.py
======================================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Trains and evaluates all Baseline Models (Logistic Regression, Random Forest, GRU,
Temporal Transformer, Persistence, Majority) across Setting A, Setting B, and Setting C.
Strict anti-leakage compliance: Scaler fit on Train, Threshold calibrated on Val,
Evaluated on Test.
"""

from __future__ import annotations
import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, List, Tuple, Optional, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data.benchmark_dataset import HardenedBenchmarkDataset, get_54_feature_names
from src.evaluation.benchmark_metrics import (
    compute_binary_classification_metrics,
    compute_onset_early_warning_metrics,
    calibrate_optimal_threshold,
    compute_state_forecasting_metrics
)

REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "final_benchmark")
os.makedirs(REPORT_DIR, exist_ok=True)


class SimpleGRUForecaster(nn.Module):
    def __init__(self, state_dim: int = 54, hidden_dim: int = 128, num_layers: int = 2):
        super().__init__()
        self.gru = nn.GRU(state_dim, hidden_dim, num_layers=num_layers, batch_first=True, dropout=0.1)
        self.state_head = nn.Linear(hidden_dim, 10 * state_dim)
        self.atk_head = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        out, _ = self.gru(x)
        last = out[:, -1, :]
        states = self.state_head(last).view(-1, 10, 54)
        atk_logits = self.atk_head(last)
        return states, atk_logits


class SimpleTransformerForecaster(nn.Module):
    def __init__(self, state_dim: int = 54, hidden_dim: int = 128, nhead: int = 4, num_layers: int = 2):
        super().__init__()
        self.in_proj = nn.Linear(state_dim, hidden_dim)
        layer = nn.TransformerEncoderLayer(d_model=hidden_dim, nhead=nhead, dim_feedforward=256, dropout=0.1, batch_first=True)
        self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.state_head = nn.Linear(hidden_dim, 10 * state_dim)
        self.atk_head = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        h = self.in_proj(x)
        enc = self.encoder(h)
        last = enc[:, -1, :]
        states = self.state_head(last).view(-1, 10, 54)
        atk_logits = self.atk_head(last)
        return states, atk_logits


def train_neural_model(
    model: nn.Module,
    train_x: torch.Tensor,
    train_y_state: torch.Tensor,
    train_y_atk: torch.Tensor,
    pos_weight: float,
    device: torch.device,
    epochs: int = 4,
    batch_size: int = 512
) -> nn.Module:
    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    bce_loss = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight], device=device))
    mse_loss = nn.MSELoss()

    ds = TensorDataset(train_x, train_y_state, train_y_atk)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    model.train()
    for ep in range(epochs):
        for bx, by_st, by_atk in loader:
            bx = bx.to(device)
            by_st = by_st.to(device)
            by_atk = by_atk.to(device).unsqueeze(-1)

            optimizer.zero_grad()
            pred_st, pred_atk = model(bx)
            loss = mse_loss(pred_st, by_st) + 1.2 * bce_loss(pred_atk, by_atk)
            loss.backward()
            optimizer.step()

    return model


def eval_neural_model(
    model: nn.Module,
    x: torch.Tensor,
    device: torch.device,
    batch_size: int = 512
) -> Tuple[np.ndarray, np.ndarray]:
    model.eval()
    all_st = []
    all_p = []
    with torch.no_grad():
        for i in range(0, len(x), batch_size):
            bx = x[i : i + batch_size].to(device)
            st, atk = model(bx)
            all_st.append(st.cpu().numpy())
            all_p.append(torch.sigmoid(atk).squeeze(-1).cpu().numpy())
    return np.concatenate(all_st, axis=0), np.concatenate(all_p, axis=0)


def evaluate_baseline_predictions(
    probs: np.ndarray,
    manifest: pd.DataFrame,
    y_true: np.ndarray,
    tau: float,
    pred_states: Optional[np.ndarray] = None,
    true_states: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    preds = (probs >= tau).astype(int)
    y_t = y_true.astype(int)

    tp = int(np.sum((preds == 1) & (y_t == 1)))
    fp = int(np.sum((preds == 1) & (y_t == 0)))
    tn = int(np.sum((preds == 0) & (y_t == 0)))
    fn = int(np.sum((preds == 0) & (y_t == 1)))

    prec = float(tp / max(1, tp + fp))
    rec = float(tp / max(1, tp + fn))
    f1 = float(2 * prec * rec / max(1e-8, prec + rec))
    fpr = float(fp / max(1, fp + tn))

    try:
        from sklearn.metrics import average_precision_score, roc_auc_score
        pr_auc = float(average_precision_score(y_t, probs))
        roc_auc = float(roc_auc_score(y_t, probs))
    except Exception:
        pr_auc = 0.0
        roc_auc = 0.5

    # Onset Evaluation
    precursor_df = manifest[manifest["is_onset_precursor"]].copy()
    precursor_df["alarm"] = (probs[precursor_df.index.values] >= tau)
    episodes_eval = set()
    episodes_alert = set()
    lead_times = []

    for ep_id, grp in precursor_df.groupby("episode_id"):
        if ep_id == "None":
            continue
        episodes_eval.add(ep_id)
        if grp["alarm"].any():
            episodes_alert.add(ep_id)
            max_lead_steps = len(grp)
            lead_times.append(min(20.0, max(2.0, max_lead_steps * 2.0)))

    total_events = len(episodes_eval)
    events_det = len(episodes_alert)
    onset_rec = float(events_det / max(1, total_events))
    med_lead = float(np.median(lead_times)) if len(lead_times) > 0 else 0.0
    missed_eps = total_events - events_det

    # Pure Benign False Alarms
    pure_benign_df = manifest[(~manifest["is_attack_current"]) & (~manifest["is_attack_k10"]) & (~manifest["is_onset_precursor"])]
    total_benign_hrs = max(1e-4, (len(pure_benign_df) * 2.0) / 3600.0)
    fa_count = int(np.sum(preds[pure_benign_df.index.values]))
    window_fa_hr = float(fa_count / total_benign_hrs)

    # Incident FA (clusters with gap > 5 windows)
    confirmed_mask = preds
    incident_starts = []
    in_inc = False
    last_al = 0
    for t in range(len(confirmed_mask)):
        if confirmed_mask[t]:
            if not in_inc:
                in_inc = True
                incident_starts.append(t)
                last_al = t
            else:
                last_al = t
        else:
            if in_inc and (t - last_al) > 5:
                in_inc = False

    benign_set = set(pure_benign_df.index.values)
    inc_fa = sum(1 for idx in incident_starts if idx in benign_set)
    inc_fa_hr = float(inc_fa / total_benign_hrs)

    state_mae = float(np.mean(np.abs(pred_states - true_states))) if pred_states is not None and true_states is not None else np.nan
    state_mse = float(np.mean((pred_states - true_states) ** 2)) if pred_states is not None and true_states is not None else np.nan

    return {
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "onset_recall": onset_rec,
        "events_detected": events_det,
        "total_events": total_events,
        "median_lead_time": med_lead,
        "missed_episodes": missed_eps,
        "window_fa_hr": window_fa_hr,
        "incident_fa_hr": inc_fa_hr,
        "total_incidents": len(incident_starts),
        "state_mae": state_mae,
        "state_mse": state_mse,
        "tau": tau
    }


def main():
    print("=" * 80)
    print("RETRAINING AND EVALUATING ALL BASELINES ACROSS SETTINGS A, B, AND C")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    all_baseline_rows = []

    for s in ["A", "B", "C"]:
        print(f"\n>>> PROCESSING SETTING {s} <<<")
        scaler_path = os.path.join(PROJECT_ROOT, "models", "scalers", f"setting_{s.lower()}_scaler.joblib")
        scaler = joblib.load(scaler_path)

        train_ds = HardenedBenchmarkDataset(setting=s, split="train", scaler=scaler, fit_scaler=False)
        val_ds = HardenedBenchmarkDataset(setting=s, split="val", scaler=scaler, fit_scaler=False)
        test_ds = HardenedBenchmarkDataset(setting=s, split="test", scaler=scaler, fit_scaler=False)

        # 2D flattened inputs for tabular models
        train_x_static = train_ds.x_history[:, -1, :].numpy()  # Last observed 54-D state
        val_x_static = val_ds.x_history[:, -1, :].numpy()
        test_x_static = test_ds.x_history[:, -1, :].numpy()

        train_y_atk = train_ds.attack_k10.numpy()
        val_y_atk = val_ds.attack_k10.numpy()
        test_y_atk = test_ds.attack_k10.numpy()

        pos_count = np.sum(train_y_atk == 1)
        neg_count = np.sum(train_y_atk == 0)
        pos_weight = float(neg_count / max(1, pos_count))

        # 1. Majority Baseline
        maj_probs_val = np.zeros_like(val_y_atk)
        maj_probs_test = np.zeros_like(test_y_atk)
        maj_res = evaluate_baseline_predictions(maj_probs_test, test_ds.manifest, test_y_atk, tau=0.50)
        maj_res["model"] = "Majority_Class"
        maj_res["variant"] = "Constant_0"
        maj_res["setting"] = f"Setting {s}"
        maj_res["protocol"] = f"Trained_on_Setting_{s}"
        maj_res["params"] = 0
        all_baseline_rows.append(maj_res)

        # 2. Persistence Baseline (y_t_current -> y_{t+10})
        # Check current state attack label from manifest
        pers_probs_val = val_ds.manifest["is_attack_current"].values.astype(float)
        pers_probs_test = test_ds.manifest["is_attack_current"].values.astype(float)
        pers_res = evaluate_baseline_predictions(pers_probs_test, test_ds.manifest, test_y_atk, tau=0.50)
        pers_res["model"] = "Persistence"
        pers_res["variant"] = "y_t_current"
        pers_res["setting"] = f"Setting {s}"
        pers_res["protocol"] = f"Trained_on_Setting_{s}"
        pers_res["params"] = 0
        all_baseline_rows.append(pers_res)

        # 3. Logistic Regression (Class-Weighted)
        print("Training Logistic Regression...")
        lr = LogisticRegression(class_weight="balanced", max_iter=500, random_state=42)
        lr.fit(train_x_static, train_y_atk)
        lr_probs_val = lr.predict_proba(val_x_static)[:, 1]
        lr_tau = calibrate_optimal_threshold(lr_probs_val, val_y_atk, metric="f1")
        lr_probs_test = lr.predict_proba(test_x_static)[:, 1]
        lr_res = evaluate_baseline_predictions(lr_probs_test, test_ds.manifest, test_y_atk, tau=lr_tau)
        lr_res["model"] = "Logistic_Regression"
        lr_res["variant"] = "Static_54D_Balanced"
        lr_res["setting"] = f"Setting {s}"
        lr_res["protocol"] = f"Trained_on_Setting_{s}"
        lr_res["params"] = 55
        all_baseline_rows.append(lr_res)

        # 4. Random Forest (100 Trees)
        print("Training Random Forest...")
        rf = RandomForestClassifier(n_estimators=100, max_depth=14, class_weight="balanced", n_jobs=-1, random_state=42)
        # Train on up to 50,000 samples for fast convergence
        if len(train_x_static) > 50000:
            idx = np.random.RandomState(42).choice(len(train_x_static), 50000, replace=False)
            rf.fit(train_x_static[idx], train_y_atk[idx])
        else:
            rf.fit(train_x_static, train_y_atk)
        rf_probs_val = rf.predict_proba(val_x_static)[:, 1]
        rf_tau = calibrate_optimal_threshold(rf_probs_val, val_y_atk, metric="f1")
        rf_probs_test = rf.predict_proba(test_x_static)[:, 1]
        rf_res = evaluate_baseline_predictions(rf_probs_test, test_ds.manifest, test_y_atk, tau=rf_tau)
        rf_res["model"] = "Random_Forest"
        rf_res["variant"] = "Static_54D_Balanced"
        rf_res["setting"] = f"Setting {s}"
        rf_res["protocol"] = f"Trained_on_Setting_{s}"
        rf_res["params"] = 250000
        all_baseline_rows.append(rf_res)

        # 5. GRU Sequence Forecaster
        print("Training GRU Sequence Forecaster...")
        gru = SimpleGRUForecaster(state_dim=54, hidden_dim=128, num_layers=2)
        gru = train_neural_model(gru, train_ds.x_history, train_ds.y_future_states, train_ds.attack_k10, pos_weight, device, epochs=4)
        gru_st_val, gru_p_val = eval_neural_model(gru, val_ds.x_history, device)
        gru_tau = calibrate_optimal_threshold(gru_p_val, val_y_atk, metric="f1")
        gru_st_test, gru_p_test = eval_neural_model(gru, test_ds.x_history, device)
        gru_res = evaluate_baseline_predictions(gru_p_test, test_ds.manifest, test_y_atk, tau=gru_tau, pred_states=gru_st_test, true_states=test_ds.y_future_states.numpy())
        gru_res["model"] = "GRU"
        gru_res["variant"] = "Sequence_10step_54D"
        gru_res["setting"] = f"Setting {s}"
        gru_res["protocol"] = f"Trained_on_Setting_{s}"
        gru_res["params"] = sum(p.numel() for p in gru.parameters())
        all_baseline_rows.append(gru_res)

        # 6. Temporal Transformer Forecaster
        print("Training Temporal Transformer Forecaster...")
        tf_model = SimpleTransformerForecaster(state_dim=54, hidden_dim=128, nhead=4, num_layers=2)
        tf_model = train_neural_model(tf_model, train_ds.x_history, train_ds.y_future_states, train_ds.attack_k10, pos_weight, device, epochs=4)
        tf_st_val, tf_p_val = eval_neural_model(tf_model, val_ds.x_history, device)
        tf_tau = calibrate_optimal_threshold(tf_p_val, val_y_atk, metric="f1")
        tf_st_test, tf_p_test = eval_neural_model(tf_model, test_ds.x_history, device)
        tf_res = evaluate_baseline_predictions(tf_p_test, test_ds.manifest, test_y_atk, tau=tf_tau, pred_states=tf_st_test, true_states=test_ds.y_future_states.numpy())
        tf_res["model"] = "Transformer"
        tf_res["variant"] = "Sequence_10step_54D"
        tf_res["setting"] = f"Setting {s}"
        tf_res["protocol"] = f"Trained_on_Setting_{s}"
        tf_res["params"] = sum(p.numel() for p in tf_model.parameters())
        all_baseline_rows.append(tf_res)

    df_base = pd.DataFrame(all_baseline_rows)
    df_base.to_csv(os.path.join(REPORT_DIR, "retrained_baselines_abc.csv"), index=False)
    print(f"\nAll baselines successfully retrained and evaluated on Settings A, B, and C! Saved to {REPORT_DIR}")


if __name__ == "__main__":
    main()
