"""
train_benchmark_tfcnet.py
=========================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Phase 6: TFCNet Standardized Benchmark Training & Multi-Task Evaluation
Trains TFCNet across:
- Setting A (Seen Attack Generalization)
- Setting B (Mixed Temporal Shift Generalization)
- Setting C (Strict Out-of-Distribution / Zero-Day Generalization)

Computes standardized metrics across State Forecasting (MAE/MSE),
Occurrence Forecasting (F1, PR-AUC, ROC-AUC, FPR), Threat Classification,
and Early Onset Warning (Lead Time, FA/Hour, Onset Recall).
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
from torch.optim.lr_scheduler import CosineAnnealingLR

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data.benchmark_dataset import HardenedBenchmarkDataset
from src.models.tfcnet import TFCNet
from src.evaluation.benchmark_metrics import (
    compute_unified_benchmark_report,
    calibrate_optimal_threshold
)

ROOT_DIR = PROJECT_ROOT
CHECKPOINT_DIR = os.path.join(ROOT_DIR, "models", "checkpoints")
REPORT_DIR = os.path.join(ROOT_DIR, "reports", "phase_6")
os.makedirs(CHECKPOINT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def evaluate_dataset(
    model: nn.Module,
    dataset: HardenedBenchmarkDataset,
    device: torch.device,
    batch_size: int = 512
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, float]:
    model.eval()
    all_pred_states = []
    all_true_states = []
    all_pred_probs = []
    all_true_binary = []
    all_pred_logits = []
    all_true_family = []
    total_val_loss = 0.0
    num_batches = 0

    N = len(dataset)
    with torch.no_grad():
        for i in range(0, N, batch_size):
            b_end = min(i + batch_size, N)
            x = dataset.x_history[i:b_end].to(device)
            y_states = dataset.y_future_states[i:b_end].to(device)
            y_att = dataset.attack_k10[i:b_end].to(device)
            y_fam = dataset.family_k10[i:b_end].to(device)

            out = model(x, K=10)
            loss, _ = model.compute_loss(
                out, x, y_states, y_att, y_fam,
                lambda_state=1.0, lambda_attack=1.0, lambda_family=0.5,
                pos_weight=torch.tensor([1.5], device=device)
            )
            total_val_loss += loss.item()
            num_batches += 1

            all_pred_states.append(out["states_tensor"].cpu().numpy())
            all_true_states.append(y_states.cpu().numpy())
            probs_k10 = torch.sigmoid(out["attack_logits"][-1]).squeeze(-1).cpu().numpy()
            all_pred_probs.append(probs_k10)
            all_true_binary.append(y_att.cpu().numpy())
            all_pred_logits.append(out["family_logits"][-1].cpu().numpy())
            all_true_family.append(y_fam.cpu().numpy())

    return (
        np.concatenate(all_pred_states, axis=0),
        np.concatenate(all_true_states, axis=0),
        np.concatenate(all_pred_probs, axis=0),
        np.concatenate(all_true_binary, axis=0),
        np.concatenate(all_pred_logits, axis=0),
        np.concatenate(all_true_family, axis=0),
        total_val_loss / max(1, num_batches)
    )


def train_single_setting(
    setting: str,
    epochs: int = 4,
    samples_per_epoch: int = 18000,
    batch_size: int = 256,
    lr: float = 1e-3
) -> Dict[str, Any]:
    print(f"\n{'='*30} TRAINING TFCNET: SETTING {setting} {'='*30}", flush=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device} | CPU threads: {torch.get_num_threads()} | Batch Size: {batch_size}", flush=True)

    # 1. Load Datasets
    t0 = time.time()
    scaler_path = os.path.join(ROOT_DIR, "models", "scalers", f"setting_{setting.lower()}_scaler.joblib")
    
    train_ds = HardenedBenchmarkDataset(setting=setting, split="train", fit_scaler=True, scaler_save_path=scaler_path)
    val_ds = HardenedBenchmarkDataset(setting=setting, split="val", scaler=train_ds.scaler, fit_scaler=False)
    test_ds = HardenedBenchmarkDataset(setting=setting, split="test", scaler=train_ds.scaler, fit_scaler=False)
    
    data_time = time.time() - t0
    print(f"Datasets prepared in {data_time:.2f}s (Train: {len(train_ds):,}, Val: {len(val_ds):,}, Test: {len(test_ds):,})", flush=True)

    # 2. Instantiate TFCNet
    model = TFCNet(
        state_dim=54,
        seq_len=10,
        forecast_horizon=10,
        hidden_dim=128,
        n_transformer_layers=2,
        n_heads=4,
        num_classes=7,
        dropout=0.1
    ).to(device)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    balanced_pos_weight = torch.tensor([1.5], device=device)

    best_val_loss = float("inf")
    best_checkpoint_path = os.path.join(CHECKPOINT_DIR, f"tfcnet_setting_{setting.lower()}.pt")
    
    training_history = []
    train_start = time.time()

    # Stratification indices
    att_indices = torch.where(train_ds.attack_k10 == 1.0)[0]
    ben_indices = torch.where(train_ds.attack_k10 == 0.0)[0]
    num_attacks = len(att_indices)

    # 3. Training Loop
    for epoch in range(1, epochs + 1):
        model.train()
        ep_t0 = time.time()
        
        target_benign = min(len(ben_indices), max(samples_per_epoch - num_attacks, num_attacks))
        perm_ben = ben_indices[torch.randperm(len(ben_indices))[:target_benign]]
        epoch_indices = torch.cat([att_indices, perm_ben])[torch.randperm(num_attacks + target_benign)]
        
        N_ep = len(epoch_indices)
        epoch_loss = 0.0
        recon_acc = 0.0
        rollout_acc = 0.0
        atk_acc = 0.0
        fam_acc = 0.0
        num_batches = 0

        for s in range(0, N_ep, batch_size):
            b_idx = epoch_indices[s : s + batch_size]
            x = train_ds.x_history[b_idx].to(device)
            y_states = train_ds.y_future_states[b_idx].to(device)
            y_att = train_ds.attack_k10[b_idx].to(device)
            y_fam = train_ds.family_k10[b_idx].to(device)

            optimizer.zero_grad()
            out = model(x, K=10)
            loss, l_dict = model.compute_loss(
                out, x, y_states, y_att, y_fam,
                lambda_state=1.0,
                lambda_attack=1.0,
                lambda_family=0.5,
                pos_weight=balanced_pos_weight
            )
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()

            epoch_loss += loss.item()
            recon_acc += l_dict["recon_mse"]
            rollout_acc += l_dict["rollout_mse"]
            atk_acc += l_dict["attack_bce"]
            fam_acc += l_dict["family_ce"]
            num_batches += 1

        scheduler.step()
        ep_time = time.time() - ep_t0

        avg_train_loss = epoch_loss / max(1, num_batches)
        avg_recon = recon_acc / max(1, num_batches)
        avg_rollout = rollout_acc / max(1, num_batches)
        avg_atk = atk_acc / max(1, num_batches)
        avg_fam = fam_acc / max(1, num_batches)

        # Quick validation
        _, _, _, _, _, _, val_loss = evaluate_dataset(model, val_ds, device, batch_size=512)

        print(f"Epoch [{epoch:02d}/{epochs:02d}] ({ep_time:.1f}s) | Train Loss: {avg_train_loss:.4f} (Rollout MSE: {avg_rollout:.4f}, Atk: {avg_atk:.4f}, Fam: {avg_fam:.4f}) | Val Loss: {val_loss:.4f}", flush=True)

        training_history.append({
            "epoch": epoch,
            "train_loss": round(avg_train_loss, 5),
            "val_loss": round(val_loss, 5),
            "epoch_seconds": round(ep_time, 2)
        })

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save({
                "model_state_dict": model.state_dict(),
                "setting": setting,
                "epoch": epoch,
                "val_loss": val_loss,
                "config": {
                    "state_dim": 54, "seq_len": 10, "forecast_horizon": 10,
                    "hidden_dim": 128, "n_transformer_layers": 2, "n_heads": 4, "num_classes": 7
                }
            }, best_checkpoint_path)

    total_train_time = time.time() - train_start
    print(f"\nTraining completed in {total_train_time:.1f}s. Best Val Loss: {best_val_loss:.4f}. Checkpoint saved to {best_checkpoint_path}", flush=True)

    # 4. Load Best Checkpoint for Final Inference & Calibration
    checkpoint = torch.load(best_checkpoint_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # 5. Validation Inference -> Calibrate Threshold tau
    print("\nRunning Validation inference to calibrate decision threshold tau*...", flush=True)
    val_pred_s, val_true_s, val_pred_p, val_true_b, val_pred_l, val_true_f, _ = evaluate_dataset(model, val_ds, device, batch_size=512)
    optimal_tau = calibrate_optimal_threshold(val_pred_p, val_true_b, metric="f1")
    print(f"Calibrated Optimal Threshold on Val: tau* = {optimal_tau:.2f}", flush=True)

    # 6. Test Inference -> Compute Standardized Evaluation Report
    print(f"Running Test partition evaluation ({len(test_ds):,} sequences)...", flush=True)
    test_pred_s, test_true_s, test_pred_p, test_true_b, test_pred_l, test_true_f, _ = evaluate_dataset(model, test_ds, device, batch_size=512)
    test_manifest = test_ds.manifest

    metrics_report = compute_unified_benchmark_report(
        y_pred_states=test_pred_s,
        y_true_states=test_true_s,
        y_pred_probs=test_pred_p,
        y_true_binary=test_true_b,
        y_pred_logits=test_pred_l,
        y_true_family=test_true_f,
        manifest_df=test_manifest,
        threshold=optimal_tau
    )

    final_result = {
        "model_family": "TFCNet",
        "setting": setting,
        "parameters": model.count_parameters()["total_parameters"],
        "training_time_seconds": round(total_train_time, 2),
        "best_epoch": checkpoint["epoch"],
        "best_val_loss": round(float(best_val_loss), 5),
        "calibrated_threshold_tau": optimal_tau,
        "history": training_history,
        "metrics": metrics_report
    }

    # Save Setting JSON
    setting_json_path = os.path.join(REPORT_DIR, f"setting_{setting.lower()}_results.json")
    with open(setting_json_path, "w", encoding="utf-8") as f:
        json.dump(final_result, f, indent=2)
    print(f"Setting {setting} results saved to {setting_json_path}", flush=True)

    return final_result


def generate_benchmark_summary_report(results: List[Dict[str, Any]]):
    md_path = os.path.join(REPORT_DIR, "tfcnet_benchmark_summary.md")
    csv_path = os.path.join(REPORT_DIR, "tfcnet_benchmark_summary.csv")

    csv_rows = []
    for r in results:
        m = r["metrics"]
        s = m["state_forecasting"]
        b = m["binary_classification"]
        f = m["family_classification"]
        o = m["onset_early_warning"]

        csv_rows.append({
            "Setting": f"Setting {r['setting']}",
            "Model": r["model_family"],
            "Parameters": r["parameters"],
            "Calibrated_Tau": r["calibrated_threshold_tau"],
            "State_MAE_Overall": s["overall_state_mae"],
            "State_MSE_Overall": s["overall_state_mse"],
            "State_MAE_k1": s.get("mae_k1", "N/A"),
            "State_MAE_k10": s.get("mae_k10", "N/A"),
            "Binary_F1": b["f1_score"],
            "Binary_Precision": b["precision"],
            "Binary_Recall": b["recall"],
            "Binary_PR_AUC": b["pr_auc"],
            "Binary_ROC_AUC": b["roc_auc"],
            "Binary_FPR": b["false_positive_rate_fpr"],
            "Family_Macro_F1": f["family_macro_f1"],
            "Onset_Event_Recall": o["onset_event_recall"],
            "Median_Lead_Time_sec": o["median_lead_time_seconds"],
            "False_Alarms_per_Hour": o["false_alarms_per_hour"],
            "Training_Time_sec": r["training_time_seconds"]
        })

    summary_df = pd.DataFrame(csv_rows)
    summary_df.to_csv(csv_path, index=False)

    lines = [
        "# Phase 6: TFCNet Benchmark Results Across Settings A, B, and C",
        "",
        "## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data",
        "**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**",
        "",
        "---",
        "",
        "## 1. Master TFCNet Benchmark Table",
        "",
        "| Metric Domain | Primary Metric | Setting A (Seen Attacks) | Setting B (Mixed Traffic) | Setting C (Zero-Day OOD) |",
        "| :--- | :--- | :--- | :--- | :--- |",
        f"| **State Forecasting** | Overall State MAE | **{results[0]['metrics']['state_forecasting']['overall_state_mae']}** | **{results[1]['metrics']['state_forecasting']['overall_state_mae']}** | **{results[2]['metrics']['state_forecasting']['overall_state_mae']}** |",
        f"| | Overall State MSE | **{results[0]['metrics']['state_forecasting']['overall_state_mse']}** | **{results[1]['metrics']['state_forecasting']['overall_state_mse']}** | **{results[2]['metrics']['state_forecasting']['overall_state_mse']}** |",
        f"| | Horizon $k=1$ (2s) MAE | {results[0]['metrics']['state_forecasting'].get('mae_k1', 'N/A')} | {results[1]['metrics']['state_forecasting'].get('mae_k1', 'N/A')} | {results[2]['metrics']['state_forecasting'].get('mae_k1', 'N/A')} |",
        f"| | Horizon $k=10$ (20s) MAE | {results[0]['metrics']['state_forecasting'].get('mae_k10', 'N/A')} | {results[1]['metrics']['state_forecasting'].get('mae_k10', 'N/A')} | {results[2]['metrics']['state_forecasting'].get('mae_k10', 'N/A')} |",
        f"| **Occurrence Forecast ($t+10$)** | Calibrated Threshold $\\tau^*$ | $\\tau={results[0]['calibrated_threshold_tau']}$ | $\\tau={results[1]['calibrated_threshold_tau']}$ | $\\tau={results[2]['calibrated_threshold_tau']}$ |",
        f"| | **Macro F1 Score** | **{results[0]['metrics']['binary_classification']['f1_score']:.4f}** | **{results[1]['metrics']['binary_classification']['f1_score']:.4f}** | **{results[2]['metrics']['binary_classification']['f1_score']:.4f}** |",
        f"| | Precision | {results[0]['metrics']['binary_classification']['precision']:.4f} | {results[1]['metrics']['binary_classification']['precision']:.4f} | {results[2]['metrics']['binary_classification']['precision']:.4f} |",
        f"| | Recall | {results[0]['metrics']['binary_classification']['recall']:.4f} | {results[1]['metrics']['binary_classification']['recall']:.4f} | {results[2]['metrics']['binary_classification']['recall']:.4f} |",
        f"| | PR-AUC | {results[0]['metrics']['binary_classification']['pr_auc']:.4f} | {results[1]['metrics']['binary_classification']['pr_auc']:.4f} | {results[2]['metrics']['binary_classification']['pr_auc']:.4f} |",
        f"| | False Positive Rate (FPR) | {results[0]['metrics']['binary_classification']['false_positive_rate_fpr']:.4f} | {results[1]['metrics']['binary_classification']['false_positive_rate_fpr']:.4f} | {results[2]['metrics']['binary_classification']['false_positive_rate_fpr']:.4f} |",
        f"| **Threat Family** | 7-Class Macro F1 | **{results[0]['metrics']['family_classification']['family_macro_f1']:.4f}** | **{results[1]['metrics']['family_classification']['family_macro_f1']:.4f}** | **{results[2]['metrics']['family_classification']['family_macro_f1']:.4f}** |",
        f"| **Onset Early Warning** | **Onset Event Recall** | **{results[0]['metrics']['onset_early_warning']['onset_event_recall']:.4f}** | **{results[1]['metrics']['onset_early_warning']['onset_event_recall']:.4f}** | **{results[2]['metrics']['onset_early_warning']['onset_event_recall']:.4f}** |",
        f"| | Median Lead Time | **{results[0]['metrics']['onset_early_warning']['median_lead_time_seconds']}s** | **{results[1]['metrics']['onset_early_warning']['median_lead_time_seconds']}s** | **{results[2]['metrics']['onset_early_warning']['median_lead_time_seconds']}s** |",
        f"| | False Alarms / Hour | **{results[0]['metrics']['onset_early_warning']['false_alarms_per_hour']:.2f} FA/hr** | **{results[1]['metrics']['onset_early_warning']['false_alarms_per_hour']:.2f} FA/hr** | **{results[2]['metrics']['onset_early_warning']['false_alarms_per_hour']:.2f} FA/hr** |",
        "",
        "---",
        "",
        "## 2. Scientific Architecture Overview (TFCNet)",
        "- **Time-Domain Branch:** Multi-scale 1D dilated convolutions ($k \\in \\{1, 3, 5, \\text{dilated}\\}$) capture local micro-bursts and rate changes.",
        "- **Frequency-Domain Branch:** Real-valued Fast Fourier Transform (RFFT) extracts periodic frequency spectral components (beaconing and scanning cycles).",
        "- **iTransformer Backbone:** Inverted multi-head self-attention models correlations across all 54 continuous physical metric variates simultaneously.",
        "",
        "_Generated automatically by `scripts/experiments/train_benchmark_tfcnet.py`._"
    ]

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nMaster TFCNet benchmark report generated at {md_path}", flush=True)


def main():
    print("=" * 80, flush=True)
    print("SIH26153: PHASE 6 TFCNET BENCHMARK TRAINING (SETTINGS A, B, C)", flush=True)
    print("=" * 80, flush=True)

    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

    all_results = []
    for setting in ["A", "B", "C"]:
        res = train_single_setting(
            setting=setting,
            epochs=4,
            samples_per_epoch=18000,
            batch_size=256,
            lr=1e-3
        )
        all_results.append(res)

    print("\n" + "=" * 80, flush=True)
    print("GENERATING MASTER TFCNET BENCHMARK REPORTS", flush=True)
    print("=" * 80, flush=True)
    generate_benchmark_summary_report(all_results)
    print("PHASE 6 EXECUTION FULLY COMPLETE", flush=True)


if __name__ == "__main__":
    main()
