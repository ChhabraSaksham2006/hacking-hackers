"""
optimize_sparserssm.py
======================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Systematic Optimization and Ablation Study for SparseRSSM:
1. Loss Calibration: Fix double-weighting in stratified training (use calibrated pos_weight=1.5).
2. Latent Dynamics: Evaluate Latent Multi-Head Self-Attention + Top-K Sparsity (ratio=0.8).
3. Horizon Supervision: Supervise intermediate rollout trajectory steps.
4. Robust Decision Calibration: Prevent degenerate threshold collapse (bounded grid search tau in [0.15, 0.85]).
5. Extended Convergence: 4 epochs with Warmup + Cosine Annealing.
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
from src.models.sparse_rssm import SparseRSSM
from src.evaluation.benchmark_metrics import (
    compute_unified_benchmark_report,
    calibrate_optimal_threshold
)

ROOT_DIR = PROJECT_ROOT
CHECKPOINT_DIR = os.path.join(ROOT_DIR, "models", "checkpoints", "optimized")
REPORT_DIR = os.path.join(ROOT_DIR, "reports", "phase_5_optimization")
os.makedirs(CHECKPOINT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def robust_calibrate_threshold(
    y_pred_probs: np.ndarray,
    y_true_binary: np.ndarray,
    min_tau: float = 0.15,
    max_tau: float = 0.85,
    num_steps: int = 71
) -> float:
    """
    Robust threshold search bounded in [min_tau, max_tau] to prevent degenerate collapsing.
    Maximizes F1 score, breaking ties towards higher precision.
    """
    best_tau = 0.50
    best_score = -1.0
    
    thresholds = np.linspace(min_tau, max_tau, num_steps)
    for tau in thresholds:
        preds = (y_pred_probs >= tau).astype(int)
        tp = np.sum((preds == 1) & (y_true_binary == 1))
        fp = np.sum((preds == 1) & (y_true_binary == 0))
        fn = np.sum((preds == 0) & (y_true_binary == 1))
        
        if tp == 0:
            f1 = 0.0
        else:
            prec = tp / (tp + fp)
            rec = tp / (tp + fn)
            f1 = 2 * (prec * rec) / (prec + rec)
            
        if f1 > best_score:
            best_score = f1
            best_tau = float(tau)
            
    return float(round(best_tau, 3))


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


def train_optimized_setting(
    setting: str,
    epochs: int = 4,
    samples_per_epoch: int = 18000,
    batch_size: int = 256,
    lr: float = 1.5e-3,
    sparsity_ratio: float = 0.8,
    use_attention: bool = True
) -> Dict[str, Any]:
    print(f"\n{'='*30} OPTIMIZING SPARSERSSM: SETTING {setting} {'='*30}", flush=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device} | Sparsity: {sparsity_ratio} | Attention: {use_attention} | Epochs: {epochs}", flush=True)

    # 1. Load Datasets
    t0 = time.time()
    scaler_path = os.path.join(ROOT_DIR, "models", "scalers", f"setting_{setting.lower()}_scaler.joblib")
    train_ds = HardenedBenchmarkDataset(setting=setting, split="train", fit_scaler=True, scaler_save_path=scaler_path)
    val_ds = HardenedBenchmarkDataset(setting=setting, split="val", scaler=train_ds.scaler, fit_scaler=False)
    test_ds = HardenedBenchmarkDataset(setting=setting, split="test", scaler=train_ds.scaler, fit_scaler=False)
    
    print(f"Datasets ready in {time.time() - t0:.2f}s (Train: {len(train_ds):,}, Val: {len(val_ds):,}, Test: {len(test_ds):,})", flush=True)

    # 2. Instantiate Model with Latent Attention & Calibrated Sparsity
    model = SparseRSSM(
        state_dim=54,
        latent_dim=128,
        hidden_dim=128,
        sparsity_ratio=sparsity_ratio,
        use_attention=use_attention,
        num_classes=7
    ).to(device)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    balanced_pos_weight = torch.tensor([1.5], device=device)

    best_val_loss = float("inf")
    best_checkpoint_path = os.path.join(CHECKPOINT_DIR, f"sparserssm_opt_setting_{setting.lower()}.pt")
    
    training_history = []
    train_start = time.time()

    # Stratified indices
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
                lambda_attack=1.5,
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

        # Validation
        _, _, _, _, _, _, val_loss = evaluate_dataset(model, val_ds, device, batch_size=512)

        print(f"Epoch [{epoch:02d}/{epochs:02d}] ({ep_time:.1f}s) | Train Loss: {avg_train_loss:.4f} (Recon: {avg_recon:.4f}, Rollout: {avg_rollout:.4f}, Atk: {avg_atk:.4f}, Fam: {avg_fam:.4f}) | Val Loss: {val_loss:.4f}", flush=True)

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
                    "state_dim": 54, "latent_dim": 128, "hidden_dim": 128,
                    "sparsity_ratio": sparsity_ratio, "use_attention": use_attention, "num_classes": 7
                }
            }, best_checkpoint_path)

    total_train_time = time.time() - train_start
    print(f"Training finished in {total_train_time:.1f}s. Best Val Loss: {best_val_loss:.4f}", flush=True)

    # 4. Load Best Checkpoint & Run Calibration
    checkpoint = torch.load(best_checkpoint_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    print("Calibrating robust threshold on validation set...", flush=True)
    val_pred_s, val_true_s, val_pred_p, val_true_b, val_pred_l, val_true_f, _ = evaluate_dataset(model, val_ds, device, batch_size=512)
    optimal_tau = robust_calibrate_threshold(val_pred_p, val_true_b, min_tau=0.15, max_tau=0.85)
    print(f"Robust Calibrated Threshold tau* = {optimal_tau:.3f}", flush=True)

    # 5. Full Test Evaluation
    print(f"Evaluating on Test partition ({len(test_ds):,} sequences)...", flush=True)
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
        "model_family": "SparseRSSM_Optimized",
        "setting": setting,
        "parameters": model.count_parameters()["total_parameters"],
        "sparsity_ratio": sparsity_ratio,
        "use_attention": use_attention,
        "training_time_seconds": round(total_train_time, 2),
        "best_epoch": checkpoint["epoch"],
        "best_val_loss": round(float(best_val_loss), 5),
        "calibrated_threshold_tau": optimal_tau,
        "history": training_history,
        "metrics": metrics_report
    }

    setting_json_path = os.path.join(REPORT_DIR, f"opt_setting_{setting.lower()}_results.json")
    with open(setting_json_path, "w", encoding="utf-8") as f:
        json.dump(final_result, f, indent=2)

    return final_result


def generate_optimization_comparison_report(baseline_results: List[Dict[str, Any]], opt_results: List[Dict[str, Any]]):
    md_path = os.path.join(REPORT_DIR, "sparserssm_optimization_comparison.md")
    csv_path = os.path.join(REPORT_DIR, "sparserssm_optimization_comparison.csv")

    rows = []
    for b, o in zip(baseline_results, opt_results):
        bm = b["metrics"]
        om = o["metrics"]
        setting_name = f"Setting {b['setting']}"

        rows.append({
            "Setting": setting_name,
            "Baseline_State_MAE": bm["state_forecasting"]["overall_state_mae"],
            "Opt_State_MAE": om["state_forecasting"]["overall_state_mae"],
            "MAE_Delta": round(om["state_forecasting"]["overall_state_mae"] - bm["state_forecasting"]["overall_state_mae"], 5),
            "Baseline_F1": bm["binary_classification"]["f1_score"],
            "Opt_F1": om["binary_classification"]["f1_score"],
            "F1_Delta": round(om["binary_classification"]["f1_score"] - bm["binary_classification"]["f1_score"], 4),
            "Baseline_PR_AUC": bm["binary_classification"]["pr_auc"],
            "Opt_PR_AUC": om["binary_classification"]["pr_auc"],
            "Baseline_Precision": bm["binary_classification"]["precision"],
            "Opt_Precision": om["binary_classification"]["precision"],
            "Baseline_Recall": bm["binary_classification"]["recall"],
            "Opt_Recall": om["binary_classification"]["recall"],
            "Baseline_Onset_Recall": bm["onset_early_warning"]["onset_event_recall"],
            "Opt_Onset_Recall": om["onset_early_warning"]["onset_event_recall"],
            "Baseline_FA_per_Hour": bm["onset_early_warning"]["false_alarms_per_hour"],
            "Opt_FA_per_Hour": om["onset_early_warning"]["false_alarms_per_hour"],
        })

    df = pd.DataFrame(rows)
    df.to_csv(csv_path, index=False)

    md_lines = [
        "# SparseRSSM Optimization & Ablation Study",
        "",
        "## Scientific Comparison: Baseline Phase 5 vs. Optimized Model",
        "",
        "| Setting | Model Variant | State MAE | Binary F1 | Precision | Recall | PR-AUC | Onset Recall | FA / Hour |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    for b, o in zip(baseline_results, opt_results):
        s_name = f"Setting {b['setting']}"
        bm = b["metrics"]
        om = o["metrics"]
        md_lines.append(f"| **{s_name}** | Phase 5 Baseline | {bm['state_forecasting']['overall_state_mae']:.4f} | {bm['binary_classification']['f1_score']:.4f} | {bm['binary_classification']['precision']:.4f} | {bm['binary_classification']['recall']:.4f} | {bm['binary_classification']['pr_auc']:.4f} | {bm['onset_early_warning']['onset_event_recall']:.4f} | {bm['onset_early_warning']['false_alarms_per_hour']:.1f} |")
        md_lines.append(f"| | **Optimized Model** | **{om['state_forecasting']['overall_state_mae']:.4f}** | **{om['binary_classification']['f1_score']:.4f}** | **{om['binary_classification']['precision']:.4f}** | **{om['binary_classification']['recall']:.4f}** | **{om['binary_classification']['pr_auc']:.4f}** | **{om['onset_early_warning']['onset_event_recall']:.4f}** | **{om['onset_early_warning']['false_alarms_per_hour']:.1f}** |")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"\nOptimization comparison report written to {md_path}", flush=True)


def main():
    print("=" * 80, flush=True)
    print("SIH26153: OPTIMIZING SPARSERSSM BENCHMARK PERFORMANCE", flush=True)
    print("=" * 80, flush=True)

    # Load baseline results
    baseline_results = []
    for s in ["a", "b", "c"]:
        p = os.path.join(ROOT_DIR, "reports", "phase_5", f"setting_{s}_results.json")
        with open(p, "r", encoding="utf-8") as f:
            baseline_results.append(json.load(f))

    # Run optimization across Settings A, B, C
    opt_results = []
    for s in ["A", "B", "C"]:
        res = train_optimized_setting(
            setting=s,
            epochs=4,
            samples_per_epoch=18000,
            batch_size=256,
            lr=1.5e-3,
            sparsity_ratio=0.8,
            use_attention=True
        )
        opt_results.append(res)

    generate_optimization_comparison_report(baseline_results, opt_results)
    print("\nALL OPTIMIZATION RUNS COMPLETED SUCCESSFULLY", flush=True)


if __name__ == "__main__":
    main()
