"""
5-Fold Cross-Validation Training & Forensic Audit Module

Performs comprehensive 5-fold cross-validation of the Sequence World Model across all 5 days
to guarantee that every attack stage (Recon, Initial Access, Lateral Movement, DoS) is trained and evaluated.
Computes per-stage Recall, Precision, Confusion Matrices, and State Dynamics MSE.
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.utils.data import DataLoader, Subset, WeightedRandomSampler
from sklearn.model_selection import KFold, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score, f1_score, accuracy_score
from typing import Dict, Any, List, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import NetworkSequenceDataset, get_feature_columns
from src.world_model import LSTMWorldModel, compute_world_model_loss
from src.mitre_mapping import STAGE_NAMES


def train_and_eval_fold(
    fold_idx: int,
    train_dataset: NetworkSequenceDataset,
    val_dataset: NetworkSequenceDataset,
    input_dim: int,
    num_classes: int = 5,
    hidden_dim: int = 128,
    num_layers: int = 2,
    epochs: int = 6,
    batch_size: int = 256,
    lr: float = 1e-3,
    device: torch.device = torch.device("cpu")
) -> Dict[str, Any]:
    """Train and evaluate model on a single fold."""
    # Balanced sampler for training
    sampler = WeightedRandomSampler(
        weights=train_dataset.sample_weights,
        num_samples=len(train_dataset),
        replacement=True
    )
    train_loader = DataLoader(train_dataset, batch_size=batch_size, sampler=sampler)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    model = LSTMWorldModel(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        num_classes=num_classes
    ).to(device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    class_weights = torch.tensor([1.0, 15.0, 20.0, 15.0, 15.0], dtype=torch.float32).to(device)

    print(f"\n--- FOLD {fold_idx} TRAINING (Train: {len(train_dataset):,} seqs, Val: {len(val_dataset):,} seqs) ---")

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for seqs, states, labels in train_loader:
            seqs, states, labels = seqs.to(device), states.to(device), labels.to(device)
            optimizer.zero_grad()
            pred_state, pred_stage, _ = model(seqs)
            loss, _, _ = compute_world_model_loss(
                pred_state, states, pred_stage, labels,
                class_weights=class_weights, state_loss_weight=0.5
            )
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_loss += loss.item()

        scheduler.step()

    # Full Evaluation on Validation Fold
    model.eval()
    all_preds, all_targets, all_pred_states, all_true_states = [], [], [], []
    with torch.no_grad():
        for seqs, states, labels in val_loader:
            seqs = seqs.to(device)
            pred_state, pred_stage, _ = model(seqs)
            preds = torch.argmax(pred_stage, dim=-1).cpu().numpy()
            all_preds.extend(preds)
            all_targets.extend(labels.numpy())
            all_pred_states.extend(pred_state.cpu().numpy())
            all_true_states.extend(states.numpy())

    all_preds = np.array(all_preds)
    all_targets = np.array(all_targets)
    all_pred_states = np.array(all_pred_states)
    all_true_states = np.array(all_true_states)

    state_mse = float(np.mean((all_pred_states - all_true_states) ** 2))
    acc = float(accuracy_score(all_targets, all_preds))
    bal_acc = float(balanced_accuracy_score(all_targets, all_preds))
    macro_f1 = float(f1_score(all_targets, all_preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(all_targets, all_preds, average="weighted", zero_division=0))

    present_labels = sorted(set(all_targets) | set(all_preds))
    target_names = [STAGE_NAMES.get(int(l), f"Stage {l}") for l in present_labels]
    report = classification_report(
        all_targets, all_preds, labels=present_labels,
        target_names=target_names, zero_division=0
    )
    cm = confusion_matrix(all_targets, all_preds, labels=[0, 1, 2, 3, 4])

    print(f"Fold {fold_idx} | Acc: {acc:.4f} | BalAcc: {bal_acc:.4f} | Macro-F1: {macro_f1:.4f} | State MSE: {state_mse:.4f}")
    print("Confusion Matrix (rows=True [0..4], cols=Pred [0..4]):")
    print(cm)

    return {
        "fold": fold_idx,
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "state_mse": state_mse,
        "confusion_matrix": cm,
        "report": report,
        "predictions": all_preds,
        "targets": all_targets
    }


def run_5fold_cross_val(
    data_dir: str,
    lookback: int = 10,
    horizon: int = 1,
    epochs: int = 6,
    batch_size: int = 256
):
    """Loads all 5 days of data and runs 5-Fold Cross-Validation."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    print("Loading all Week 1 Parquet data ...")

    day_files = [
        os.path.join(data_dir, f"windows_{day}_dt10s.parquet")
        for day in ["monday", "tuesday", "wednesday", "thursday", "friday"]
    ]
    all_dfs = [pd.read_parquet(f) for f in day_files if os.path.exists(f)]
    df_all = pd.concat(all_dfs, ignore_index=True)
    feature_cols = get_feature_columns(df_all)

    print(f"Total dataset: {len(df_all):,} windows, {len(feature_cols)} features")
    print("Class distribution across all 5 days:")
    for code, cnt in df_all["mitre_stage_code"].value_counts().sort_index().items():
        print(f"  Stage {code} ({STAGE_NAMES.get(code, 'Unknown')}): {cnt:,}")

    # Build sequence dataset
    print(f"\nBuilding Sequence Dataset (P={lookback}, K={horizon}) ...")
    full_dataset = NetworkSequenceDataset(
        df_all, feature_cols, scaler=None, fit_scaler=True,
        lookback=lookback, horizon=horizon
    )
    print(f"Total Sequences: {len(full_dataset):,}")

    labels = full_dataset.future_labels.numpy()
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    fold_results = []
    total_cm = np.zeros((5, 5), dtype=int)

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(np.zeros(len(labels)), labels), start=1):
        # Create train and val subsets
        train_sub = Subset(full_dataset, train_idx)
        val_sub   = Subset(full_dataset, val_idx)

        # Attach sample weights to subset
        train_sub.sample_weights = full_dataset.sample_weights[train_idx]
        val_sub.sample_weights   = full_dataset.sample_weights[val_idx]

        res = train_and_eval_fold(
            fold_idx=fold_idx,
            train_dataset=train_sub,
            val_dataset=val_sub,
            input_dim=len(feature_cols),
            epochs=epochs,
            batch_size=batch_size,
            device=device
        )
        fold_results.append(res)
        total_cm += res["confusion_matrix"]

    print("\n" + "="*75)
    print("              5-FOLD CROSS-VALIDATION FINAL SUMMARY")
    print("="*75)

    mean_acc = np.mean([r["accuracy"] for r in fold_results])
    mean_bal_acc = np.mean([r["balanced_accuracy"] for r in fold_results])
    mean_macro_f1 = np.mean([r["macro_f1"] for r in fold_results])
    mean_weighted_f1 = np.mean([r["weighted_f1"] for r in fold_results])
    mean_state_mse = np.mean([r["state_mse"] for r in fold_results])

    print(f"Mean Overall Accuracy:          {mean_acc:.4f} (+/- {np.std([r['accuracy'] for r in fold_results]):.4f})")
    print(f"Mean Balanced Accuracy:         {mean_bal_acc:.4f} (+/- {np.std([r['balanced_accuracy'] for r in fold_results]):.4f})")
    print(f"Mean Macro F1-Score:            {mean_macro_f1:.4f} (+/- {np.std([r['macro_f1'] for r in fold_results]):.4f})")
    print(f"Mean Weighted F1-Score:         {mean_weighted_f1:.4f} (+/- {np.std([r['weighted_f1'] for r in fold_results]):.4f})")
    print(f"Mean State Vector MSE:          {mean_state_mse:.4f} (+/- {np.std([r['state_mse'] for r in fold_results]):.4f})")

    print("\nAggregated Confusion Matrix across all 190,327 sequences:")
    print("Rows: True Stage [0..4], Columns: Predicted Stage [0..4]")
    print(total_cm)

    print("\nPer-Stage Recall & Precision across all 5 Folds:")
    for stage_code in range(5):
        stage_name = STAGE_NAMES.get(stage_code, f"Stage {stage_code}")
        true_positives = total_cm[stage_code, stage_code]
        actual_total = total_cm[stage_code, :].sum()
        pred_total = total_cm[:, stage_code].sum()
        recall = (true_positives / actual_total) if actual_total > 0 else 0.0
        precision = (true_positives / pred_total) if pred_total > 0 else 0.0
        print(f"  [{stage_code}] {stage_name:<30}: True={actual_total:<6} | Pred={pred_total:<6} | Recall={recall:.4f} | Precision={precision:.4f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run 5-Fold Cross Validation on World Model")
    parser.add_argument("--data_dir", default="data/processed")
    parser.add_argument("--lookback", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=1)
    parser.add_argument("--epochs", type=int, default=6)
    parser.add_argument("--batch_size", type=int, default=256)
    args = parser.parse_args()

    run_5fold_cross_val(
        data_dir=args.data_dir,
        lookback=args.lookback,
        horizon=args.horizon,
        epochs=args.epochs,
        batch_size=args.batch_size
    )
