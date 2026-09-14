"""
Unified Multi-Domain World Model Training & Forensic Evaluation Engine

Trains the Dual-Head LSTM World Model on the unified DARPA + CIC-IDS2017 multi-domain dataset.
Evaluates multi-step forecasting dynamics and per-stage detection across all 5 MITRE stages:
  Stage 0: Benign Baseline
  Stage 1: Reconnaissance (PortScan)
  Stage 2: Initial Access (SSH/FTP/Web Brute-Force)
  Stage 3: Lateral Movement & Exploits (Buffer Overflow, SQLi, XSS, Infiltration)
  Stage 4: Denial of Service (SYN flood, ICMP flood, teardrop, Hulk, DDoS, Slowloris)
"""

import os
import sys
import glob
import argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.utils.data import DataLoader, WeightedRandomSampler
from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score, f1_score, accuracy_score
from typing import Dict, Any, List, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import get_feature_columns
from src.dataset_unified_sequence import UnifiedMultiDomainDataset
from src.world_model import LSTMWorldModel, compute_world_model_loss
from src.mitre_mapping import STAGE_NAMES


def train_unified_world_model(
    darpa_dir: str = "data/processed",
    cic_dir: str = "data/processed_cic",
    models_dir: str = "models",
    lookback: int = 10,
    horizon: int = 1,
    hidden_dim: int = 128,
    num_layers: int = 2,
    epochs: int = 6,
    batch_size: int = 256,
    lr: float = 1e-3,
    max_train_samples: int = 250000,
    max_test_samples: int = 50000
):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Executing Unified Training on Device: {device}")
    os.makedirs(models_dir, exist_ok=True)

    # ── 1. Load Session DataFrames ─────────────────────────────────────────
    darpa_files = sorted(glob.glob(os.path.join(darpa_dir, "windows_*_dt10s.parquet")))
    cic_files   = sorted(glob.glob(os.path.join(cic_dir, "*.parquet")))

    print(f"Loading {len(darpa_files)} DARPA sessions and {len(cic_files)} CIC-IDS2017 sessions ...")
    all_sessions = [pd.read_parquet(f) for f in darpa_files + cic_files]
    feature_cols = get_feature_columns(all_sessions[0])
    print(f"Canonical Feature Dimension: D = {len(feature_cols)}")

    # ── 2. Build Unified Sequence Datasets ─────────────────────────────────
    print(f"\nConstructing Stratified Train (80%) and Test (20%) Sequences (P={lookback}, K={horizon}) ...")
    train_dataset = UnifiedMultiDomainDataset(
        session_dfs=all_sessions,
        feature_cols=feature_cols,
        scaler=None,
        fit_scaler=True,
        lookback=lookback,
        horizon=horizon,
        split_type='train',
        train_ratio=0.8
    )
    print(f"Train Dataset: {len(train_dataset):,} sequences")

    test_dataset = UnifiedMultiDomainDataset(
        session_dfs=all_sessions,
        feature_cols=feature_cols,
        scaler=train_dataset.scaler,
        fit_scaler=False,
        lookback=lookback,
        horizon=horizon,
        split_type='test',
        train_ratio=0.8
    )
    print(f"Test Dataset:  {len(test_dataset):,} sequences")

    # Display Stage Distributions in Train and Test
    print("\nTrain Stage Distribution:")
    tr_counts = torch.bincount(train_dataset.future_labels, minlength=5)
    for code, cnt in enumerate(tr_counts.tolist()):
        print(f"  Stage {code} ({STAGE_NAMES.get(code, 'Unknown'):<32}): {cnt:>8,}")

    print("\nTest Stage Distribution:")
    te_counts = torch.bincount(test_dataset.future_labels, minlength=5)
    for code, cnt in enumerate(te_counts.tolist()):
        print(f"  Stage {code} ({STAGE_NAMES.get(code, 'Unknown'):<32}): {cnt:>8,}")

    # ── 3. DataLoaders with Balanced Sampler ──────────────────────────────
    num_train_samples = min(len(train_dataset), max_train_samples)
    train_sampler = WeightedRandomSampler(
        weights=train_dataset.sample_weights,
        num_samples=num_train_samples,
        replacement=True
    )
    train_loader = DataLoader(train_dataset, batch_size=batch_size, sampler=train_sampler)
    
    # Subsample test set if very large for fast and rigorous evaluation
    test_sampler = None
    if len(test_dataset) > max_test_samples:
        test_sampler = WeightedRandomSampler(
            weights=test_dataset.sample_weights,
            num_samples=max_test_samples,
            replacement=True
        )
        test_loader = DataLoader(test_dataset, batch_size=batch_size, sampler=test_sampler)
    else:
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    # ── 4. Initialize World Model ─────────────────────────────────────────
    model = LSTMWorldModel(
        input_dim=len(feature_cols),
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        num_classes=5
    ).to(device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    class_weights = torch.tensor([1.0, 5.0, 10.0, 10.0, 5.0], dtype=torch.float32).to(device)

    best_checkpoint_path = os.path.join(models_dir, "unified_world_model_best.pt")

    print("\n" + "="*70)
    print(f"Starting Multi-Domain World Model Training ({epochs} Epochs) ...")
    print("="*70)

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss, total_stage_loss, total_state_loss = 0.0, 0.0, 0.0

        for batch_idx, (seqs, states, labels) in enumerate(train_loader, start=1):
            seqs, states, labels = seqs.to(device), states.to(device), labels.to(device)
            optimizer.zero_grad()

            pred_state, pred_stage, _ = model(seqs)
            loss, stage_l, state_l = compute_world_model_loss(
                pred_state, states, pred_stage, labels,
                class_weights=class_weights, state_loss_weight=0.2
            )

            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            total_loss += loss.item()
            total_stage_loss += stage_l.item()
            total_state_loss += state_l.item()

        scheduler.step()
        avg_loss = total_loss / len(train_loader)
        print(f"Epoch {epoch:02d}/{epochs:02d} | Loss: {avg_loss:.4f} | StageLoss: {total_stage_loss/len(train_loader):.4f} | StateLoss: {total_state_loss/len(train_loader):.4f}")

    # Save Best Unified Model
    torch.save(model.state_dict(), best_checkpoint_path)
    print(f"\nSaved Unified World Model Checkpoint: {best_checkpoint_path}")

    # ── 5. Comprehensive Forensic Evaluation on Held-Out Test Set ─────────
    print("\n" + "="*70)
    print("           UNIFIED WORLD MODEL HELD-OUT TEST EVALUATION")
    print("="*70)

    model.eval()
    all_preds, all_targets = [], []
    all_pred_states, all_true_states = [], []

    with torch.no_grad():
        for seqs, states, labels in test_loader:
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

    acc = accuracy_score(all_targets, all_preds)
    bal_acc = balanced_accuracy_score(all_targets, all_preds)
    macro_f1 = f1_score(all_targets, all_preds, average="macro", zero_division=0)
    weighted_f1 = f1_score(all_targets, all_preds, average="weighted", zero_division=0)
    state_mse = float(np.mean((all_pred_states - all_true_states) ** 2))

    cm = confusion_matrix(all_targets, all_preds, labels=[0, 1, 2, 3, 4])

    print(f"\nOverall Test Accuracy:     {acc*100:.2f}%")
    print(f"Balanced Test Accuracy:    {bal_acc*100:.2f}%")
    print(f"Macro F1-Score:            {macro_f1:.4f}")
    print(f"Weighted F1-Score:         {weighted_f1:.4f}")
    print(f"State Vector Dynamics MSE: {state_mse:.4f}")

    print("\nConfusion Matrix (Rows=True Stage [0..4], Columns=Predicted Stage [0..4]):")
    print(cm)

    print("\nDetailed Per-Stage Performance Metrics:")
    for stage_code in range(5):
        sname = STAGE_NAMES.get(stage_code, f"Stage {stage_code}")
        tp = cm[stage_code, stage_code]
        actual_tot = cm[stage_code, :].sum()
        pred_tot = cm[:, stage_code].sum()
        recall = (tp / actual_tot) if actual_tot > 0 else 0.0
        precision = (tp / pred_tot) if pred_tot > 0 else 0.0
        print(f"  [{stage_code}] {sname:<35}: True={actual_tot:>7,} | Pred={pred_tot:>7,} | Recall={recall*100:>6.2f}% | Precision={precision*100:>6.2f}%")


if __name__ == "__main__":
    train_unified_world_model()
