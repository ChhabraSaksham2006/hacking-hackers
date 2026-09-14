"""
Training Script for World Model Network Attack Forecasting

Trains the dual-head World Model on sequence network state telemetry.
Saves the best model checkpoint based on Validation Macro F1-score.

Usage:
    python src/train_world_model.py --data_dir data/processed --lookback 10 --horizon 1 --epochs 10 --batch_size 128
"""

import os
import sys
import argparse
import time
from typing import Tuple, Dict, Any, List
import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from sklearn.metrics import classification_report, f1_score, balanced_accuracy_score

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import create_dataloaders
from src.world_model import LSTMWorldModel, TransformerWorldModel, compute_world_model_loss
from src.mitre_mapping import STAGE_NAMES


def train_one_epoch(
    model: nn.Module,
    dataloader: torch.utils.data.DataLoader,
    optimizer: torch.optim.Optimizer,
    class_weights: torch.Tensor,
    device: torch.device,
    state_loss_weight: float = 0.5,
    max_norm: float = 1.0
) -> Tuple[float, float, float]:
    """Train model for one epoch."""
    model.train()
    total_loss, total_stage_loss, total_state_loss = 0.0, 0.0, 0.0
    num_batches = len(dataloader)

    for sequences, future_states, future_labels in dataloader:
        sequences = sequences.to(device)
        future_states = future_states.to(device)
        future_labels = future_labels.to(device)

        optimizer.zero_grad()
        pred_state, pred_stage_logits, _ = model(sequences)

        loss, loss_stage, loss_state = compute_world_model_loss(
            pred_state, future_states, pred_stage_logits, future_labels,
            class_weights=class_weights, state_loss_weight=state_loss_weight
        )

        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm)
        optimizer.step()

        total_loss += loss.item()
        total_stage_loss += loss_stage.item()
        total_state_loss += loss_state.item()

    return (
        total_loss / num_batches,
        total_stage_loss / num_batches,
        total_state_loss / num_batches
    )


@torch.no_grad()
def evaluate_model(
    model: nn.Module,
    dataloader: torch.utils.data.DataLoader,
    class_weights: torch.Tensor,
    device: torch.device,
    state_loss_weight: float = 0.5
) -> Dict[str, Any]:
    """Evaluate model on validation/test dataloader."""
    model.eval()
    total_loss, total_stage_loss, total_state_loss = 0.0, 0.0, 0.0
    all_preds = []
    all_targets = []
    num_batches = len(dataloader)

    for sequences, future_states, future_labels in dataloader:
        sequences = sequences.to(device)
        future_states = future_states.to(device)
        future_labels = future_labels.to(device)

        pred_state, pred_stage_logits, _ = model(sequences)

        loss, loss_stage, loss_state = compute_world_model_loss(
            pred_state, future_states, pred_stage_logits, future_labels,
            class_weights=class_weights, state_loss_weight=state_loss_weight
        )

        total_loss += loss.item()
        total_stage_loss += loss_stage.item()
        total_state_loss += loss_state.item()

        preds = torch.argmax(pred_stage_logits, dim=-1).cpu().numpy()
        all_preds.extend(preds)
        all_targets.extend(future_labels.cpu().numpy())

    all_preds = np.array(all_preds)
    all_targets = np.array(all_targets)

    macro_f1 = float(f1_score(all_targets, all_preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(all_targets, all_preds, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(all_targets, all_preds))
    acc = float((all_preds == all_targets).mean())

    present_labels = sorted(set(all_targets) | set(all_preds))
    target_names = [STAGE_NAMES.get(int(l), f"Stage {l}") for l in present_labels]
    report = classification_report(
        all_targets, all_preds, labels=present_labels,
        target_names=target_names, zero_division=0
    )

    return {
        "loss": total_loss / num_batches,
        "loss_stage": total_stage_loss / num_batches,
        "loss_state": total_state_loss / num_batches,
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "report": report,
        "predictions": all_preds,
        "targets": all_targets
    }


def main():
    parser = argparse.ArgumentParser(description="Train World Model")
    parser.add_argument("--data_dir", default="data/processed", help="Path to processed parquet data")
    parser.add_argument("--models_dir", default="models", help="Directory to save model checkpoints")
    parser.add_argument("--model_type", choices=["lstm", "transformer"], default="lstm")
    parser.add_argument("--lookback", type=int, default=10, help="Lookback sequence length P")
    parser.add_argument("--horizon", type=int, default=1, help="Forecasting horizon K (steps ahead)")
    parser.add_argument("--hidden_dim", type=int, default=128, help="Hidden dimension size")
    parser.add_argument("--num_layers", type=int, default=2, help="Number of recurrent layers")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=128, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--weight_decay", type=float, default=1e-4, help="Weight decay")
    parser.add_argument("--state_loss_weight", type=float, default=0.5, help="Weight lambda for state MSE loss")
    args = parser.parse_args()

    os.makedirs(args.models_dir, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    print(f"Building Sequence Dataset: Lookback P={args.lookback}, Horizon K={args.horizon} ...")

    train_loader, val_loader, test_loader, scaler, feature_cols = create_dataloaders(
        data_dir=args.data_dir,
        lookback=args.lookback,
        horizon=args.horizon,
        batch_size=args.batch_size
    )

    input_dim = len(feature_cols)
    num_classes = 5
    print(f"Features: {input_dim}, Classes: {num_classes}")
    print(f"Train Batches: {len(train_loader)} | Val Batches: {len(val_loader)} | Test Batches: {len(test_loader)}")

    # Class weights for loss (give higher weight to rare attack classes 1..4)
    # Stage 0: Benign (1.0), Stage 1: Recon (10.0), Stage 2: Initial Access (10.0), Stage 3: Lateral (10.0), Stage 4: DoS (10.0)
    weights = torch.tensor([1.0, 15.0, 20.0, 15.0, 15.0], dtype=torch.float32).to(device)

    # Initialize model
    if args.model_type == "lstm":
        model = LSTMWorldModel(
            input_dim=input_dim,
            hidden_dim=args.hidden_dim,
            num_layers=args.num_layers,
            num_classes=num_classes
        ).to(device)
    else:
        model = TransformerWorldModel(
            input_dim=input_dim,
            hidden_dim=args.hidden_dim,
            num_layers=args.num_layers,
            num_classes=num_classes
        ).to(device)

    num_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model ({args.model_type.upper()}) initialized with {num_params:,} trainable parameters.")

    optimizer = AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=1e-5)

    best_val_f1 = -1.0
    best_checkpoint_path = os.path.join(args.models_dir, f"world_model_{args.model_type}_best.pt")

    print("\n" + "="*70)
    print(f"  STARTING WORLD MODEL TRAINING (P={args.lookback}, K={args.horizon})")
    print("="*70)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()
        train_loss, train_stage_l, train_state_l = train_one_epoch(
            model, train_loader, optimizer, weights, device,
            state_loss_weight=args.state_loss_weight
        )
        val_results = evaluate_model(
            model, val_loader, weights, device,
            state_loss_weight=args.state_loss_weight
        )
        scheduler.step()
        elapsed = time.time() - t0

        print(
            f"Epoch {epoch:02d}/{args.epochs:02d} [{elapsed:.1f}s] | "
            f"Train Loss: {train_loss:.4f} (Stage: {train_stage_l:.4f}, State: {train_state_l:.4f}) | "
            f"Val Loss: {val_results['loss']:.4f} | "
            f"Val Acc: {val_results['accuracy']:.4f} | "
            f"Val BalAcc: {val_results['balanced_accuracy']:.4f} | "
            f"Val Macro-F1: {val_results['macro_f1']:.4f}"
        )

        if val_results["macro_f1"] > best_val_f1 or epoch == 1:
            best_val_f1 = val_results["macro_f1"]
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_macro_f1": best_val_f1,
                "lookback": args.lookback,
                "horizon": args.horizon,
                "feature_cols": feature_cols,
                "input_dim": input_dim,
                "hidden_dim": args.hidden_dim,
                "num_classes": num_classes,
                "model_type": args.model_type
            }, best_checkpoint_path)
            print(f"  --> Saved new best checkpoint (Macro-F1: {best_val_f1:.4f}) to {best_checkpoint_path}")

    # Load best checkpoint and evaluate on Test set (Friday)
    print("\n" + "="*70)
    print(f"  FINAL EVALUATION ON TEST SPLIT (FRIDAY) USING BEST CHECKPOINT")
    print("="*70)

    checkpoint = torch.load(best_checkpoint_path, map_location=device)
    model.load_state_dict(checkpoint["model_state_dict"])

    test_results = evaluate_model(
        model, test_loader, weights, device, state_loss_weight=args.state_loss_weight
    )

    print(f"Test Accuracy:          {test_results['accuracy']:.4f}")
    print(f"Test Balanced Accuracy: {test_results['balanced_accuracy']:.4f}")
    print(f"Test Macro F1:          {test_results['macro_f1']:.4f}")
    print(f"Test Weighted F1:       {test_results['weighted_f1']:.4f}")
    print(f"Test State MSE:         {test_results['loss_state']:.4f}")
    print("\nTest Classification Report:")
    print(test_results["report"])


if __name__ == "__main__":
    main()
