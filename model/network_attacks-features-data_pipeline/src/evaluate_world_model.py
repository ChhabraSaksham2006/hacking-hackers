"""
World Model Evaluation & Forecasting Analysis Module

Evaluates a trained World Model checkpoint across multiple forecasting horizons K in {1, 5, 10} steps ahead.
Computes stage forecasting accuracy, state vector MSE, and generates comparative metrics against baseline.

Usage:
    python src/evaluate_world_model.py --checkpoint models/world_model_lstm_best.pt --data_dir data/processed
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import classification_report, confusion_matrix, f1_score, balanced_accuracy_score, accuracy_score
from typing import Dict, Any, List

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import create_dataloaders
from src.world_model import LSTMWorldModel, TransformerWorldModel
from src.mitre_mapping import STAGE_NAMES


def evaluate_horizon(
    checkpoint_path: str,
    data_dir: str,
    horizon: int = 1,
    lookback: int = 10,
    batch_size: int = 128
) -> Dict[str, Any]:
    """Evaluates the model for a specific forecasting horizon K."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(checkpoint_path, map_location=device)

    feature_cols = checkpoint["feature_cols"]
    input_dim = checkpoint["input_dim"]
    hidden_dim = checkpoint.get("hidden_dim", 128)
    num_classes = checkpoint.get("num_classes", 5)
    model_type = checkpoint.get("model_type", "lstm")

    # Create dataloaders for this specific horizon
    train_loader, val_loader, test_loader, scaler, _ = create_dataloaders(
        data_dir=data_dir,
        lookback=lookback,
        horizon=horizon,
        batch_size=batch_size
    )

    if model_type == "lstm":
        model = LSTMWorldModel(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_classes=num_classes
        ).to(device)
    else:
        model = TransformerWorldModel(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_classes=num_classes
        ).to(device)

    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    all_preds = []
    all_targets = []
    all_pred_states = []
    all_true_states = []

    with torch.no_grad():
        for sequences, future_states, future_labels in test_loader:
            sequences = sequences.to(device)
            pred_state, pred_stage_logits, _ = model(sequences)

            preds = torch.argmax(pred_stage_logits, dim=-1).cpu().numpy()
            all_preds.extend(preds)
            all_targets.extend(future_labels.numpy())

            all_pred_states.extend(pred_state.cpu().numpy())
            all_true_states.extend(future_states.numpy())

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
    cm = confusion_matrix(all_targets, all_preds, labels=present_labels).tolist()

    return {
        "horizon_steps": horizon,
        "horizon_seconds": horizon * 2.0,  # 2s step size
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "state_mse": state_mse,
        "report": report,
        "confusion_matrix": cm,
        "present_labels": present_labels
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate World Model multi-horizon forecasting")
    parser.add_argument("--checkpoint", default="models/world_model_lstm_best.pt", help="Path to checkpoint")
    parser.add_argument("--data_dir", default="data/processed", help="Path to processed data")
    parser.add_argument("--horizons", nargs="+", type=int, default=[1, 5, 10], help="Forecast horizons K")
    args = parser.parse_args()

    print("="*70)
    print("      WORLD MODEL MULTI-HORIZON FORECASTING EVALUATION")
    print("="*70)

    for K in args.horizons:
        sec = K * 2.0
        print(f"\nEvaluating Forecast Horizon: K = {K} steps ({sec:.0f}s ahead in time) ...")
        res = evaluate_horizon(args.checkpoint, args.data_dir, horizon=K)

        print(f"--- Horizon K={K} ({sec:.0f}s Ahead) Results ---")
        print(f"Accuracy:          {res['accuracy']:.4f}")
        print(f"Balanced Accuracy: {res['balanced_accuracy']:.4f}")
        print(f"Macro F1-Score:    {res['macro_f1']:.4f}")
        print(f"Weighted F1-Score: {res['weighted_f1']:.4f}")
        print(f"State Vector MSE:  {res['state_mse']:.4f}")
        print("\nClassification Report:")
        print(res["report"])


if __name__ == "__main__":
    main()
