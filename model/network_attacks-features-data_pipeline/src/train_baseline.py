"""
Baseline Logistic Regression — v2

Trains a multinomial Logistic Regression on windowed state features.
Supports both:
  (a) single PCAP + list file (fast, for DARPA_eval_b sample)
  (b) pre-built Parquet splits from build_dataset.py (for full week1)

Temporal split is always respected — NO random shuffling of overlapping windows.
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, balanced_accuracy_score, f1_score
)
from src.mitre_mapping import STAGE_NAMES

META_COLS = [
    "day", "split", "window_idx", "window_start_time", "window_end_time",
    "active_session_count", "is_attack", "mitre_stage_code",
    "mitre_stage_name", "active_attack_names"
]


def get_feature_cols(df: pd.DataFrame) -> List[str]:
    """Return all numeric non-metadata, non-delta feature columns."""
    return [
        c for c in df.columns
        if c not in META_COLS
        and np.issubdtype(df[c].dtype, np.number)
        and not c.startswith("delta_")
    ]


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=42,
            C=1.0
        ))
    ])


def evaluate(y_true, y_pred, stage_names: Dict[int, str]) -> Dict[str, Any]:
    present_labels = sorted(set(y_true) | set(y_pred))
    target_names = [stage_names.get(int(l), f"Stage {l}") for l in present_labels]
    return {
        "accuracy":          float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1":          float(f1_score(y_true, y_pred, average="macro",    zero_division=0)),
        "weighted_f1":       float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "confusion_matrix":  confusion_matrix(y_true, y_pred, labels=present_labels).tolist(),
        "report":            classification_report(y_true, y_pred, labels=present_labels,
                                                   target_names=target_names, zero_division=0),
    }


def train_on_parquet_splits(train_path: str, val_path: str) -> Dict[str, Any]:
    """Train on pre-built Parquet splits (temporal split, no leakage)."""
    df_train = pd.read_parquet(train_path)
    df_val   = pd.read_parquet(val_path)

    feat_cols = get_feature_cols(df_train)
    X_train = df_train[feat_cols].fillna(0.0)
    y_train = df_train["mitre_stage_code"].astype(int)
    X_val   = df_val[feat_cols].fillna(0.0)
    y_val   = df_val["mitre_stage_code"].astype(int)

    print(f"Train: {len(X_train)} windows | Val: {len(X_val)} windows")
    print(f"Features: {len(feat_cols)}")
    print(f"Train stage distribution:\n{y_train.value_counts().sort_index()}")
    print(f"Val stage distribution:\n{y_val.value_counts().sort_index()}")

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_val)

    results = evaluate(y_val, y_pred, STAGE_NAMES)
    results["pipeline"]      = pipe
    results["feature_names"] = feat_cols

    # Feature coefficients per stage
    coefs = pipe.named_steps["clf"].coef_
    classes = pipe.named_steps["clf"].classes_
    feature_coefficients = {}
    for i, cls_code in enumerate(classes):
        cls_name = STAGE_NAMES.get(int(cls_code), f"Stage {cls_code}")
        weights = coefs[i]
        top5_pos = np.argsort(weights)[::-1][:5]
        top5_neg = np.argsort(weights)[:5]
        feature_coefficients[cls_name] = {
            "top_positive": [(feat_cols[j], float(weights[j])) for j in top5_pos],
            "top_negative": [(feat_cols[j], float(weights[j])) for j in top5_neg],
        }
    results["feature_coefficients"] = feature_coefficients

    return results


def train_on_single_pcap(pcap: str, list_file: str, delta_t: float = 10.0, step: float = 2.0) -> Dict[str, Any]:
    """
    Temporal-split CV on a single PCAP (for DARPA_eval_b sample).
    Uses first 70% of windows for training, last 30% for eval.
    (No random shuffle — windows are overlapping)
    """
    from src.temporal_aggregator import TemporalStateAggregator
    agg = TemporalStateAggregator(pcap, list_file)
    df = agg.aggregate_windows(delta_t=delta_t, step_size=step, include_deltas=True)

    feat_cols = get_feature_cols(df)
    X = df[feat_cols].fillna(0.0)
    y = df["mitre_stage_code"].astype(int)

    # Temporal split (no shuffle)
    split_idx = int(0.7 * len(df))
    X_train, y_train = X.iloc[:split_idx], y.iloc[:split_idx]
    X_val,   y_val   = X.iloc[split_idx:], y.iloc[split_idx:]

    print(f"Train: {len(X_train)} windows | Val: {len(X_val)} windows")
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_val)

    results = evaluate(y_val, y_pred, STAGE_NAMES)
    results["pipeline"]      = pipe
    results["feature_names"] = feat_cols
    return results


def print_results(results: Dict[str, Any]):
    print("\n" + "="*60)
    print("       LOGISTIC REGRESSION BASELINE RESULTS")
    print("="*60)
    print(f"Overall Accuracy:          {results['accuracy']:.4f}")
    print(f"Balanced Accuracy:         {results['balanced_accuracy']:.4f}")
    print(f"Macro F1-Score:            {results['macro_f1']:.4f}")
    print(f"Weighted F1-Score:         {results['weighted_f1']:.4f}")
    print("\nClassification Report:")
    print(results["report"])

    if "feature_coefficients" in results:
        print("\n--- Top Features per Stage ---")
        for stage, coef_dict in results["feature_coefficients"].items():
            print(f"\n[{stage}]")
            for feat, w in coef_dict["top_positive"]:
                print(f"  + {feat:<30}: {w:+.4f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode",      choices=["pcap", "parquet"], default="pcap")
    parser.add_argument("--pcap",      default="DARPA_eval_b/sample_data01.pcap")
    parser.add_argument("--list",      default="DARPA_eval_b/tcpdump.list")
    parser.add_argument("--train_pq",  default="data/processed/split_train_dt10s.parquet")
    parser.add_argument("--val_pq",    default="data/processed/split_val_dt10s.parquet")
    parser.add_argument("--delta_t",   type=float, default=10.0)
    parser.add_argument("--step",      type=float, default=2.0)
    args = parser.parse_args()

    if args.mode == "parquet":
        results = train_on_parquet_splits(args.train_pq, args.val_pq)
    else:
        results = train_on_single_pcap(args.pcap, args.list, args.delta_t, args.step)

    print_results(results)
