"""
Network Sequence Dataset Module for World Model

Constructs temporal sliding sequence tensors [S_{t-P+1}, ..., S_t] from window Parquet files
paired with future state S_{t+K} and future MITRE attack stage Y_{t+K}.
Preserves distinct day boundaries and supports class-balanced sampling.
"""

import os
import sys
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.preprocessing import StandardScaler
from typing import Tuple, List, Dict, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.mitre_mapping import STAGE_NAMES

META_COLS = [
    "day", "split", "window_idx", "window_start_time", "window_end_time",
    "active_session_count", "is_attack", "mitre_stage_code",
    "mitre_stage_name", "active_attack_names"
]


def get_feature_columns(df: pd.DataFrame) -> List[str]:
    """Returns numerical feature column names (excluding metadata and raw delta prefixes)."""
    return [
        c for c in df.columns
        if c not in META_COLS
        and np.issubdtype(df[c].dtype, np.number)
        and not c.startswith("delta_")
    ]


class NetworkSequenceDataset(Dataset):
    """
    PyTorch Dataset generating sliding sequence windows:
      Input:  X_t = [S_{t-P+1}, ..., S_t]  (shape: [P, D])
      Target: S_{t+K}                       (shape: [D])
              Y_{t+K}                       (shape: [1], class integer 0..4)
    """

    def __init__(
        self,
        df: pd.DataFrame,
        feature_cols: List[str],
        scaler: Optional[StandardScaler] = None,
        lookback: int = 10,
        horizon: int = 1,
        fit_scaler: bool = False
    ):
        self.lookback = lookback
        self.horizon = horizon
        self.feature_cols = feature_cols

        # Group data by day so sequences never cross overnight boundaries
        self.sequences = []
        self.future_states = []
        self.future_labels = []
        self.sample_weights = []

        # Fit or apply scaler
        X_raw = df[feature_cols].fillna(0.0).values
        if fit_scaler or scaler is None:
            self.scaler = StandardScaler()
            self.scaler.fit(X_raw)
        else:
            self.scaler = scaler

        # Process each day independently
        days = df["day"].unique() if "day" in df.columns else ["default"]
        for day in days:
            day_df = df[df["day"] == day] if "day" in df.columns else df
            if len(day_df) < (lookback + horizon):
                continue

            day_features = self.scaler.transform(day_df[feature_cols].fillna(0.0).values)
            day_labels = day_df["mitre_stage_code"].values.astype(np.int64)

            n_samples = len(day_df) - lookback - horizon + 1
            for i in range(n_samples):
                seq_x = day_features[i : i + lookback]                  # [P, D]
                target_state = day_features[i + lookback + horizon - 1] # [D]
                target_label = day_labels[i + lookback + horizon - 1]   # int

                self.sequences.append(seq_x)
                self.future_states.append(target_state)
                self.future_labels.append(target_label)

                # Weight: give higher weight to attack sequences (stage > 0)
                weight = 10.0 if target_label > 0 else 1.0
                self.sample_weights.append(weight)

        self.sequences = torch.tensor(np.array(self.sequences), dtype=torch.float32)
        self.future_states = torch.tensor(np.array(self.future_states), dtype=torch.float32)
        self.future_labels = torch.tensor(np.array(self.future_labels), dtype=torch.long)
        self.sample_weights = torch.tensor(self.sample_weights, dtype=torch.double)

    def __len__(self) -> int:
        return len(self.future_labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        return self.sequences[idx], self.future_states[idx], self.future_labels[idx]


def create_dataloaders(
    data_dir: str,
    lookback: int = 10,
    horizon: int = 1,
    batch_size: int = 128,
    num_workers: int = 0
) -> Tuple[DataLoader, DataLoader, DataLoader, StandardScaler, List[str]]:
    """
    Creates Train, Validation, and Test DataLoaders from processed Parquet splits.
    """
    train_pq = os.path.join(data_dir, "split_train_dt10s.parquet")
    val_pq   = os.path.join(data_dir, "split_val_dt10s.parquet")
    test_pq  = os.path.join(data_dir, "split_test_dt10s.parquet")

    df_train = pd.read_parquet(train_pq)
    df_val   = pd.read_parquet(val_pq)
    df_test  = pd.read_parquet(test_pq)

    feature_cols = get_feature_columns(df_train)

    # Train dataset (fits scaler)
    train_dataset = NetworkSequenceDataset(
        df_train, feature_cols, scaler=None, fit_scaler=True,
        lookback=lookback, horizon=horizon
    )

    # Val & Test datasets (uses fitted scaler from train)
    val_dataset = NetworkSequenceDataset(
        df_val, feature_cols, scaler=train_dataset.scaler, fit_scaler=False,
        lookback=lookback, horizon=horizon
    )

    test_dataset = NetworkSequenceDataset(
        df_test, feature_cols, scaler=train_dataset.scaler, fit_scaler=False,
        lookback=lookback, horizon=horizon
    )

    # Balanced Sampler for Training to ensure attack batches are well-represented
    sampler = WeightedRandomSampler(
        weights=train_dataset.sample_weights,
        num_samples=len(train_dataset),
        replacement=True
    )

    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, sampler=sampler, num_workers=num_workers
    )
    val_loader = DataLoader(
        val_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers
    )
    test_loader = DataLoader(
        test_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers
    )

    return train_loader, val_loader, test_loader, train_dataset.scaler, feature_cols
