"""
Unified Multi-Domain Sequence Dataset (DARPA + CIC-IDS2017)

Constructs rolling sequence windows [S_{t-P+1}, ..., S_t] -> (S_{t+K}, Y_{t+K})
with strict session-boundary isolation and standardized scaling.
"""

import os
import sys
import glob
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Optional, Dict

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import get_feature_columns


class UnifiedMultiDomainDataset(Dataset):
    """
    Unified Sequence Dataset that spans multiple session DataFrames (DARPA + CIC-IDS2017).
    Guarantees no sequence lookback crosses session boundaries.
    """
    def __init__(
        self,
        session_dfs: List[pd.DataFrame],
        feature_cols: List[str],
        scaler: Optional[StandardScaler] = None,
        fit_scaler: bool = True,
        lookback: int = 10,
        horizon: int = 1,
        split_type: Optional[str] = None, # 'train', 'test', or None (all)
        train_ratio: float = 0.8
    ):
        self.lookback = lookback
        self.horizon = horizon
        self.feature_cols = feature_cols

        # ── 1. Fit or apply StandardScaler across all sessions ────────────────
        all_features = [df[feature_cols].values.astype(np.float32) for df in session_dfs]
        concat_features = np.vstack(all_features)
        concat_features = np.nan_to_num(concat_features, nan=0.0, posinf=1e6, neginf=-1e6)

        if fit_scaler:
            self.scaler = StandardScaler()
            self.scaler.fit(concat_features)
        else:
            self.scaler = scaler if scaler is not None else StandardScaler().fit(concat_features)

        # ── 2. Build sequences within each session independently ──────────────
        all_seq_x = []
        all_future_state = []
        all_future_label = []

        for i, df in enumerate(session_dfs):
            feats = df[feature_cols].values.astype(np.float32)
            feats = np.nan_to_num(feats, nan=0.0, posinf=1e6, neginf=-1e6)
            scaled_feats = np.clip(self.scaler.transform(feats), -10.0, 10.0).astype(np.float32)
            
            labels = df['mitre_stage_code'].values.astype(np.int64)
            n_rows = len(df)

            max_start = n_rows - lookback - horizon + 1
            if max_start <= 0:
                continue

            # Determine split ranges
            split_point = int(max_start * train_ratio)
            if split_type == 'train':
                start_range = range(0, split_point)
            elif split_type == 'test':
                start_range = range(split_point, max_start)
            else:
                start_range = range(0, max_start)

            for start in start_range:
                end = start + lookback
                target_idx = end + horizon - 1

                all_seq_x.append(scaled_feats[start:end])
                all_future_state.append(scaled_feats[target_idx])
                all_future_label.append(labels[target_idx])

        self.seq_x = torch.tensor(np.array(all_seq_x, dtype=np.float32))
        self.future_states = torch.tensor(np.array(all_future_state, dtype=np.float32))
        self.future_labels = torch.tensor(np.array(all_future_label, dtype=np.int64))

        # ── 3. Compute Class Weights and Sample Weights for Balanced Sampler ──
        class_counts = torch.bincount(self.future_labels, minlength=5).float()
        total_samples = len(self.future_labels)
        
        # Smooth inverse class weighting
        self.class_weights = total_samples / (5.0 * (class_counts + 1.0))
        self.class_weights = self.class_weights / self.class_weights.mean()
        
        self.sample_weights = self.class_weights[self.future_labels]

    def __len__(self) -> int:
        return len(self.future_labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        return self.seq_x[idx], self.future_states[idx], self.future_labels[idx]
