"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.temporal.dataset_builder

Temporal Sequence Dataset Builder & PyTorch Dataset.
Constructs sliding lookback sequences [S_{t-P+1}, ..., S_t] -> S_{t+K}
with multi-horizon target labels, strict daily boundary isolation,
and leakage-free scaling across chronological train/val/test splits.
"""

from typing import Dict, List, Optional, Tuple, Union, Any
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler

from src.temporal.state_aggregator import (
    STATE_FEATURE_NAMES,
    FAMILY_TO_IDX
)


# Chronological Dataset Split Definition
TRAIN_DAYS = [
    "Wednesday-14-02-2018.parquet",
    "Thursday-15-02-2018.parquet",
    "Friday-16-02-2018.parquet",
    "Wednesday-21-02-2018.parquet",
    "Thursday-22-02-2018.parquet"
]

VAL_DAYS = [
    "Friday-23-02-2018.parquet"
]

TEST_DAYS = [
    "Wednesday-28-02-2018.parquet",
    "Thursday-01-03-2018.parquet",
    "Friday-02-03-2018.parquet"
]


class TemporalForecastingDataset(Dataset):
    """
    PyTorch Dataset providing fixed-length historical lookback sequences
    and multi-horizon forecasting targets.
    """

    def __init__(
        self,
        sequences: np.ndarray,            # Shape: (N, P, D=54)
        targets_state: Dict[int, np.ndarray],   # Horizon K -> Shape: (N, D=54)
        targets_binary: Dict[int, np.ndarray],  # Horizon K -> Shape: (N,)
        targets_family: Dict[int, np.ndarray],  # Horizon K -> Shape: (N,)
        targets_tau: np.ndarray,                # Shape: (N,)
        metadata: pd.DataFrame                 # Sequence anchor metadata
    ):
        self.horizons = sorted(targets_state.keys())
        self.sequences = torch.from_numpy(sequences).float()
        self.targets_state = {k: torch.from_numpy(v).float() for k, v in targets_state.items()}
        self.targets_binary = {k: torch.from_numpy(v).long() for k, v in targets_binary.items()}
        self.targets_family = {k: torch.from_numpy(v).long() for k, v in targets_family.items()}
        self.targets_tau = torch.from_numpy(targets_tau).float()
        self.metadata = metadata

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        sample = {
            'input_sequence': self.sequences[idx],
            'target_tau': self.targets_tau[idx],
            # Multi-horizon targets
            'target_state_k1': self.targets_state[1][idx],
            'target_state_k3': self.targets_state[3][idx],
            'target_state_k5': self.targets_state[5][idx],
            'target_state_k10': self.targets_state[10][idx],
            'target_binary_k1': self.targets_binary[1][idx],
            'target_binary_k3': self.targets_binary[3][idx],
            'target_binary_k5': self.targets_binary[5][idx],
            'target_binary_k10': self.targets_binary[10][idx],
            'target_family_k1': self.targets_family[1][idx],
            'target_family_k3': self.targets_family[3][idx],
            'target_family_k5': self.targets_family[5][idx],
        }
        for k in self.horizons:
            sample[f'target_state_k{k}'] = self.targets_state[k][idx]
            sample[f'target_binary_k{k}'] = self.targets_binary[k][idx]
            sample[f'target_family_k{k}'] = self.targets_family[k][idx]
        return sample


class TemporalSequenceBuilder:
    """
    Builds structured sequence arrays from aggregated daily state Parquet files.
    """

    def __init__(
        self,
        lookback_steps: int = 10,
        horizons: Optional[List[int]] = None,
        feature_names: Optional[List[str]] = None
    ):
        self.lookback = int(lookback_steps)
        self.horizons = horizons or [1, 3, 5, 10, 25, 50, 100, 200]
        self.max_horizon = max(self.horizons)
        self.feature_names = feature_names or STATE_FEATURE_NAMES
        self.scaler: Optional[StandardScaler] = None

    def fit_scaler(self, train_dfs: List[pd.DataFrame]) -> StandardScaler:
        """
        Fits a StandardScaler strictly on the training session state features.
        """
        self.scaler = StandardScaler()
        all_train_features = []
        for df in train_dfs:
            feats = df[self.feature_names].values.astype(np.float32)
            # Impute any NaNs with 0 prior to scaling
            feats = np.nan_to_num(feats, nan=0.0, posinf=0.0, neginf=0.0)
            all_train_features.append(feats)

        stacked_features = np.vstack(all_train_features)
        self.scaler.fit(stacked_features)
        return self.scaler

    def transform_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforms a DataFrame's continuous state features using the fitted scaler.
        """
        if self.scaler is None:
            raise RuntimeError("Scaler must be fitted before transforming data.")

        df_copy = df.copy()
        raw_feats = df_copy[self.feature_names].values.astype(np.float32)
        raw_feats = np.nan_to_num(raw_feats, nan=0.0, posinf=0.0, neginf=0.0)
        scaled_feats = self.scaler.transform(raw_feats)
        df_copy[self.feature_names] = scaled_feats
        return df_copy

    def extract_session_sequences(
        self,
        session_df: pd.DataFrame
    ) -> Tuple[np.ndarray, Dict[int, np.ndarray], Dict[int, np.ndarray], Dict[int, np.ndarray], np.ndarray, pd.DataFrame]:
        """
        Extracts valid sliding sequences [t-P+1 ... t] and future targets [t+K]
        strictly bounded within a single session.
        """
        n_windows = len(session_df)
        min_required = self.lookback + self.max_horizon
        if n_windows < min_required:
            raise ValueError(
                f"Session has {n_windows} windows, but at least {min_required} are required."
            )

        features = session_df[self.feature_names].values.astype(np.float32)
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

        is_attack = session_df['is_attack'].values.astype(np.int64)
        family_indices = session_df['family_idx'].values.astype(np.int64)
        tau_onset = session_df['time_to_attack_onset_sec'].values.astype(np.float32)

        # Valid anchor indices: t such that t - lookback + 1 >= 0 and t + max_horizon < n_windows
        # i.e., t in [lookback - 1, n_windows - 1 - max_horizon]
        start_t = self.lookback - 1
        end_t = n_windows - 1 - self.max_horizon
        n_samples = end_t - start_t + 1

        # Fast sliding window view for sequences: shape (n_windows - lookback + 1, lookback, D)
        windows_all = np.lib.stride_tricks.sliding_window_view(
            features, window_shape=(self.lookback, len(self.feature_names))
        )[:, 0, :, :]
        # Sequence corresponding to anchor t is window at index (t - lookback + 1)
        # For t in [start_t, end_t], index in windows_all is [0, n_samples - 1]
        seq_array = np.ascontiguousarray(windows_all[:n_samples])
        tau_array = np.ascontiguousarray(tau_onset[start_t : end_t + 1])

        targets_state: Dict[int, np.ndarray] = {}
        targets_binary: Dict[int, np.ndarray] = {}
        targets_family: Dict[int, np.ndarray] = {}

        for k in self.horizons:
            targets_state[k] = np.ascontiguousarray(features[start_t + k : end_t + k + 1])
            targets_binary[k] = np.ascontiguousarray(is_attack[start_t + k : end_t + k + 1])
            targets_family[k] = np.ascontiguousarray(family_indices[start_t + k : end_t + k + 1])

        # Metadata
        meta_df = pd.DataFrame({
            'session_id': session_df['session_id'].iloc[start_t : end_t + 1].values,
            'anchor_window_idx': np.arange(start_t, end_t + 1, dtype=np.int32),
            'anchor_timestamp': session_df['timestamp_end'].iloc[start_t : end_t + 1].values,
            'is_attack_current': is_attack[start_t : end_t + 1],
            'family_current': session_df['dominant_attack_family'].iloc[start_t : end_t + 1].values,
            'tau_onset': tau_array
        })
        return seq_array, targets_state, targets_binary, targets_family, tau_array, meta_df

    def build_dataset_from_sessions(
        self,
        session_dfs: List[pd.DataFrame]
    ) -> TemporalForecastingDataset:
        """
        Combines sequences from multiple sessions into a unified TemporalForecastingDataset.
        """
        all_seqs = []
        all_tau = []
        all_states = {k: [] for k in self.horizons}
        all_binary = {k: [] for k in self.horizons}
        all_family = {k: [] for k in self.horizons}
        all_metas = []

        for s_df in session_dfs:
            seqs, t_state, t_bin, t_fam, tau, meta = self.extract_session_sequences(s_df)
            all_seqs.append(seqs)
            all_tau.append(tau)
            all_metas.append(meta)
            for k in self.horizons:
                all_states[k].append(t_state[k])
                all_binary[k].append(t_bin[k])
                all_family[k].append(t_fam[k])

        combined_seqs = np.vstack(all_seqs)
        combined_tau = np.concatenate(all_tau)
        combined_meta = pd.concat(all_metas, ignore_index=True)

        combined_states = {k: np.vstack(all_states[k]) for k in self.horizons}
        combined_binary = {k: np.concatenate(all_binary[k]) for k in self.horizons}
        combined_family = {k: np.concatenate(all_family[k]) for k in self.horizons}

        return TemporalForecastingDataset(
            sequences=combined_seqs,
            targets_state=combined_states,
            targets_binary=combined_binary,
            targets_family=combined_family,
            targets_tau=combined_tau,
            metadata=combined_meta
        )
