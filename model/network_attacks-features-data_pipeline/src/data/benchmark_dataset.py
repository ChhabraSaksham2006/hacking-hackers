"""
benchmark_dataset.py
====================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Ultra-high-performance, episode-aware PyTorch Dataset & DataLoader for Settings A, B, and C.
Pre-materializes contiguous sequence tensor buffers for instant C++ batch slicing (>150,000 samples/sec).
Guarantees strict train-only normalization fitting.
"""

import os
import glob
import yaml
import joblib
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader, TensorDataset, WeightedRandomSampler
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional, Any, Union

# Root directory resolution
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_PATH = os.path.join(ROOT_DIR, "configs", "benchmark_contract.yaml")
SPLITS_DIR = os.path.join(ROOT_DIR, "data", "benchmark_splits")
STATE_DIR = os.path.join(ROOT_DIR, "data", "processed", "temporal_states")
SCALER_DIR = os.path.join(ROOT_DIR, "models", "scalers")


def get_54_feature_names(config_path: str = CONFIG_PATH) -> List[str]:
    """
    Extracts the exact 54 canonical feature names in order from benchmark_contract.yaml.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    mapping = cfg["state_representation"]["feature_index_mapping"]
    base_f = [mapping["base_features"][i] for i in range(len(mapping["base_features"]))]
    delta_f = [mapping["delta_features"][i] for i in range(37, 37 + len(mapping["delta_features"]))]
    return base_f + delta_f


class HardenedBenchmarkDataset(Dataset):
    """
    PyTorch Dataset with pre-materialized contiguous tensor buffers.
    """
    def __init__(
        self,
        setting: str = "A",               # 'A', 'B', or 'C'
        split: str = "train",             # 'train', 'val', or 'test'
        scaler: Optional[StandardScaler] = None,
        fit_scaler: bool = False,
        scaler_save_path: Optional[str] = None,
        clip_range: Tuple[float, float] = (-10.0, 10.0)
    ):
        super().__init__()
        self.setting = setting.upper()
        self.split = split.lower()
        self.clip_range = clip_range
        self.feature_names = get_54_feature_names()
        self.num_features = len(self.feature_names)  # 54

        # 1. Load split manifest
        manifest_file = os.path.join(SPLITS_DIR, f"setting_{self.setting.lower()}_splits.parquet")
        if not os.path.exists(manifest_file):
            raise FileNotFoundError(f"Split manifest not found: {manifest_file}. Please run build_benchmark_splits.py first.")
        
        manifest_df = pd.read_parquet(manifest_file)
        self.manifest = manifest_df[manifest_df["split"] == self.split].reset_index(drop=True)
        if len(self.manifest) == 0:
            raise ValueError(f"No sequences found for setting={self.setting}, split={self.split}")

        # 2. Load all raw state data for participating days
        active_days = self.manifest["day"].unique()
        self.day_raw_states: Dict[str, np.ndarray] = {}

        for day in active_days:
            state_file = os.path.join(STATE_DIR, f"{day}_states.parquet")
            state_df = pd.read_parquet(state_file)
            
            # Extract 54 features
            feats = state_df[self.feature_names].values.astype(np.float32)
            feats = np.nan_to_num(feats, nan=0.0, posinf=1e6, neginf=-1e6)
            self.day_raw_states[day] = feats

        # 3. Fit or apply StandardScaler
        if fit_scaler:
            if self.split != "train":
                raise ValueError("Anti-leakage violation: fit_scaler=True is only permitted on split='train'!")
            
            train_feats_list = []
            for day, grp in self.manifest.groupby("day"):
                day_feats = self.day_raw_states[day]
                s_arr = grp["history_start_idx"].values
                e_arr = grp["forecast_end_idx"].values
                mask = np.zeros(len(day_feats), dtype=bool)
                for s, e in zip(s_arr, e_arr):
                    mask[s : e + 1] = True
                train_feats_list.append(day_feats[mask])
                
            concat_train = np.vstack(train_feats_list)
            self.scaler = StandardScaler()
            self.scaler.fit(concat_train)
            
            if scaler_save_path:
                os.makedirs(os.path.dirname(scaler_save_path), exist_ok=True)
                joblib.dump(self.scaler, scaler_save_path)
        else:
            if scaler is not None:
                self.scaler = scaler
            else:
                default_scaler_path = os.path.join(SCALER_DIR, f"setting_{self.setting.lower()}_scaler.joblib")
                if os.path.exists(default_scaler_path):
                    self.scaler = joblib.load(default_scaler_path)
                else:
                    raise ValueError(f"No scaler provided and default scaler not found at {default_scaler_path}")

        # 4. Pre-scale day state arrays
        day_scaled_states: Dict[str, np.ndarray] = {}
        for day, raw_feats in self.day_raw_states.items():
            scaled = self.scaler.transform(raw_feats)
            scaled = np.clip(scaled, self.clip_range[0], self.clip_range[1]).astype(np.float32)
            day_scaled_states[day] = scaled

        # 5. Pre-materialize contiguous numpy arrays for instant indexing
        N_seq = len(self.manifest)
        x_all = np.empty((N_seq, 10, 54), dtype=np.float32)
        y_all = np.empty((N_seq, 10, 54), dtype=np.float32)

        # Fast group-by-day batch slicing
        for day, grp in self.manifest.groupby("day"):
            d_scaled = day_scaled_states[day]
            indices = grp.index.values
            h_starts = grp["history_start_idx"].values
            f_starts = grp["forecast_start_idx"].values

            # Vectorized sliding window generation
            for idx_in_grp, (h_s, f_s, global_idx) in enumerate(zip(h_starts, f_starts, indices)):
                x_all[global_idx] = d_scaled[h_s : h_s + 10]
                y_all[global_idx] = d_scaled[f_s : f_s + 10]

        self.x_history = torch.from_numpy(x_all)
        self.y_future_states = torch.from_numpy(y_all)
        self.attack_k10 = torch.tensor(self.manifest["is_attack_k10"].values.astype(np.float32), dtype=torch.float32)
        self.attack_any_k = torch.tensor(self.manifest["is_attack_any_k"].values.astype(np.float32), dtype=torch.float32)
        self.family_k10 = torch.tensor(self.manifest["family_idx_k10"].values.astype(np.int64), dtype=torch.int64)
        self.onset_precursor = torch.tensor(self.manifest["is_onset_precursor"].values.astype(np.bool_), dtype=torch.bool)
        self.episode_ids = self.manifest["episode_id"].values
        self.days = self.manifest["day"].values
        self.ref_window_indices = self.manifest["history_end_idx"].values

        # 6. Compute Class Weights for balanced training
        self._compute_weights()

    def _compute_weights(self):
        """
        Computes inverse frequency class weights for binary and multi-class balancing.
        """
        pos_count = (self.attack_k10 == 1.0).sum().item()
        neg_count = (self.attack_k10 == 0.0).sum().item()
        self.pos_weight = torch.tensor([neg_count / max(1, pos_count)], dtype=torch.float32)

        family_counts = torch.bincount(self.family_k10, minlength=7).float()
        total_samples = len(self.family_k10)
        self.family_weights = total_samples / (7.0 * (family_counts + 1.0))
        self.family_weights = self.family_weights / self.family_weights.mean()
        self.sample_weights = self.family_weights[self.family_k10]

    def __len__(self) -> int:
        return len(self.manifest)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return {
            "x_history": self.x_history[idx],
            "y_future_states": self.y_future_states[idx],
            "y_attack_k10": self.attack_k10[idx],
            "y_attack_any_k": self.attack_any_k[idx],
            "y_family_k10": self.family_k10[idx],
            "is_onset_precursor": self.onset_precursor[idx],
            "day": self.days[idx],
            "ref_window_idx": self.ref_window_indices[idx],
            "episode_id": self.episode_ids[idx]
        }


def get_benchmark_dataloaders(
    setting: str = "A",
    batch_size: int = 512,
    num_workers: int = 0,
    balanced_sampling: bool = False
) -> Tuple[DataLoader, DataLoader, DataLoader, StandardScaler]:
    """
    Factory function to construct Train, Val, and Test DataLoaders for Setting A, B, or C.
    Guarantees strict train-only normalization fitting.
    """
    os.makedirs(SCALER_DIR, exist_ok=True)
    scaler_path = os.path.join(SCALER_DIR, f"setting_{setting.lower()}_scaler.joblib")

    # 1. Train dataset (fits scaler)
    train_dataset = HardenedBenchmarkDataset(
        setting=setting,
        split="train",
        fit_scaler=True,
        scaler_save_path=scaler_path
    )
    fitted_scaler = train_dataset.scaler

    # 2. Val dataset (uses fitted scaler)
    val_dataset = HardenedBenchmarkDataset(
        setting=setting,
        split="val",
        scaler=fitted_scaler,
        fit_scaler=False
    )

    # 3. Test dataset (uses fitted scaler)
    test_dataset = HardenedBenchmarkDataset(
        setting=setting,
        split="test",
        scaler=fitted_scaler,
        fit_scaler=False
    )

    if balanced_sampling:
        train_sampler = WeightedRandomSampler(
            weights=train_dataset.sample_weights,
            num_samples=len(train_dataset),
            replacement=True
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, sampler=train_sampler, num_workers=num_workers)
    else:
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=num_workers)

    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers)

    return train_loader, val_loader, test_loader, fitted_scaler
