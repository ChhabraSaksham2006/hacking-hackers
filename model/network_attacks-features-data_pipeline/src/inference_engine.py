"""
Core World Model Inference Engine

Loads trained Unified World Model weights and normalization parameters to provide:
  1. Single-Step Prediction: Predicts S_{t+1} (denormalized physical telemetry) and Y_{t+1} (MITRE stage probabilities).
  2. Multi-Step Autoregressive Rollout: Forecasts S_{t+1 ... t+K} and Y_{t+1 ... t+K} into the future.
  3. Risk & State Drift Scoring: Detects abnormal state transitions and security alerts.
"""

import os
import sys
import glob
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List, Tuple, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.dataset_sequence import get_feature_columns
from src.world_model import LSTMWorldModel
from src.mitre_mapping import STAGE_NAMES


class WorldModelInferenceEngine:
    """
    Unified Inference Engine for the Dual-Head LSTM World Model.
    """
    def __init__(
        self,
        model_path: str = "models/unified_world_model_best.pt",
        data_sample_dir: str = "data/processed",
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_classes: int = 5,
        device: Optional[torch.device] = None
    ):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.num_classes = num_classes

        # ── 1. Discover Feature Schema & Fit Scaler ──────────────────────────
        darpa_pqs = sorted(glob.glob(os.path.join(data_sample_dir, "windows_*_dt10s.parquet")))
        if not darpa_pqs:
            darpa_pqs = sorted(glob.glob("data/backup_darpa_week1/windows_*_dt10s.parquet"))
            
        sample_df = pd.read_parquet(darpa_pqs[0])
        self.feature_cols = get_feature_columns(sample_df)
        self.input_dim = len(self.feature_cols)

        # Build standard scaler based on baseline data
        all_samples = []
        for p in darpa_pqs[:3]:
            df = pd.read_parquet(p)
            all_samples.append(df[self.feature_cols].values)
            
        cic_pqs = sorted(glob.glob("data/processed_cic/*.parquet"))
        for p in cic_pqs[:2]:
            df = pd.read_parquet(p)
            all_samples.append(df[self.feature_cols].values)

        concat_samples = np.nan_to_num(np.vstack(all_samples), nan=0.0, posinf=1e6, neginf=-1e6)
        self.scaler = StandardScaler()
        self.scaler.fit(concat_samples)

        # ── 2. Load Model Checkpoint ─────────────────────────────────────────
        self.model = LSTMWorldModel(
            input_dim=self.input_dim,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            num_classes=num_classes
        ).to(self.device)

        if os.path.exists(model_path):
            state_dict = torch.load(model_path, map_location=self.device, weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            print(f"[InferenceEngine] Loaded World Model weights from: {model_path} ({self.input_dim} features)")
        else:
            raise FileNotFoundError(f"Model checkpoint not found at {model_path}")

    def normalize_sequence(self, raw_sequence: np.ndarray) -> np.ndarray:
        """Normalizes a raw (P, 47) feature array using fitted StandardScaler."""
        cleaned = np.nan_to_num(raw_sequence, nan=0.0, posinf=1e6, neginf=-1e6)
        scaled = np.clip(self.scaler.transform(cleaned), -10.0, 10.0)
        return scaled.astype(np.float32)

    def denormalize_state(self, scaled_state: np.ndarray) -> Dict[str, float]:
        """Denormalizes a (47,) scaled state vector back to physical network telemetry."""
        scaled_2d = scaled_state.reshape(1, -1)
        raw_2d = self.scaler.inverse_transform(scaled_2d).flatten()
        return {col: float(val) for col, val in zip(self.feature_cols, raw_2d)}

    def predict_step(self, raw_history_sequence: np.ndarray) -> Dict[str, Any]:
        """
        Executes a 1-step lookahead prediction given historical window sequence [S_{t-P+1} ... S_t].
        
        Args:
            raw_history_sequence: np.ndarray of shape (P, 47) where P >= 10.
        
        Returns:
            Dict containing predicted state, stage probabilities, and risk metrics.
        """
        # Take the most recent 10 windows
        seq_slice = raw_history_sequence[-10:]
        scaled_seq = self.normalize_sequence(seq_slice)
        tensor_in = torch.tensor(scaled_seq, dtype=torch.float32).unsqueeze(0).to(self.device)

        with torch.no_grad():
            pred_scaled_state, stage_logits, _ = self.model(tensor_in)
            probs = F.softmax(stage_logits, dim=-1).cpu().numpy().flatten()
            pred_stage_code = int(np.argmax(probs))
            pred_scaled_state_np = pred_scaled_state.cpu().numpy().flatten()

        # Denormalize predicted state to physical telemetry
        pred_telemetry = self.denormalize_state(pred_scaled_state_np)

        # Risk score = 1.0 - Benign probability
        benign_prob = float(probs[0])
        attack_risk_score = float(1.0 - benign_prob)

        # Threat classification
        stage_name = STAGE_NAMES.get(pred_stage_code, f"Stage {pred_stage_code}")
        
        alert_level = "LOW"
        if attack_risk_score > 0.8:
            alert_level = "CRITICAL"
        elif attack_risk_score > 0.5:
            alert_level = "HIGH"
        elif attack_risk_score > 0.2:
            alert_level = "MEDIUM"

        return {
            "predicted_stage_code": pred_stage_code,
            "predicted_stage_name": stage_name,
            "confidence": float(probs[pred_stage_code]),
            "stage_probabilities": {
                f"stage_{i}_{STAGE_NAMES.get(i,'?')}": float(probs[i])
                for i in range(self.num_classes)
            },
            "risk_score": attack_risk_score,
            "alert_level": alert_level,
            "predicted_telemetry_summary": {
                "packet_rate": max(0.0, pred_telemetry.get("packet_rate", 0.0)),
                "byte_rate": max(0.0, pred_telemetry.get("byte_rate", 0.0)),
                "syn_ratio": float(np.clip(pred_telemetry.get("syn_ratio", 0.0), 0.0, 1.0)),
                "ack_ratio": float(np.clip(pred_telemetry.get("ack_ratio", 0.0), 0.0, 1.0)),
                "auth_packet_ratio": float(np.clip(pred_telemetry.get("auth_packet_ratio", 0.0), 0.0, 1.0)),
                "fragment_count": max(0.0, pred_telemetry.get("fragment_count", 0.0)),
                "oversized_icmp_count": max(0.0, pred_telemetry.get("oversized_icmp_count", 0.0))
            },
            "full_predicted_state_vector": pred_telemetry
        }

    def predict_batch(self, raw_history_sequences: np.ndarray, batch_size: int = 512) -> List[Dict[str, Any]]:
        """
        Vectorized batch prediction across N sequences of shape (N, P, 47).
        Evaluates tens of thousands of sliding windows in seconds.
        """
        N, P, D = raw_history_sequences.shape
        seq_slice = raw_history_sequences[:, -10:, :]  # (N, 10, D)
        
        # Vectorized Normalization
        flat_seqs = seq_slice.reshape(-1, D)
        cleaned = np.nan_to_num(flat_seqs, nan=0.0, posinf=1e6, neginf=-1e6)
        scaled_flat = np.clip(self.scaler.transform(cleaned), -10.0, 10.0)
        scaled_seqs = scaled_flat.reshape(N, 10, D).astype(np.float32)

        all_pred_states = []
        all_probs = []

        with torch.no_grad():
            for i in range(0, N, batch_size):
                batch_tensor = torch.tensor(scaled_seqs[i : i + batch_size], dtype=torch.float32).to(self.device)
                pred_states, stage_logits, _ = self.model(batch_tensor)
                probs = F.softmax(stage_logits, dim=-1)

                all_pred_states.append(pred_states.cpu().numpy())
                all_probs.append(probs.cpu().numpy())

        all_pred_states = np.vstack(all_pred_states)
        all_probs = np.vstack(all_probs)

        # Vectorized Denormalization
        denorm_states = self.scaler.inverse_transform(all_pred_states)

        results = []
        for i in range(N):
            probs_i = all_probs[i]
            pred_stage_code = int(np.argmax(probs_i))
            stage_name = STAGE_NAMES.get(pred_stage_code, f"Stage {pred_stage_code}")
            benign_prob = float(probs_i[0])
            risk_score = float(1.0 - benign_prob)

            alert_level = "LOW"
            if risk_score > 0.8:
                alert_level = "CRITICAL"
            elif risk_score > 0.5:
                alert_level = "HIGH"
            elif risk_score > 0.2:
                alert_level = "MEDIUM"

            state_dict = {col: float(val) for col, val in zip(self.feature_cols, denorm_states[i])}

            results.append({
                "predicted_stage_code": pred_stage_code,
                "predicted_stage_name": stage_name,
                "confidence": float(probs_i[pred_stage_code]),
                "stage_probabilities": {
                    f"stage_{k}_{STAGE_NAMES.get(k,'?')}": float(probs_i[k])
                    for k in range(self.num_classes)
                },
                "risk_score": risk_score,
                "alert_level": alert_level,
                "predicted_telemetry_summary": {
                    "packet_rate": max(0.0, state_dict.get("packet_rate", 0.0)),
                    "byte_rate": max(0.0, state_dict.get("byte_rate", 0.0)),
                    "syn_ratio": float(np.clip(state_dict.get("syn_ratio", 0.0), 0.0, 1.0)),
                    "ack_ratio": float(np.clip(state_dict.get("ack_ratio", 0.0), 0.0, 1.0)),
                    "auth_packet_ratio": float(np.clip(state_dict.get("auth_packet_ratio", 0.0), 0.0, 1.0)),
                    "fragment_count": max(0.0, state_dict.get("fragment_count", 0.0)),
                    "oversized_icmp_count": max(0.0, state_dict.get("oversized_icmp_count", 0.0))
                },
                "full_predicted_state_vector": state_dict
            })

        return results

    def forecast_trajectory(
        self,
        raw_history_sequence: np.ndarray,
        horizon_steps: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Autoregressively rolls out predictions K steps into the future.
        """
        current_history = list(raw_history_sequence[-10:])
        trajectory = []

        for step in range(1, horizon_steps + 1):
            history_arr = np.array(current_history[-10:])
            step_result = self.predict_step(history_arr)
            step_result["forecast_step"] = step
            trajectory.append(step_result)

            # Feed predicted state back into rolling sequence
            next_raw_state = np.array([step_result["full_predicted_state_vector"][c] for c in self.feature_cols])
            current_history.append(next_raw_state)

        return trajectory
