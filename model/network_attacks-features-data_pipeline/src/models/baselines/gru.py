"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.baselines.gru

Baseline 3: Recurrent GRU Multi-Horizon Temporal Forecaster.
Processes sequential network state trajectories [S_{t-P+1}, ..., S_t]
and forecasts future attack occurrence, attack families, continuous states,
and time-to-attack onset across multiple horizons.
"""

from typing import Dict, List, Optional, Tuple, Any
import torch
import torch.nn as nn
import torch.nn.functional as F


class TemporalGRUForecaster(nn.Module):
    """
    Multi-horizon Gated Recurrent Unit (GRU) sequence forecaster.
    """

    def __init__(
        self,
        input_dim: int = 54,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.1,
        horizons: Optional[List[int]] = None,
        num_classes: int = 7
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.horizons = horizons or [1, 3, 5, 10, 25, 50, 100, 200]
        self.num_classes = num_classes

        # Recurrent Core
        self.gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(hidden_dim)

        # Multi-Horizon Prediction Heads
        self.binary_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(hidden_dim, 64),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(64, 1)
            )
            for k in self.horizons
        })

        self.state_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(hidden_dim, 64),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(64, input_dim)
            )
            for k in self.horizons
        })

        self.family_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(hidden_dim, 64),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(64, num_classes)
            )
            for k in self.horizons
        })

        # Time-to-attack onset regressor
        self.tau_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
            nn.ReLU()  # tau >= 0
        )

    def forward(self, x: torch.Tensor) -> Dict[str, Any]:
        """
        Parameters
        ----------
        x : torch.Tensor of shape (B, P, D)
            Lookback sequence tensor.

        Returns
        -------
        Dict[str, Any] containing logits, state forecasts, family logits, and tau.
        """
        # GRU outputs: out shape (B, P, hidden_dim), h_n shape (num_layers, B, hidden_dim)
        gru_out, _ = self.gru(x)
        # Take the final temporal state representation h_t
        h_t = gru_out[:, -1, :]
        h_t = self.norm(self.dropout(h_t))

        outputs: Dict[str, Any] = {
            'latent_h': h_t,
            'tau_pred': self.tau_head(h_t).squeeze(-1)
        }

        for k in self.horizons:
            outputs[f'binary_logits_k{k}'] = self.binary_heads[f'k{k}'](h_t).squeeze(-1)
            outputs[f'binary_probs_k{k}'] = torch.sigmoid(outputs[f'binary_logits_k{k}'])
            outputs[f'state_pred_k{k}'] = self.state_heads[f'k{k}'](h_t)
            outputs[f'family_logits_k{k}'] = self.family_heads[f'k{k}'](h_t)

        return outputs
