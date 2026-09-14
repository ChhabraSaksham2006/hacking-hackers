"""
World Model Architecture Module

Implements the Dual-Head Sequence World Model:
  - Backbone: Multi-layer LSTM / GRU / Transformer sequence encoder
  - Head 1: Future System State Forecaster (Predicts S_{t+K} in continuous feature space via MSE)
  - Head 2: Future MITRE Attack Stage Classifier (Predicts Y_{t+K} categorical distribution via Cross-Entropy)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Dict, Any


class LSTMWorldModel(nn.Module):
    """
    Recurrent World Model with dual forecasting heads.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_classes: int = 5,
        dropout: float = 0.2
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_classes = num_classes

        # Input feature projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        # Recurrent sequence encoder
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        # Latent representation layer
        self.latent_norm = nn.LayerNorm(hidden_dim)

        # Head 1: Future Network State Forecaster S_{t+K} in R^D
        self.state_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, input_dim)
        )

        # Head 2: Future MITRE Attack Stage Forecaster Y_{t+K} in {0..4}
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x: Input sequence [batch_size, lookback_P, input_dim]
        Returns:
            pred_state: [batch_size, input_dim]
            pred_stage_logits: [batch_size, num_classes]
            latent_h: [batch_size, hidden_dim]
        """
        # x: [B, P, D] -> [B, P, H]
        proj = self.input_proj(x)

        # lstm_out: [B, P, H], (h_n, c_n)
        lstm_out, _ = self.lstm(proj)

        # Take last time step as summary of sequence: h_t in [B, H]
        latent_h = self.latent_norm(lstm_out[:, -1, :])

        # Dual head predictions
        pred_state = self.state_head(latent_h)           # [B, D]
        pred_stage_logits = self.stage_head(latent_h)   # [B, num_classes]

        return pred_state, pred_stage_logits, latent_h


class TransformerWorldModel(nn.Module):
    """
    Transformer-based World Model with Self-Attention sequence backbone.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 2,
        num_classes: int = 5,
        dropout: float = 0.1,
        max_seq_len: int = 50
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.pos_embedding = nn.Parameter(torch.zeros(1, max_seq_len, hidden_dim))

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim * 2,
            dropout=dropout,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(hidden_dim)

        # Forecasting heads
        self.state_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim)
        )
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        B, P, D = x.shape
        proj = self.input_proj(x) + self.pos_embedding[:, :P, :]
        encoded = self.transformer_encoder(proj)
        latent_h = self.norm(encoded[:, -1, :])

        pred_state = self.state_head(latent_h)
        pred_stage_logits = self.stage_head(latent_h)
        return pred_state, pred_stage_logits, latent_h


def compute_world_model_loss(
    pred_state: torch.Tensor,
    target_state: torch.Tensor,
    pred_stage_logits: torch.Tensor,
    target_stage: torch.Tensor,
    class_weights: torch.Tensor,
    state_loss_weight: float = 0.5
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """
    Computes joint Multi-Task Loss:
      L = L_{stage_cross_entropy} + lambda * L_{state_mse}
    """
    # 1. State forecasting MSE loss
    loss_state = F.mse_loss(pred_state, target_state)

    # 2. Stage classification Cross-Entropy loss with class weights
    loss_stage = F.cross_entropy(pred_stage_logits, target_stage, weight=class_weights)

    # 3. Total multi-task loss
    total_loss = loss_stage + (state_loss_weight * loss_state)

    return total_loss, loss_stage, loss_state
