"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.baselines.transformer

Baseline 4: Lightweight Temporal Transformer Forecaster.
Processes sequential network state trajectories [S_{t-P+1}, ..., S_t]
using self-attention mechanisms to capture long-range temporal dependencies
and forecast multi-horizon attack occurrence, families, states, and onset delay.
"""

import math
from typing import Dict, List, Optional, Tuple, Any
import torch
import torch.nn as nn
import torch.nn.functional as F


class PositionalEncoding(nn.Module):
    """
    Standard sinusoidal positional encoding for short temporal sequences.
    """

    def __init__(self, d_model: int, max_len: int = 50, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # (1, max_len, d_model)
        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (B, P, d_model)
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)


class TemporalTransformerForecaster(nn.Module):
    """
    Lightweight Temporal Transformer for multi-horizon attack sequence forecasting.
    """

    def __init__(
        self,
        input_dim: int = 54,
        d_model: int = 128,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 256,
        dropout: float = 0.1,
        horizons: Optional[List[int]] = None,
        num_classes: int = 7
    ):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        self.horizons = horizons or [1, 3, 5, 10, 25, 50, 100, 200]
        self.num_classes = num_classes

        # Feature Projection & Positional Encoding
        self.input_proj = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model=d_model, max_len=50, dropout=dropout)

        # Transformer Encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            activation="gelu",
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(d_model)

        # Multi-Horizon Prediction Heads
        self.binary_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(d_model, 64),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(64, 1)
            )
            for k in self.horizons
        })

        self.state_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(d_model, 64),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(64, input_dim)
            )
            for k in self.horizons
        })

        self.family_heads = nn.ModuleDict({
            f"k{k}": nn.Sequential(
                nn.Linear(d_model, 64),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(64, num_classes)
            )
            for k in self.horizons
        })

        # Time-to-attack onset regressor
        self.tau_head = nn.Sequential(
            nn.Linear(d_model, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
            nn.ReLU()
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
        # Linear projection + Positional Encoding
        proj = self.input_proj(x)  # (B, P, d_model)
        enc_in = self.pos_encoder(proj)

        # Transformer Encoder
        enc_out = self.transformer_encoder(enc_in)  # (B, P, d_model)

        # Temporal Pooling: Attention weighted / mean pooling across temporal steps
        h_t = self.norm(enc_out.mean(dim=1))  # (B, d_model)

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
