"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.decoders

Shared State Decoder Architecture.
Strict Requirements:
  - Canonical state dimension: EXACTLY 54.
  - Exactly ONE StateDecoder module used for BOTH:
      1. Current state reconstruction: x_recon_t = StateDecoder(z_t)
      2. Future state prediction: x_pred_{t+k} = StateDecoder(z_{t+k}^{pred})
  - Reconstructs and predicts from the DENSE latent BEFORE Top-K sparsification.
"""

import torch
import torch.nn as nn


class StateDecoder(nn.Module):
    """
    Shared 54-Dimensional Continuous State Decoder D_psi.
    Decodes dense latent representations into physical network state telemetry.
    """

    def __init__(
        self,
        latent_dim: int = 128,
        hidden_dim: int = 128,
        state_dim: int = 54
    ):
        super().__init__()
        assert state_dim == 54, f"StateDecoder MUST have state_dim=54, got {state_dim}"
        self.state_dim = state_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim

        self.net = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, state_dim)
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: Dense latent tensor of shape (..., latent_dim)
        Returns:
            x_hat: Reconstructed or predicted state tensor of shape (..., 54)
        """
        assert z.shape[-1] == self.latent_dim, (
            f"Expected latent_dim {self.latent_dim}, got {z.shape[-1]}"
        )
        x_hat = self.net(z)
        assert x_hat.shape[-1] == 54, f"Output state dimension MUST be 54, got {x_hat.shape[-1]}"
        return x_hat
