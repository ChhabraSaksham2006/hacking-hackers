"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.transition

World Transition Model Architecture F_theta.
Maps combined world state r_t = [z^{cap}_t ; h_t] to the next predicted dense latent z_{t+1}^{pred}.
"""

import torch
import torch.nn as nn


class WorldTransitionModel(nn.Module):
    """
    World Transition Model F_theta.
    Predicts the next dense latent representation z_{t+1}^{pred} from the combined
    instantaneous sparse information z^{cap}_t and temporal memory h_t.
    """

    def __init__(
        self,
        latent_dim: int = 128,
        hidden_dim: int = 128,
        mlp_hidden_dim: int = 128,
        dropout: float = 0.1
    ):
        super().__init__()
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        self.world_state_dim = latent_dim + hidden_dim

        self.net = nn.Sequential(
            nn.Linear(self.world_state_dim, mlp_hidden_dim),
            nn.LayerNorm(mlp_hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(mlp_hidden_dim, mlp_hidden_dim),
            nn.LayerNorm(mlp_hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(mlp_hidden_dim, latent_dim)
        )

    def forward(self, r_t: torch.Tensor) -> torch.Tensor:
        """
        Args:
            r_t: Combined world state [z^{cap}_t ; h_t] of shape (..., latent_dim + hidden_dim)
        Returns:
            z_pred_next: Next dense latent tensor of shape (..., latent_dim)
        """
        assert r_t.shape[-1] == self.world_state_dim, (
            f"Expected world state dim {self.world_state_dim}, got {r_t.shape[-1]}"
        )
        z_pred_next = self.net(r_t)
        assert z_pred_next.shape[-1] == self.latent_dim, (
            f"Output latent dim MUST be {self.latent_dim}, got {z_pred_next.shape[-1]}"
        )
        return z_pred_next
