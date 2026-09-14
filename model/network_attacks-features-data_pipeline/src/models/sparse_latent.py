"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.sparse_latent

Top-K Sparse Latent Routing & Optional Lightweight Feature Attention.
Implements:
  1. TopKSparseLatent: Straight-through gradient-preserving Top-K sparsification.
     Supports exact sparsity levels: 5%, 10%, 25%, 50%, 100% (dense control).
  2. LightweightLatentAttention: Optional non-GNN feature interaction mechanism
     operating on latent representations.
"""

from typing import Dict, List, Optional, Tuple, Any
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class TopKSparseLatent(nn.Module):
    """
    Straight-Through Top-K Sparse Latent Routing Module.

    Forward:
      Computes hard Top-K mask based on absolute magnitude |z_t| and zeros out
      all coordinates outside the top-K.
      Active dimension count: k = max(1, round(sparsity_ratio * latent_dim)).
      For sparsity_ratio == 1.0 (100%), acts as an identity (dense control).

    Backward:
      Straight-Through Estimator (STE):
        z_cap = z + (z_hard - z).detach()
      Ensures gradients flow directly back to the encoder without degradation.
    """

    def __init__(self, latent_dim: int = 128, sparsity_ratio: float = 0.10):
        super().__init__()
        self.latent_dim = int(latent_dim)
        self.sparsity_ratio = float(sparsity_ratio)

        if not (0.0 < self.sparsity_ratio <= 1.0):
            raise ValueError(f"sparsity_ratio must be in (0.0, 1.0], got {sparsity_ratio}")

        if self.sparsity_ratio >= 1.0:
            self.k = self.latent_dim
            self.is_dense = True
        else:
            self.k = max(1, int(round(self.sparsity_ratio * self.latent_dim)))
            self.is_dense = False

        # Register buffer for tracking active coordinates statistics
        self.register_buffer("last_active_mask", torch.zeros(self.latent_dim))
        self.register_buffer("activation_frequency", torch.zeros(self.latent_dim))
        self.total_forward_calls = 0

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: Dense latent tensor of shape (..., latent_dim)
        Returns:
            z_cap: Sparse latent tensor of same shape with straight-through gradients.
        """
        assert z.shape[-1] == self.latent_dim, (
            f"Expected latent dimension {self.latent_dim}, got {z.shape[-1]}"
        )

        if self.is_dense:
            return z

        # 1. Identify top-k coordinates by magnitude
        abs_z = torch.abs(z)
        _, topk_indices = torch.topk(abs_z, k=self.k, dim=-1, largest=True, sorted=False)

        # 2. Build hard binary mask
        mask = torch.zeros_like(z)
        mask.scatter_(dim=-1, index=topk_indices, value=1.0)

        # 3. Hard sparsification
        z_hard = z * mask

        # 4. Straight-Through Estimator: forward uses z_hard, backward passes dL/dz directly
        z_cap = z + (z_hard - z).detach()

        # Update diagnostic tracking (detached)
        if self.training:
            with torch.no_grad():
                flat_mask = mask.view(-1, self.latent_dim)
                mean_mask = flat_mask.mean(dim=0)
                self.last_active_mask.copy_(mean_mask)
                self.activation_frequency.add_(mean_mask)
                self.total_forward_calls += 1

        return z_cap

    def get_sparsity_diagnostics(self) -> Dict[str, Any]:
        """Returns diagnostic metadata about active coordinates and sparsity."""
        freq = self.activation_frequency.cpu().numpy()
        denom = max(1, self.total_forward_calls)
        normalized_freq = freq / denom

        return {
            "latent_dim": self.latent_dim,
            "sparsity_ratio": self.sparsity_ratio,
            "active_k": self.k,
            "is_dense": self.is_dense,
            "mean_activation_freq": float(normalized_freq.mean()),
            "std_activation_freq": float(normalized_freq.std()),
            "active_indices_last_step": (self.last_active_mask > 0).nonzero().squeeze(-1).tolist()
        }


class LightweightLatentAttention(nn.Module):
    """
    Lightweight Feature Interaction Attention mechanism for latent representations.
    Partitions the latent vector into sub-vectors (tokens), performs multi-head
    self-attention to model cross-feature correlations, and applies residual LayerNorm.
    Strictly non-GNN.
    """

    def __init__(
        self,
        latent_dim: int = 128,
        num_heads: int = 4,
        num_tokens: int = 8,
        dropout: float = 0.05
    ):
        super().__init__()
        self.latent_dim = latent_dim
        self.num_tokens = num_tokens
        assert latent_dim % num_tokens == 0, (
            f"latent_dim ({latent_dim}) must be divisible by num_tokens ({num_tokens})"
        )
        self.token_dim = latent_dim // num_tokens
        assert self.token_dim % num_heads == 0, (
            f"token_dim ({self.token_dim}) must be divisible by num_heads ({num_heads})"
        )

        self.norm1 = nn.LayerNorm(latent_dim)
        self.mha = nn.MultiheadAttention(
            embed_dim=self.token_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True
        )
        self.norm2 = nn.LayerNorm(latent_dim)
        self.ffn = nn.Sequential(
            nn.Linear(latent_dim, latent_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(latent_dim, latent_dim)
        )

        self.last_attention_weights: Optional[torch.Tensor] = None

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: Latent tensor (B, latent_dim)
        Returns:
            z_att: Attention-refined latent tensor (B, latent_dim)
        """
        orig_shape = z.shape
        flat_z = z.view(-1, self.latent_dim)
        B = flat_z.size(0)

        # Reshape into tokens: (B, num_tokens, token_dim)
        norm_z = self.norm1(flat_z)
        tokens = norm_z.view(B, self.num_tokens, self.token_dim)

        # Multi-Head Attention across tokens
        attn_out, attn_weights = self.mha(tokens, tokens, tokens, need_weights=True)
        if not self.training:
            self.last_attention_weights = attn_weights.detach().cpu()

        attn_out = attn_out.contiguous().view(B, self.latent_dim)
        x = flat_z + attn_out

        # FFN with residual connection
        x = x + self.ffn(self.norm2(x))

        return x.view(*orig_shape)
