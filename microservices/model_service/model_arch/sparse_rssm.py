"""
sparse_rssm.py
==============
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Canonical 54-Dimensional Sparse Recurrent State-Space World Model (SparseRSSM).
Supports:
- P=10 Vectorized Historical Context Encoding (54-D states)
- K=10 Multi-Step Autoregressive State Rollout in Latent Space
- Straight-Through Top-K Latent Sparsity Routing (or Dense when ratio=1.0)
- Multi-Task Prediction Heads: Future State Reconstruction, Binary Attack Occurrence, 7-Class Threat Family
"""

from __future__ import annotations
import torch
from torch import nn
from typing import Dict, List, Tuple, Optional, Any

STATE_DIM = 54
NUM_CLASSES = 7


class StraightThroughTopK(nn.Module):
    """
    Straight-Through Top-K Sparsity Operator:
    Hard Top-K selection in forward pass, dense gradient backpropagation.
    When ratio >= 1.0, acts as an exact identity (Dense Mode).
    """
    def __init__(self, ratio: float = 1.0):
        super().__init__()
        self.ratio = float(ratio)

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        if self.ratio >= 1.0:
            return z
        k = max(1, min(z.shape[-1], round(z.shape[-1] * self.ratio)))
        _, idx = z.abs().topk(k, dim=-1)
        hard = torch.zeros_like(z).scatter(-1, idx, z.gather(-1, idx))
        return z + (hard - z).detach()


class SparseRSSM(nn.Module):
    """
    Recurrent State-Space World Model for 54-D continuous network state telemetry.
    """
    def __init__(
        self,
        state_dim: int = STATE_DIM,
        latent_dim: int = 128,
        hidden_dim: int = 128,
        sparsity_ratio: float = 1.0,      # Default 1.0 (Dense canonical mode); <1.0 for sparse
        use_attention: bool = False,
        num_classes: int = NUM_CLASSES
    ):
        super().__init__()
        assert state_dim == STATE_DIM, f"Expected state_dim={STATE_DIM}, got {state_dim}"
        self.state_dim = state_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        self.sparsity_ratio = float(sparsity_ratio)
        self.use_attention = bool(use_attention)
        self.num_classes = num_classes

        # 1. State Encoder (Observation Model: S_t -> z_t)
        self.encoder = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, latent_dim)
        )

        # 2. State Decoder (Reconstruction / Emission Model: z_t -> S_t)
        self.state_decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, state_dim)
        )

        # 3. Optional Latent Self-Attention
        self.attention = nn.MultiheadAttention(latent_dim, 4, batch_first=True) if use_attention else None

        # 4. Straight-Through Top-K Sparsifier
        self.topk = StraightThroughTopK(self.sparsity_ratio)

        # 5. Fast Recurrent Transition Memory (GRUCell)
        self.gru = nn.GRUCell(latent_dim, hidden_dim)

        # 6. Latent State-Space Transition Dynamic Model: (z_t, h_t) -> z_{t+1}
        self.transition = nn.Sequential(
            nn.Linear(latent_dim + hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, latent_dim)
        )

        # 7. Threat Family Multi-Class Classification Head: (z_t, h_t) -> class_logits (7-D)
        self.family_head = nn.Linear(latent_dim + hidden_dim, num_classes)

        # 8. Binary Attack Occurrence Forecasting Head: (z_t, h_t) -> attack_logit (1-D)
        self.attack_head = nn.Linear(latent_dim + hidden_dim, 1)

    @property
    def stage_head(self) -> nn.Linear:
        """Alias for backward compatibility."""
        return self.family_head

    def _sparsify(self, z: torch.Tensor) -> torch.Tensor:
        if self.attention is not None:
            if z.ndim == 2:
                z_att, _ = self.attention(z.unsqueeze(1), z.unsqueeze(1), z.unsqueeze(1))
                z = z_att.squeeze(1)
            else:
                z, _ = self.attention(z, z, z)
        return self.topk(z)

    def count_parameters(self) -> Dict[str, int]:
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {"total_parameters": total, "trainable_parameters": trainable}

    def rollout(
        self,
        x: torch.Tensor,
        K: int = 10,
        hidden: Optional[torch.Tensor] = None
    ) -> Dict[str, Any]:
        """
        Consumes history sequence x (B x P x 54) and rolls forward K steps in latent state-space.
        """
        assert x.shape[-1] == self.state_dim
        B = x.shape[0]
        if x.ndim == 2:
            x = x.unsqueeze(1)

        # 1. Vectorized observation encoding across all lookback steps P
        z_all = self.encoder(x)            # [B, P, latent_dim]
        z_cap_all = self._sparsify(z_all)  # [B, P, latent_dim]

        h = torch.zeros(B, self.hidden_dim, device=x.device) if hidden is None else hidden
        
        # Fast GRU unrolling across lookback steps
        P_steps = z_cap_all.shape[1]
        for i in range(P_steps):
            h = self.gru(z_cap_all[:, i, :], h)

        # Reconstruct last observed state S_t
        z_last = z_all[:, -1, :]
        x_recon = self.state_decoder(z_last)
        z_cap = z_cap_all[:, -1, :]

        # 2. Roll forward K steps autoregressively
        states, latents, sparse_latents, hidden_states, families, attacks = [], [], [], [], [], []
        for _ in range(K):
            r = torch.cat([z_cap, h], dim=-1)
            z = self.transition(r)
            x_pred = self.state_decoder(z)
            
            states.append(x_pred)
            latents.append(z)
            families.append(self.family_head(r))
            attacks.append(self.attack_head(r))

            z_cap = self._sparsify(z)
            h = self.gru(z_cap, h)
            sparse_latents.append(z_cap)
            hidden_states.append(h)

        return {
            "x_recon": x_recon,
            "states": states,                             # List of K tensors [B, 54]
            "states_tensor": torch.stack(states, dim=1),  # [B, K, 54]
            "latents": latents,
            "sparse": sparse_latents,
            "hidden": hidden_states,
            "family_logits": families,                    # List of K tensors [B, 7]
            "family_logits_tensor": torch.stack(families, dim=1), # [B, K, 7]
            "attack_logits": attacks,                     # List of K tensors [B, 1]
            "attack_logits_tensor": torch.stack(attacks, dim=1),   # [B, K, 1]
            "final_hidden": h
        }

    def forward(self, x: torch.Tensor, K: int = 10, hidden: Optional[torch.Tensor] = None) -> Dict[str, Any]:
        return self.rollout(x, K=K, hidden=hidden)

    def compute_loss(
        self,
        out: Dict[str, Any],
        x_obs: torch.Tensor,
        targets_state: torch.Tensor,
        targets_attack_k10: Optional[torch.Tensor] = None,
        targets_family_k10: Optional[torch.Tensor] = None,
        lambda_state: float = 1.0,
        lambda_attack: float = 1.0,
        lambda_family: float = 0.5,
        pos_weight: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """
        Multi-task loss computation:
        L_total = lambda_state * L_state + lambda_attack * L_attack + lambda_family * L_family
        """
        # 1. State Loss: Reconstruction of S_t + Multi-step Rollout MSE
        recon_loss = nn.functional.mse_loss(out["x_recon"], x_obs[:, -1, :])
        pred_states_tensor = out["states_tensor"]  # [B, K, 54]
        state_rollout_loss = nn.functional.mse_loss(pred_states_tensor, targets_state)
        state_loss = recon_loss + state_rollout_loss

        # 2. Binary Attack Occurrence Loss at horizon k=10
        attack_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_attack_k10 is not None and lambda_attack > 0.0:
            bce_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
            pred_attack_k10_logit = out["attack_logits"][-1].squeeze(-1)  # [B]
            attack_loss = bce_fn(pred_attack_k10_logit, targets_attack_k10.float())

        # 3. Threat Family Multi-Class Loss at horizon k=10
        family_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_family_k10 is not None and lambda_family > 0.0:
            ce_fn = nn.CrossEntropyLoss()
            pred_family_k10_logit = out["family_logits"][-1]  # [B, 7]
            family_loss = ce_fn(pred_family_k10_logit, targets_family_k10.long())

        total_loss = (lambda_state * state_loss) + (lambda_attack * attack_loss) + (lambda_family * family_loss)

        return total_loss, {
            "total_loss": float(total_loss.detach()),
            "recon_mse": float(recon_loss.detach()),
            "rollout_mse": float(state_rollout_loss.detach()),
            "attack_bce": float(attack_loss.detach()),
            "family_ce": float(family_loss.detach())
        }
