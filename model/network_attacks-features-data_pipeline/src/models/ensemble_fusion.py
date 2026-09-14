"""
ensemble_fusion.py
==================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Hybrid Deep Ensemble Fusion Forecaster:
Combines:
1. SparseRSSM: Recurrent state-space world model (latent memory dynamics & threat classification)
2. TFCNet: Time-Frequency Convolutional + Inverted Transformer (spectral beaconing & state trajectory)
3. Gated Cross-Model Bilinear Fusion Layer: Dynamically balances temporal memory and spectral features.
4. Trajectory-Gated Decision Calibration for ultra-low false alarms (< 10 FA/hr) and high onset recall.
"""

from __future__ import annotations
import os
import sys
import torch
from torch import nn
from typing import Dict, List, Tuple, Optional, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models.sparse_rssm import SparseRSSM
from src.models.tfcnet import TFCNet

STATE_DIM = 54
NUM_CLASSES = 7


class GatedEnsembleFusion(nn.Module):
    """
    Learns dynamic gating weights to fuse SparseRSSM and TFCNet representations.
    """
    def __init__(self, hidden_dim: int = 128, num_classes: int = NUM_CLASSES):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes

        # Gating network
        self.gate = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Sigmoid()
        )

        # State trajectory blending weight (per feature dimension)
        self.state_blend_weight = nn.Parameter(torch.ones(1, 1, STATE_DIM) * 0.5)

        # Fused multi-task heads
        self.fused_attack_head = nn.Sequential(
            nn.Linear(hidden_dim * 2 + 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, 1)
        )

        self.fused_family_head = nn.Sequential(
            nn.Linear(hidden_dim * 2 + (num_classes * 2), hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(
        self,
        rssm_out: Dict[str, Any],
        tfc_out: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        rssm_out: outputs from SparseRSSM
        tfc_out: outputs from TFCNet
        """
        # 1. State trajectory blending
        s_rssm = rssm_out["states_tensor"]  # [B, K, 54]
        s_tfc = tfc_out["states_tensor"]    # [B, K, 54]
        w_blend = torch.sigmoid(self.state_blend_weight)
        fused_states = (w_blend * s_tfc) + ((1.0 - w_blend) * s_rssm)

        # 2. Extract latent representations
        h_rssm = rssm_out["final_hidden"]       # [B, 128]
        h_tfc = tfc_out["h_repr"].mean(dim=1)    # [B, 128]

        # 3. Gated latent fusion
        concat_h = torch.cat([h_rssm, h_tfc], dim=-1)  # [B, 256]
        g = self.gate(concat_h)
        h_fused = g * h_rssm + (1.0 - g) * h_tfc

        # 4. Fused attack occurrence logit
        atk_rssm = rssm_out["attack_logits"][-1]  # [B, 1]
        atk_tfc = tfc_out["attack_logits"][-1]    # [B, 1]
        atk_in = torch.cat([concat_h, atk_rssm, atk_tfc], dim=-1)
        fused_attack_logit = self.fused_attack_head(atk_in)

        # 5. Fused threat family logits
        fam_rssm = rssm_out["family_logits"][-1]  # [B, 7]
        fam_tfc = tfc_out["family_logits"][-1]    # [B, 7]
        fam_in = torch.cat([concat_h, fam_rssm, fam_tfc], dim=-1)
        fused_family_logits = self.fused_family_head(fam_in)

        return {
            "x_recon": (rssm_out["x_recon"] + tfc_out["x_recon"]) * 0.5,
            "states_tensor": fused_states,
            "attack_logits": [fused_attack_logit],
            "attack_logits_tensor": fused_attack_logit.unsqueeze(1),
            "family_logits": [fused_family_logits],
            "family_logits_tensor": fused_family_logits.unsqueeze(1),
            "h_fused": h_fused
        }


class HybridEnsembleForecaster(nn.Module):
    """
    End-to-End Ensemble Pipeline wrapping SparseRSSM + TFCNet + Gated Fusion Head.
    """
    def __init__(
        self,
        rssm_model: SparseRSSM,
        tfc_model: TFCNet,
        freeze_backbones: bool = False
    ):
        super().__init__()
        self.rssm = rssm_model
        self.tfc = tfc_model
        self.fusion = GatedEnsembleFusion(hidden_dim=128, num_classes=NUM_CLASSES)

        if freeze_backbones:
            for p in self.rssm.parameters():
                p.requires_grad = False
            for p in self.tfc.parameters():
                p.requires_grad = False

    def forward(self, x: torch.Tensor, K: int = 10) -> Dict[str, Any]:
        rssm_out = self.rssm(x, K=K)
        tfc_out = self.tfc(x, K=K)
        fused_out = self.fusion(rssm_out, tfc_out)
        return fused_out

    def compute_loss(
        self,
        out: Dict[str, Any],
        x_obs: torch.Tensor,
        targets_state: torch.Tensor,
        targets_attack_k10: Optional[torch.Tensor] = None,
        targets_family_k10: Optional[torch.Tensor] = None,
        lambda_state: float = 1.0,
        lambda_attack: float = 1.2,
        lambda_family: float = 0.5,
        pos_weight: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        # 1. State Rollout MSE
        pred_states_tensor = out["states_tensor"]  # [B, K, 54]
        state_loss = nn.functional.mse_loss(pred_states_tensor, targets_state)

        # 2. Binary Occurrence BCE
        attack_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_attack_k10 is not None:
            bce_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
            pred_attack_logit = out["attack_logits"][-1].squeeze(-1)
            attack_loss = bce_fn(pred_attack_logit, targets_attack_k10.float())

        # 3. Threat Family CE
        family_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_family_k10 is not None:
            ce_fn = nn.CrossEntropyLoss()
            pred_fam_logit = out["family_logits"][-1]
            family_loss = ce_fn(pred_fam_logit, targets_family_k10.long())

        total_loss = (lambda_state * state_loss) + (lambda_attack * attack_loss) + (lambda_family * family_loss)

        return total_loss, {
            "total_loss": float(total_loss.detach()),
            "state_mse": float(state_loss.detach()),
            "attack_bce": float(attack_loss.detach()),
            "family_ce": float(family_loss.detach())
        }
