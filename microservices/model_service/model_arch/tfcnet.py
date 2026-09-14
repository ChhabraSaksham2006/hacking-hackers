"""
tfcnet.py
=========
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

TFCNet: Time-Frequency Convolutional Network with Inverted Transformer (iTransformer) Backbone.
Combines:
1. Temporal Domain Multi-Scale 1D Convolutions (captures micro-bursts & local rate transients)
2. Frequency Domain Spectral Fourier Transform (captures periodic beaconing, scanning frequencies)
3. Gated Time-Frequency Fusion Layer
4. Inverted Transformer (iTransformer) Backbone (cross-variate attention across 54 physical state metrics)
5. Multi-Task Heads: Future State Rollout (K=10, 54-D), Binary Occurrence (1-D), Threat Family (7-D)
"""

from __future__ import annotations
import math
import torch
from torch import nn
import torch.fft
from typing import Dict, List, Tuple, Optional, Any

STATE_DIM = 54
NUM_CLASSES = 7


class TemporalConvBranch(nn.Module):
    """
    Multi-Scale 1D Dilated Convolutional feature extractor in the time domain.
    Input:  [B, P, D] -> Transposed to [B, D, P]
    Output: [B, D, hidden_dim]
    """
    def __init__(self, seq_len: int = 10, hidden_dim: int = 128):
        super().__init__()
        self.seq_len = seq_len
        self.hidden_dim = hidden_dim

        # Multi-scale 1D convolutions (k=1, k=3, k=5)
        self.conv1 = nn.Conv1d(1, hidden_dim // 4, kernel_size=1, padding=0)
        self.conv3 = nn.Conv1d(1, hidden_dim // 4, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(1, hidden_dim // 4, kernel_size=5, padding=2)
        self.conv_dilated = nn.Conv1d(1, hidden_dim // 4, kernel_size=3, dilation=2, padding=2)

        self.proj = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [B, P, D] -> We treat each of the D variates independently through 1D convs.
        Shape transformation: [B, P, D] -> [B * D, 1, P]
        """
        B, P, D = x.shape
        x_reshaped = x.permute(0, 2, 1).contiguous().view(B * D, 1, P)  # [B*D, 1, P]

        c1 = self.conv1(x_reshaped)        # [B*D, hidden_dim//4, P]
        c3 = self.conv3(x_reshaped)        # [B*D, hidden_dim//4, P]
        c5 = self.conv5(x_reshaped)        # [B*D, hidden_dim//4, P]
        cd = self.conv_dilated(x_reshaped) # [B*D, hidden_dim//4, P]

        # Concatenate scale channels
        c_all = torch.cat([c1, c3, c5, cd], dim=1)  # [B*D, hidden_dim, P]
        c_pooled = c_all.mean(dim=-1)                 # [B*D, hidden_dim]
        c_out = self.proj(c_pooled).view(B, D, self.hidden_dim) # [B, D, hidden_dim]

        return c_out


class FrequencySpectralBranch(nn.Module):
    """
    Frequency-Domain Real-Valued FFT Feature Extractor.
    Captures cyclic beaconing, scanning frequencies, and periodic network rhythms.
    Input:  [B, P, D]
    Output: [B, D, hidden_dim]
    """
    def __init__(self, seq_len: int = 10, hidden_dim: int = 128):
        super().__init__()
        self.seq_len = seq_len
        self.hidden_dim = hidden_dim
        self.rfft_len = (seq_len // 2) + 1  # 6 for P=10

        # Complex weights for spectral filtering (real and imaginary components)
        self.weight_real = nn.Parameter(torch.randn(self.rfft_len, hidden_dim // 2) * 0.02)
        self.weight_imag = nn.Parameter(torch.randn(self.rfft_len, hidden_dim // 2) * 0.02)

        self.proj = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [B, P, D]
        """
        B, P, D = x.shape
        # Compute RFFT along temporal dimension P
        x_fft = torch.fft.rfft(x, dim=1)  # [B, rfft_len, D]
        x_real = x_fft.real.permute(0, 2, 1)  # [B, D, rfft_len]
        x_imag = x_fft.imag.permute(0, 2, 1)  # [B, D, rfft_len]

        # Spectral projection
        feat_real = torch.matmul(x_real, self.weight_real)  # [B, D, hidden_dim // 2]
        feat_imag = torch.matmul(x_imag, self.weight_imag)  # [B, D, hidden_dim // 2]

        spectral_feat = torch.cat([feat_real, feat_imag], dim=-1)  # [B, D, hidden_dim]
        return self.proj(spectral_feat)


class TimeFrequencyGatedFusion(nn.Module):
    """
    Gated Bilinear Fusion combining time-domain and frequency-domain variate embeddings.
    """
    def __init__(self, hidden_dim: int = 128):
        super().__init__()
        self.gate = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.Sigmoid()
        )
        self.linear = nn.Linear(hidden_dim * 2, hidden_dim)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, h_time: torch.Tensor, h_freq: torch.Tensor) -> torch.Tensor:
        """
        h_time: [B, D, hidden_dim]
        h_freq: [B, D, hidden_dim]
        """
        combined = torch.cat([h_time, h_freq], dim=-1)
        g = self.gate(combined)
        fused = g * h_time + (1.0 - g) * h_freq
        out = self.norm(self.linear(combined) + fused)
        return out


class InvertedTransformerLayer(nn.Module):
    """
    iTransformer Layer (Inverted Attention across the 54 physical metric variates).
    Each variate's full temporal history is an embedding token.
    """
    def __init__(self, hidden_dim: int = 128, n_heads: int = 4, ffn_dim: int = 256, dropout: float = 0.1):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(hidden_dim, n_heads, dropout=dropout, batch_first=True)
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.norm2 = nn.LayerNorm(hidden_dim)

        self.ffn = nn.Sequential(
            nn.Linear(hidden_dim, ffn_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim, hidden_dim),
            nn.Dropout(dropout)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [B, 54, hidden_dim]
        """
        norm_x = self.norm1(x)
        attn_out, _ = self.self_attn(norm_x, norm_x, norm_x)
        x = x + attn_out
        x = x + self.ffn(self.norm2(x))
        return x


class TFCNet(nn.Module):
    """
    TFCNet: Time-Frequency Convolutional Network with iTransformer Backbone for Network State Forecasting.
    Consumes [B, P=10, 54] history and forecasts:
    1. Multi-Step Future State Rollout [B, K=10, 54]
    2. Binary Attack Occurrence at t+10 [B, 1]
    3. Threat Family Multi-Class Logits at t+10 [B, 7]
    """
    def __init__(
        self,
        state_dim: int = STATE_DIM,
        seq_len: int = 10,
        forecast_horizon: int = 10,
        hidden_dim: int = 128,
        n_transformer_layers: int = 2,
        n_heads: int = 4,
        num_classes: int = NUM_CLASSES,
        dropout: float = 0.1
    ):
        super().__init__()
        self.state_dim = state_dim
        self.seq_len = seq_len
        self.forecast_horizon = forecast_horizon
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes

        # 1. Time Domain Branch
        self.time_branch = TemporalConvBranch(seq_len=seq_len, hidden_dim=hidden_dim)

        # 2. Frequency Domain Branch
        self.freq_branch = FrequencySpectralBranch(seq_len=seq_len, hidden_dim=hidden_dim)

        # 3. Gated Fusion Layer
        self.fusion = TimeFrequencyGatedFusion(hidden_dim=hidden_dim)

        # 4. Inverted Transformer Backbone (cross-variate attention across 54 physical features)
        self.transformer_layers = nn.ModuleList([
            InvertedTransformerLayer(hidden_dim=hidden_dim, n_heads=n_heads, ffn_dim=hidden_dim * 2, dropout=dropout)
            for _ in range(n_transformer_layers)
        ])
        self.final_norm = nn.LayerNorm(hidden_dim)

        # 5. Multi-Task Heads
        # A. State Rollout Predictor: Projects each of the 54 variate tokens to K=10 future continuous steps
        self.state_rollout_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, forecast_horizon)
        )

        # B. Binary Attack Occurrence Head: Global pooling over 54 variates -> 1-D logit
        self.attack_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1)
        )

        # C. Threat Family Multi-Class Head: Global pooling over 54 variates -> 7-D logits
        self.family_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def count_parameters(self) -> Dict[str, int]:
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {"total_parameters": total, "trainable_parameters": trainable}

    def forward(self, x: torch.Tensor, K: int = 10) -> Dict[str, Any]:
        """
        x: [B, P=10, D=54]
        Returns dict containing:
        - "states_tensor": [B, K, 54] future continuous state rollout
        - "attack_logits": list containing [B, 1] logit at horizon K
        - "family_logits": list containing [B, 7] logits at horizon K
        - "x_recon": [B, 54] reconstructed last observed state S_t
        """
        B, P, D = x.shape
        assert D == self.state_dim, f"Expected state_dim={self.state_dim}, got {D}"

        # 1. Extract Time and Frequency Embeddings
        h_time = self.time_branch(x)      # [B, 54, hidden_dim]
        h_freq = self.freq_branch(x)      # [B, 54, hidden_dim]

        # 2. Gated Fusion
        h_fused = self.fusion(h_time, h_freq)  # [B, 54, hidden_dim]

        # 3. Cross-Variate iTransformer Reasoning
        for layer in self.transformer_layers:
            h_fused = layer(h_fused)
        h_repr = self.final_norm(h_fused)      # [B, 54, hidden_dim]

        # 4. State Forecasting Head: [B, 54, hidden_dim] -> [B, 54, K] -> Transpose to [B, K, 54]
        future_states = self.state_rollout_head(h_repr)  # [B, 54, K]
        states_tensor = future_states.permute(0, 2, 1).contiguous()  # [B, K, 54]

        # 5. Global Threat Pooling across the 54 state variates
        h_global = h_repr.mean(dim=1)  # [B, hidden_dim]

        attack_logit_k10 = self.attack_head(h_global)   # [B, 1]
        family_logits_k10 = self.family_head(h_global)  # [B, 7]

        # Reconstructed last state S_t (approx from first forecast or direct mapping)
        x_recon = states_tensor[:, 0, :]

        return {
            "x_recon": x_recon,
            "states_tensor": states_tensor,             # [B, K, 54]
            "attack_logits": [attack_logit_k10],        # List matching SparseRSSM output interface
            "attack_logits_tensor": attack_logit_k10.unsqueeze(1),
            "family_logits": [family_logits_k10],       # List matching SparseRSSM output interface
            "family_logits_tensor": family_logits_k10.unsqueeze(1),
            "h_repr": h_repr
        }

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
        # 1. State Rollout MSE across all K=10 future steps
        pred_states_tensor = out["states_tensor"]  # [B, K, 54]
        state_rollout_loss = nn.functional.mse_loss(pred_states_tensor, targets_state)
        recon_loss = nn.functional.mse_loss(out["x_recon"], targets_state[:, 0, :])
        state_loss = state_rollout_loss

        # 2. Binary Attack Occurrence BCE at horizon k=10
        attack_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_attack_k10 is not None and lambda_attack > 0.0:
            bce_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
            pred_attack_logit = out["attack_logits"][-1].squeeze(-1)  # [B]
            attack_loss = bce_fn(pred_attack_logit, targets_attack_k10.float())

        # 3. Threat Family Multi-Class Cross Entropy at horizon k=10
        family_loss = torch.tensor(0.0, device=x_obs.device)
        if targets_family_k10 is not None and lambda_family > 0.0:
            ce_fn = nn.CrossEntropyLoss()
            pred_family_logit = out["family_logits"][-1]  # [B, 7]
            family_loss = ce_fn(pred_family_logit, targets_family_k10.long())

        total_loss = (lambda_state * state_loss) + (lambda_attack * attack_loss) + (lambda_family * family_loss)

        return total_loss, {
            "total_loss": float(total_loss.detach()),
            "recon_mse": float(recon_loss.detach()),
            "rollout_mse": float(state_rollout_loss.detach()),
            "attack_bce": float(attack_loss.detach()),
            "family_ce": float(family_loss.detach())
        }
