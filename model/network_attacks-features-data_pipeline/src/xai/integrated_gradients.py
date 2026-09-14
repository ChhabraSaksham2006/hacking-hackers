"""
integrated_gradients.py
=======================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Implements path-integrated gradients and temporal saliency attribution
for multi-horizon world models (SparseRSSM) and spectral forecasters (TFCNet).
"""

from __future__ import annotations
import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any, Callable


def compute_integrated_gradients(
    model_fn: Callable[[torch.Tensor], torch.Tensor],
    input_tensor: torch.Tensor,
    baseline_tensor: Optional[torch.Tensor] = None,
    target_idx: Optional[int] = None,
    steps: int = 50,
    device: str = "cpu"
) -> np.ndarray:
    """
    Computes path-integrated gradients attribution for an input sequence.
    
    Args:
        model_fn: Callable mapping (B, P, D) -> (B, Output_dim) or (B, 1).
        input_tensor: Input tensor of shape (1, P, D) or (P, D).
        baseline_tensor: Baseline reference tensor of same shape (defaults to zeros).
        target_idx: Target output index (if multi-output).
        steps: Number of Riemann interpolation steps along path.
        device: PyTorch device ('cpu' or 'cuda').
        
    Returns:
        attributions: np.ndarray of shape (P, D) containing signed importance scores.
    """
    if input_tensor.dim() == 2:
        input_tensor = input_tensor.unsqueeze(0)  # (1, P, D)
        
    input_tensor = input_tensor.to(device).float()
    
    if baseline_tensor is None:
        baseline_tensor = torch.zeros_like(input_tensor)
    else:
        if baseline_tensor.dim() == 2:
            baseline_tensor = baseline_tensor.unsqueeze(0)
        baseline_tensor = baseline_tensor.to(device).float()

    # Create interpolated points along straight-line path: x' = x_0 + alpha * (x - x_0)
    alphas = torch.linspace(0.0, 1.0, steps + 1, device=device)
    
    # Accumulate gradients
    total_grads = torch.zeros_like(input_tensor)
    
    for alpha in alphas:
        interpolated = baseline_tensor + alpha * (input_tensor - baseline_tensor)
        interpolated.requires_grad_(True)
        
        output = model_fn(interpolated)
        if target_idx is not None and output.dim() > 1 and output.shape[-1] > 1:
            target_val = output[:, target_idx].sum()
        else:
            target_val = output.sum()
            
        target_val.backward()
        
        if interpolated.grad is not None:
            total_grads += interpolated.grad.detach()
            
    # Riemann sum approximation
    avg_grads = total_grads / (steps + 1)
    attributions = (input_tensor - baseline_tensor) * avg_grads
    
    return attributions.squeeze(0).cpu().numpy()


def compute_temporal_saliency_map(
    attributions: np.ndarray
) -> Dict[str, Any]:
    """
    Computes temporal saliency metrics across history steps P.
    
    Args:
        attributions: (P, D) array of feature attributions.
        
    Returns:
        Dictionary with per-step saliency and temporal decay rate.
    """
    p_steps, d_feats = attributions.shape
    step_saliency = np.sum(np.abs(attributions), axis=1)  # (P,)
    total_sal = max(1e-8, float(np.sum(step_saliency)))
    normalized_step_saliency = (step_saliency / total_sal).tolist()
    
    # Recent vs older history split (last 3 steps vs prior steps)
    recent_weight = float(np.sum(step_saliency[-3:]) / total_sal)
    
    return {
        "temporal_saliency_per_step": normalized_step_saliency,
        "recent_window_importance_pct": round(recent_weight * 100.0, 2),
        "peak_saliency_step": int(np.argmax(step_saliency))
    }
