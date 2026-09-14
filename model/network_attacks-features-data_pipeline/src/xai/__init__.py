"""
Explainable AI (XAI) package for SIH26153 Network Attack Forecasting.
"""

from src.xai.integrated_gradients import compute_integrated_gradients, compute_temporal_saliency_map
from src.xai.feature_attribution import PrecursorAttributionEngine, FEATURE_GROUP_DEFINITIONS

__all__ = [
    "compute_integrated_gradients",
    "compute_temporal_saliency_map",
    "PrecursorAttributionEngine",
    "FEATURE_GROUP_DEFINITIONS"
]
