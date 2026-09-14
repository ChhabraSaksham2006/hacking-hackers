"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.baselines.persistence

Baseline 0: Persistence and Majority Class Reference Forecasters.
Provides empirical lower bounds on multi-horizon attack predictability.
"""

from typing import Dict, Any, Optional
import numpy as np


class MajorityForecaster:
    """
    Predicts the majority class (Benign, y = 0) unconditionally.
    """

    def fit(self, X: np.ndarray, y: np.ndarray):
        pass

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        probs = np.zeros((n, 2), dtype=np.float32)
        probs[:, 0] = 1.0  # Benign = 100%
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.zeros(len(X), dtype=np.int64)


class PersistenceForecaster:
    """
    Persistence Forecaster: Assumes future attack presence y_{t+K} equals current state y_t.
    """

    def fit(self, X: np.ndarray, y: np.ndarray):
        pass

    def predict_proba(self, X: np.ndarray, current_is_attack: np.ndarray) -> np.ndarray:
        n = len(X)
        probs = np.zeros((n, 2), dtype=np.float32)
        probs[:, 1] = current_is_attack.astype(np.float32)
        probs[:, 0] = 1.0 - probs[:, 1]
        return probs

    def predict(self, X: np.ndarray, current_is_attack: np.ndarray) -> np.ndarray:
        return current_is_attack.astype(np.int64)
