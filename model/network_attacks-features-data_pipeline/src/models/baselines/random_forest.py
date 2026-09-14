"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.baselines.random_forest

Baseline 2: Random Forest Non-Linear Sequence & Static Forecaster.
"""

from typing import Dict, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class RandomForestForecaster:
    """
    Random Forest baseline for multi-horizon attack presence forecasting.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 15,
        min_samples_split: int = 10,
        class_weight: Optional[str] = None,
        n_jobs: int = -1,
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.class_weight = class_weight
        self.n_jobs = n_jobs
        self.random_state = random_state

        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            class_weight=self.class_weight,
            n_jobs=self.n_jobs,
            random_state=self.random_state
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)
