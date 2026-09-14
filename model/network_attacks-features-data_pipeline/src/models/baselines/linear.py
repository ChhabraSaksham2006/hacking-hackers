"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.baselines.linear

Baseline 1: Logistic Regression Forecasters.
Implements Static (S_t only) and Flattened Temporal ([S_{t-P+1}, ..., S_t]) variants
with natural distribution and class-weighted regularizations.
"""

from typing import Dict, Any, Optional
import numpy as np
from sklearn.linear_model import LogisticRegression


class LogisticRegressionForecaster:
    """
    Logistic Regression baseline for multi-horizon attack presence forecasting.
    """

    def __init__(
        self,
        class_weight: Optional[str] = None,
        C: float = 1.0,
        max_iter: int = 500,
        random_state: int = 42
    ):
        self.class_weight = class_weight
        self.C = C
        self.max_iter = max_iter
        self.random_state = random_state
        self.model = LogisticRegression(
            C=self.C,
            class_weight=self.class_weight,
            max_iter=self.max_iter,
            random_state=self.random_state,
            solver="lbfgs"
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        """
        Fits logistic regression on input features X and binary target y.
        """
        self.model.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)
