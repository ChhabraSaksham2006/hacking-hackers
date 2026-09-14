"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.models.heads

Forecasting & Risk Prediction Heads for Sparse RSSM.
Implements:
  1. MITREStageHead: 5-Class MITRE ATT&CK kill-chain stage classification.
     (0: Benign, 1: Recon, 2: Initial Access, 3: Lateral Movement/Execution, 4: DoS/DDoS).
  2. AttackRiskHead: Binary network attack occurrence / anomaly risk scoring.
  3. TauHead: Continuous onset lead-time timer regressor.
"""

from typing import Optional
import torch
import torch.nn as nn


class MITREStageHead(nn.Module):
    """
    5-Class MITRE ATT&CK Kill-Chain Stage Classifier.
    Predicts categorical probability distribution over:
      - 0: Benign Baseline
      - 1: Reconnaissance (PortScan, Network Discovery)
      - 2: Initial Access (Brute Force SSH/FTP/Web)
      - 3: Lateral Movement & Execution (Infiltration, XSS, SQLi, Botnet C2)
      - 4: Denial of Service (DoS Hulk, GoldenEye, Slowloris, LOIC, HOIC)
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        num_classes: int = 5,
        dropout: float = 0.1
    ):
        super().__init__()
        self.num_classes = num_classes
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, r: torch.Tensor) -> torch.Tensor:
        """
        Args:
            r: World state or latent representation (..., input_dim)
        Returns:
            logits: Unnormalized logits (..., 5)
        """
        return self.net(r)


class AttackRiskHead(nn.Module):
    """
    Binary Attack Occurrence & Risk Forecaster.
    Predicts probability P(attack = 1) at future forecast step.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        dropout: float = 0.1
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1)
        )

    def forward(self, r: torch.Tensor) -> torch.Tensor:
        """
        Args:
            r: World state or latent representation (..., input_dim)
        Returns:
            logit: Scalar logit for binary classification (..., 1)
        """
        return self.net(r)


class TauHead(nn.Module):
    """
    Time-to-Attack Onset Delay Regressor (tau in seconds, tau >= 0).
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        dropout: float = 0.1
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.ReLU()  # tau >= 0
        )

    def forward(self, r: torch.Tensor) -> torch.Tensor:
        """
        Args:
            r: World state or latent representation (..., input_dim)
        Returns:
            tau_pred: Predicted seconds to onset (..., 1)
        """
        return self.net(r)
