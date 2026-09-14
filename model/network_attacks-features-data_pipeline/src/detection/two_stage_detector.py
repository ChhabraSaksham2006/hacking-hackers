"""
two_stage_detector.py
======================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Two-Stage Early-Warning + Confirmation Architecture with Temporal Incident Aggregation:
- Stage 1: Sensitive Early-Warning Detector (High-Recall precursor risk detection)
- Stage 2: Confirmation / Precision Filter (State divergence, momentum, threat specificity)
- Stage 3: Temporal Incident Aggregator (Incident clustering & false alarm suppression)
- SOC Alert Generator (Risk Score, MITRE Candidate, Delta-State Evidence)
"""

from __future__ import annotations
import os
import sys
import numpy as np
import pandas as pd
import torch
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Union

MITRE_7_ONTOLOGY = {
    0: {"name": "Benign", "technique": "None", "tactic": "Normal Operations"},
    1: {"name": "DoS", "technique": "T1498", "tactic": "Impact (Network Denial of Service)"},
    2: {"name": "DDoS", "technique": "T1499", "tactic": "Impact (Endpoint Denial of Service)"},
    3: {"name": "BruteForce", "technique": "T1110", "tactic": "Credential Access (Brute Force)"},
    4: {"name": "WebAttack", "technique": "T1190", "tactic": "Initial Access (Exploit Public-Facing Application)"},
    5: {"name": "Infiltration", "technique": "T1071", "tactic": "Command and Control (Standard Application Layer Protocol)"},
    6: {"name": "Botnet", "technique": "T1584", "tactic": "Resource Development (Compromise Infrastructure: Botnet)"}
}


@dataclass
class SOCAlert:
    """
    Standardized SOC Incident Alert structure.
    """
    incident_id: str
    start_window_idx: int
    start_time_seconds: float
    duration_seconds: float
    peak_risk_score: float
    confirmed_windows_count: int
    predicted_family_idx: int
    predicted_family_name: str
    mitre_tactic: str
    mitre_technique: str
    delta_state_evidence: Dict[str, float]
    is_precursor_alert: bool
    lead_time_seconds: float = 0.0


@dataclass
class TwoStageConfig:
    """
    Calibration parameters for the Two-Stage Detection Engine.
    """
    # Stage 1: Sensitive Early-Warning
    tau_warn: float = 0.30              # Minimum risk probability to flag candidate
    tau_precursor: float = 0.15         # Precursor sensitivity threshold
    slope_threshold: float = 0.05       # Trajectory positive momentum threshold
    
    # Stage 2: Confirmation Gate
    tau_confirm_high: float = 0.70      # Direct high-confidence confirmation threshold
    tau_confirm_dynamic: float = 0.35   # Dynamic trajectory confirmation threshold
    state_divergence_pct: float = 65.0  # Percentile threshold for ||S_{t+10} - S_t||
    velocity_norm_pct: float = 65.0     # Percentile threshold for delta feature velocity
    persistence_windows: int = 2        # Consecutive windows required for persistence
    min_threat_confidence: float = 0.20 # Minimum non-benign threat probability
    
    # Stage 3: Temporal Incident Aggregation
    cooldown_windows: int = 10          # 10 windows = 20.0s cooldown for clustering
    max_incident_gap_windows: int = 5   # Max gap between confirmed alerts in same incident


class TwoStageDetectionEngine:
    """
    Two-Stage Early-Warning + Confirmation Architecture with Temporal Incident Aggregator.
    """
    def __init__(
        self,
        config: Optional[TwoStageConfig] = None,
        feature_names: Optional[List[str]] = None
    ):
        self.cfg = config or TwoStageConfig()
        self.feature_names = feature_names or [f"feat_{i}" for i in range(54)]
        self.calibrated_state_divergence_threshold = 1.0
        self.calibrated_velocity_norm_threshold = 0.5

    def fit_thresholds_on_validation(
        self,
        val_probs: np.ndarray,
        val_pred_states: np.ndarray,
        val_obs_lasts: np.ndarray,
        val_true_binary: np.ndarray,
        val_manifest: pd.DataFrame
    ):
        """
        Calibrates physical deviation percentiles strictly on Validation data to prevent test leakage.
        """
        phys_deltas = np.linalg.norm(val_pred_states[:, -1, :] - val_obs_lasts, axis=-1)
        self.calibrated_state_divergence_threshold = float(np.percentile(phys_deltas, self.cfg.state_divergence_pct))
        
        # Velocity features are dimensions 37:54
        if val_pred_states.shape[-1] >= 54:
            vel_deltas = np.linalg.norm(val_pred_states[:, -1, 37:54], axis=-1)
            self.calibrated_velocity_norm_threshold = float(np.percentile(vel_deltas, self.cfg.velocity_norm_pct))
        else:
            self.calibrated_velocity_norm_threshold = 0.5

    def run_detection(
        self,
        probs: np.ndarray,
        pred_states: np.ndarray,
        obs_lasts: np.ndarray,
        threat_logits: Optional[np.ndarray] = None,
        manifest_df: Optional[pd.DataFrame] = None
    ) -> Dict[str, Any]:
        """
        Executes Stage 1, Stage 2, and Stage 3 across a sequence of windows.
        Returns window-level decisions and aggregated incident alerts.
        """
        N = len(probs)
        stage1_candidates = np.zeros(N, dtype=bool)
        stage2_confirmed = np.zeros(N, dtype=bool)
        
        # Compute trajectory momentum (slope)
        slopes = np.zeros(N, dtype=np.float32)
        slopes[1:] = np.maximum(0.0, probs[1:] - probs[:-1])
        
        # Compute state trajectory physical divergence
        state_divergence = np.linalg.norm(pred_states[:, -1, :] - obs_lasts, axis=-1)
        velocity_norm = np.linalg.norm(pred_states[:, -1, 37:54], axis=-1) if pred_states.shape[-1] >= 54 else np.zeros(N)
        
        # Compute threat softmax probabilities if available
        if threat_logits is not None:
            exp_logits = np.exp(threat_logits - np.max(threat_logits, axis=-1, keepdims=True))
            threat_probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
            non_benign_threat_conf = np.max(threat_probs[:, 1:], axis=-1) if threat_probs.shape[-1] > 1 else np.zeros(N)
            pred_threat_classes = np.argmax(threat_logits, axis=-1)
        else:
            threat_probs = np.zeros((N, 7))
            non_benign_threat_conf = np.zeros(N)
            pred_threat_classes = np.zeros(N, dtype=int)

        # -------------------------------------------------------------
        # STAGE 1: Sensitive Early-Warning Detector (High Recall)
        # -------------------------------------------------------------
        stage1_candidates = (probs >= self.cfg.tau_warn) | (
            (slopes >= self.cfg.slope_threshold) & (probs >= self.cfg.tau_precursor)
        )

        # -------------------------------------------------------------
        # STAGE 2: Confirmation / Precision Filter (Low FA/hr)
        # -------------------------------------------------------------
        cond_high = (probs >= self.cfg.tau_confirm_high)
        cond_dyn = (probs >= self.cfg.tau_confirm_dynamic) & (
            (state_divergence >= self.calibrated_state_divergence_threshold) |
            (velocity_norm >= self.calibrated_velocity_norm_threshold) |
            (non_benign_threat_conf >= self.cfg.min_threat_confidence)
        )
        cond_precursor = (slopes >= self.cfg.slope_threshold) & (probs >= self.cfg.tau_precursor) & (
            state_divergence >= (0.80 * self.calibrated_state_divergence_threshold)
        )
        
        stage2_confirmed = stage1_candidates & (cond_high | cond_dyn | cond_precursor)

        # -------------------------------------------------------------
        # STAGE 3: Temporal Incident Aggregation
        # -------------------------------------------------------------
        soc_alerts: List[SOCAlert] = []
        in_incident = False
        incident_start_idx = 0
        incident_last_alert_idx = 0
        current_peak_risk = 0.0
        current_confirmed_count = 0
        current_threat_classes = []
        
        for t in range(N):
            if stage2_confirmed[t]:
                if not in_incident:
                    # Start new incident
                    in_incident = True
                    incident_start_idx = t
                    incident_last_alert_idx = t
                    current_peak_risk = float(probs[t])
                    current_confirmed_count = 1
                    current_threat_classes = [pred_threat_classes[t]]
                else:
                    # Continue existing incident
                    incident_last_alert_idx = t
                    current_peak_risk = max(current_peak_risk, float(probs[t]))
                    current_confirmed_count += 1
                    current_threat_classes.append(pred_threat_classes[t])
            else:
                if in_incident:
                    # Check gap from last confirmed alert
                    if (t - incident_last_alert_idx) > self.cfg.max_incident_gap_windows:
                        # Close incident and emit SOC Alert
                        fam_counts = np.bincount(current_threat_classes, minlength=7)
                        if np.sum(fam_counts[1:]) > 0:
                            top_fam = int(np.argmax(fam_counts[1:]) + 1)
                        else:
                            top_fam = int(np.argmax(fam_counts))
                        
                        top_fam_info = MITRE_7_ONTOLOGY.get(top_fam, MITRE_7_ONTOLOGY[0])
                        
                        # Compute top physical delta features
                        mean_state_pred = np.mean(pred_states[incident_start_idx:incident_last_alert_idx+1, -1, :], axis=0)
                        mean_obs = np.mean(obs_lasts[incident_start_idx:incident_last_alert_idx+1], axis=0)
                        feature_diffs = np.abs(mean_state_pred - mean_obs)
                        top_indices = np.argsort(feature_diffs)[::-1][:5]
                        
                        evidence = {
                            self.feature_names[idx]: round(float(feature_diffs[idx]), 4)
                            for idx in top_indices
                        }
                        
                        alert = SOCAlert(
                            incident_id=f"INC-{incident_start_idx:06d}",
                            start_window_idx=incident_start_idx,
                            start_time_seconds=incident_start_idx * 2.0,
                            duration_seconds=(incident_last_alert_idx - incident_start_idx + 1) * 2.0,
                            peak_risk_score=round(current_peak_risk, 4),
                            confirmed_windows_count=current_confirmed_count,
                            predicted_family_idx=top_fam,
                            predicted_family_name=top_fam_info["name"],
                            mitre_tactic=top_fam_info["tactic"],
                            mitre_technique=top_fam_info["technique"],
                            delta_state_evidence=evidence,
                            is_precursor_alert=False
                        )
                        soc_alerts.append(alert)
                        in_incident = False

        # Close open incident at end of sequence
        if in_incident:
            fam_counts = np.bincount(current_threat_classes, minlength=7)
            top_fam = int(np.argmax(fam_counts[1:]) + 1) if np.sum(fam_counts[1:]) > 0 else int(np.argmax(fam_counts))
            top_fam_info = MITRE_7_ONTOLOGY.get(top_fam, MITRE_7_ONTOLOGY[0])
            mean_state_pred = np.mean(pred_states[incident_start_idx:incident_last_alert_idx+1, -1, :], axis=0)
            mean_obs = np.mean(obs_lasts[incident_start_idx:incident_last_alert_idx+1], axis=0)
            feature_diffs = np.abs(mean_state_pred - mean_obs)
            top_indices = np.argsort(feature_diffs)[::-1][:5]
            evidence = {
                self.feature_names[idx]: round(float(feature_diffs[idx]), 4)
                for idx in top_indices
            }
            alert = SOCAlert(
                incident_id=f"INC-{incident_start_idx:06d}",
                start_window_idx=incident_start_idx,
                start_time_seconds=incident_start_idx * 2.0,
                duration_seconds=(incident_last_alert_idx - incident_start_idx + 1) * 2.0,
                peak_risk_score=round(current_peak_risk, 4),
                confirmed_windows_count=current_confirmed_count,
                predicted_family_idx=top_fam,
                predicted_family_name=top_fam_info["name"],
                mitre_tactic=top_fam_info["tactic"],
                mitre_technique=top_fam_info["technique"],
                delta_state_evidence=evidence,
                is_precursor_alert=False
            )
            soc_alerts.append(alert)

        return {
            "stage1_candidates": stage1_candidates,
            "stage2_confirmed": stage2_confirmed,
            "soc_alerts": soc_alerts,
            "state_divergence": state_divergence,
            "slopes": slopes,
            "threat_probs": threat_probs
        }
