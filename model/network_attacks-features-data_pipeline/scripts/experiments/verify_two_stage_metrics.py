import os
import sys
import numpy as np
import pandas as pd
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from src.detection.two_stage_detector import (
    TwoStageAttackDetector,
    TwoStageConfig,
    evaluate_two_stage_detector,
    aggregate_alerts_into_incidents
)
from src.data.benchmark_dataset import HardenedBenchmarkDataset

print(= * 80)
print(VERIFYING TWO-STAGE EARLY WARNING METRICS ON TEST SETS)
print(= * 80)

for s in [A, B, C]:
    sig_path = os.path.join(PROJECT_ROOT, data, processed, signals, fsetting_{s.lower()}_test_signals.npz)
    if not os.path.exists(sig_path):
        print(fError: {sig_path} not found!)
        continue

    sig_data = np.load(sig_path)
    scaler_path = os.path.join(PROJECT_ROOT, models, scalers, fsetting_{s.lower()}_scaler.joblib)
    scaler = joblib.load(scaler_path)
    test_ds = HardenedBenchmarkDataset(setting=s, split=test, scaler=scaler, fit_scaler=False)

    signals_dict = {
        tfc_risk: sig_data[tfc_risk],
        rssm_risk: sig_data[rssm_risk],
        tfc_state_dev: sig_data[tfc_state_dev],
        rssm_recon_err: sig_data[rssm_recon_err],
        traj_slope: sig_data[traj_slope],
        latent_conf: sig_data[latent_conf],
        features: test_ds.x_history[:, -1, :].numpy()
    }

    # Calibrated config
    cfg = TwoStageConfig(tau_s1=0.10, tau_s2=0.80, w_tfc=0.60, w_rssm=0.40, w_dev=0.30, w_slope=0.25, w_lat=0.25, w_feat=0.20, min_confirm_count=1)

    det = TwoStageAttackDetector(cfg)
    metrics, alarms = evaluate_two_stage_detector(det, signals_dict, test_ds.manifest, test_ds.attack_k10.numpy())

    print(f\n--- SETTING {s} TEST RESULTS ---)
    print(fTotal Test Windows: {len(test_ds)})
    print(fGround Truth Attacks (k=10): {np.sum(test_ds.attack_k10.numpy() == 1)})
    print(fCandidate Alerts (Stage 1): {np.sum(alarms['candidate_mask'])})
    print(fConfirmed Alerts (Stage 2): {np.sum(alarms['confirmed_mask'])})
    print(fPrecision: {metrics['precision'] * 100:.2f}%)
    print(fRecall: {metrics['recall'] * 100:.2f}%)
    print(fF1-Score: {metrics['f1_score'] * 100:.2f}%)
    print(fPR-AUC: {metrics['pr_auc']:.4f})
    print(fROC-AUC: {metrics['roc_auc']:.4f})
    print(fFPR: {metrics['fpr'] * 100:.4f}%)
    print(fEvents Detected: {metrics['events_detected']} / {metrics['total_events']})
    print(fOnset Recall: {metrics['onset_recall'] * 100:.2f}%)
    print(fMedian Lead Time: {metrics['median_lead_time']:.1f}s)
    print(fMissed Episodes: {metrics['missed_episodes']})
    print(fWindow FA/hr: {metrics['window_fa_hr']:.2f})
    print(fIncident FA/hr: {metrics['incident_fa_hr']:.2f})
    print(fTotal Incidents: {metrics['total_incidents']})
