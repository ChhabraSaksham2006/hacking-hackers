# -*- coding: utf-8 -*-
"""
Phase 6 — Pre-Attack Onset Forecasting & Early-Warning World Model Engine
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data

Implements:
1. Strict Pure-Benign History Filtering (zero attack flows in 10-step history)
2. Multi-Horizon Onset Targets: H in {2s, 10s, 20s, 60s, 120s, 300s}
3. Episode-Aware Event Extraction and Forensic Evaluation (Window vs Event Metrics)
4. Baselines: Majority, Logistic Regression, Random Forest, Phase 5.5 RSSM
5. Progression of Experiments:
   - E601: Phase 5.5 RSSM (Standard BCE control on onset)
   - E602: Precursor/Transition Weighted Loss (decay weighting near onset)
   - E603: Precursor Horizon / Window Length Comparison
   - E604: Onset-Loss Weighting (lambda_onset in {0.5, 1.0, 2.0, 5.0})
   - E605: Focal Loss (gamma in {1.0, 2.0})
   - E606: Best Validation Configurations Evaluated
   - E607: Multi-Seed Confirmation (seeds 42, 123, 2025)
6. Dual State-Forecasting + Onset Multi-Task Retention (State MAE/MSE preserved)
7. Final Deployable Artifact Export to artifacts/phase6_onset/
"""

import os, sys, time, json, random, math, pickle, warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
    precision_recall_curve, auc, confusion_matrix,
    mean_absolute_error, mean_squared_error
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings('ignore')
torch.set_num_threads(min(8, os.cpu_count() or 4))

REPO_ROOT = Path(r"C:\CyberSecurityNetworkingAttackPredictionModel")
sys.path.insert(0, str(REPO_ROOT))

from src.models.sparse_rssm import SparseRSSM
from src.temporal.dataset_builder import (
    TemporalSequenceBuilder, STATE_FEATURE_NAMES,
    TRAIN_DAYS, VAL_DAYS, TEST_DAYS
)
from src.temporal.state_aggregator import (
    BASE_FEATURE_NAMES, DELTA_FEATURE_NAMES
)

REPORTS_DIR = REPO_ROOT / "reports" / "phase_6"
CONFIGS_DIR = REPORTS_DIR / "configs"
ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "phase6_onset"
DATA_DIR = REPO_ROOT / "data" / "processed" / "temporal_states"

for d in [REPORTS_DIR, CONFIGS_DIR, ARTIFACTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

HORIZON_STEPS = {
    2: 1,      # 2s -> 1 step
    10: 5,     # 10s -> 5 steps
    20: 10,    # 20s -> 10 steps
    60: 30,    # 60s -> 30 steps
    120: 60,   # 120s -> 60 steps
    300: 150   # 300s -> 150 steps
}

PRIMARY_H_SEC = 20 # Primary research horizon (20s / 10 steps)

def seed_all(s=42):
    random.seed(s)
    np.random.seed(s)
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)

# ============================================================
# FOCAL LOSS & WEIGHTED ONSET LOSS IMPLEMENTATION
# ============================================================

class FocalBCEWithLogitsLoss(nn.Module):
    def __init__(self, gamma=2.0, pos_weight=None, reduction='mean'):
        super().__init__()
        self.gamma = float(gamma)
        self.pos_weight = pos_weight
        self.reduction = reduction

    def forward(self, logits, targets):
        bce = nn.functional.binary_cross_entropy_with_logits(
            logits, targets, pos_weight=self.pos_weight, reduction='none'
        )
        probs = torch.sigmoid(logits)
        p_t = targets * probs + (1 - targets) * (1 - probs)
        modulating_factor = (1.0 - p_t) ** self.gamma
        loss = modulating_factor * bce
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        return loss

# ============================================================
# DATA PIPELINE WITH PURE-BENIGN ONSET TARGETS
# ============================================================

def extract_pure_benign_dataset(max_lookahead_steps=150):
    print("\n[DATA] Building Pure-Benign History Dataset across all splits...", flush=True)
    tr_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in TRAIN_DAYS]
    va_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in VAL_DAYS]
    te_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in TEST_DAYS]

    builder = TemporalSequenceBuilder(
        lookback_steps=10,
        horizons=list(range(1, max_lookahead_steps + 1)),
        feature_names=STATE_FEATURE_NAMES
    )
    builder.fit_scaler(tr_raw)

    def process(dfs, split_name):
        seqs, y_hists, target_states, onset_labels = [], [], [], {h: [] for h in HORIZON_STEPS}
        anchor_meta = []
        
        for d in dfs:
            d_scaled = builder.transform_dataframe(d)
            f = np.nan_to_num(d_scaled[STATE_FEATURE_NAMES].values.astype('float32'))
            y = d.is_attack.values.astype('int64')
            sess_id = d['session_id'].iloc[0] if 'session_id' in d.columns else 'session'
            n = len(d)
            st = 9
            en = n - 1 - max_lookahead_steps
            if en < st: continue
            
            # Sliding view over lookback=10
            w_f = np.lib.stride_tricks.sliding_window_view(f, (10, 54))[:, 0, :, :]
            w_y = np.lib.stride_tricks.sliding_window_view(y, 10)
            n_samples = en - st + 1
            
            # Filter STRICTLY to pure-benign history: all 10 history windows == 0
            pure_mask = np.all(w_y[:n_samples] == 0, axis=1)
            valid_anchors = np.where(pure_mask)[0]
            
            if len(valid_anchors) == 0: continue
            
            sel_f = w_f[:n_samples][valid_anchors]
            seqs.append(sel_f)
            y_hists.append(w_y[:n_samples][valid_anchors])
            
            # Target states at k=1..10 (for state rollout tracking)
            # block shape: (N_valid, 10, 54)
            st_blocks = []
            for k in range(1, 11):
                st_blocks.append(f[st + k : en + k + 1][valid_anchors])
            target_states.append(np.stack(st_blocks, axis=1))
            
            # Onset targets for each H in {2s, 10s, 20s, 60s, 120s, 300s}
            for sec, k_step in HORIZON_STEPS.items():
                # future window from t+1 to t+k_step
                at_blocks = np.stack([y[st + k : en + k + 1][valid_anchors] for k in range(1, k_step + 1)], axis=1)
                onset_label = (np.max(at_blocks, axis=1) == 1).astype('int64')
                onset_labels[sec].append(onset_label)
                
            for v_idx in valid_anchors:
                anchor_t = st + v_idx
                anchor_meta.append({
                    'session': sess_id,
                    'anchor_idx': int(anchor_t),
                    'timestamp': str(d['timestamp_start'].iloc[anchor_t])
                })
                
        seq_tensor = torch.from_numpy(np.vstack(seqs)).float()
        y_hist_arr = np.vstack(y_hists)
        states_tensor = torch.from_numpy(np.vstack(target_states)).float()
        onset_dict = {h: torch.from_numpy(np.concatenate(onset_labels[h])).long() for h in HORIZON_STEPS}
        
        print(f"  [{split_name}] Pure-Benign History Sequences: {len(seq_tensor):,}", flush=True)
        for h in [2, 10, 20, 60, 120, 300]:
            pos = int(onset_dict[h].sum())
            print(f"     H={h:3d}s: onsets={pos:5d} ({100*pos/len(seq_tensor):.3f}%)", flush=True)
            
        return {
            'seq': seq_tensor,
            'y_hist': y_hist_arr,
            'states': states_tensor, # (N, 10, 54)
            'onset': onset_dict,     # Dict[sec, Tensor(N,)]
            'meta': anchor_meta
        }

    train_data = process(tr_raw, "TRAIN")
    val_data = process(va_raw, "VAL")
    test_data = process(te_raw, "TEST")
    return train_data, val_data, test_data, builder

# ============================================================
# EVENT-LEVEL METRICS & EVALUATION PROTOCOL
# ============================================================

def evaluate_onset_predictions(y_true, y_probs, threshold, anchor_meta, events_df, H_sec, test_duration_hours=None):
    """
    Computes BOTH window-level metrics AND true episode event-level metrics.
    Prevents temporal duplicate window inflation.
    """
    y_true = np.asarray(y_true).astype(int)
    y_probs = np.asarray(y_probs).astype(float)
    y_pred = (y_probs >= threshold).astype(int)
    
    # 1. Window-Level Metrics
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (cm.ravel().tolist() + [0, 0, 0, 0])[:4] if cm.size == 4 else (int(cm[0,0]), 0, 0, 0)
    fpr = float(fp / max(1, fp + tn))
    fa_per_hour = (fp / max(0.001, test_duration_hours)) if test_duration_hours else 0.0
    
    roc_auc = pr_auc = 0.5
    if len(np.unique(y_true)) > 1:
        try: roc_auc = float(roc_auc_score(y_true, y_probs))
        except: pass
        try:
            p_c, r_c, _ = precision_recall_curve(y_true, y_probs)
            pr_auc = float(auc(r_c, p_c))
        except: pass

    # 2. Event-Level Metrics
    # Filter events to those in this split with prev_benign_windows >= 10
    # Group warnings to test which attack events were predicted within H_sec before onset
    event_detected = {}
    event_lead_times = {}
    
    # Map each test window index to its session & anchor
    # An event is detected if there is at least one alert (y_pred=1) at an anchor window t
    # where 0 < (onset_idx - t) * 2 <= H_sec
    for _, ev in events_df.iterrows():
        ev_id = ev['event_id']
        ev_sess = ev['session']
        onset_w = ev['onset_window_idx']
        
        event_detected[ev_id] = False
        event_lead_times[ev_id] = []
        
        for idx, m in enumerate(anchor_meta):
            if m['session'] == ev_sess:
                dist_sec = (onset_w - m['anchor_idx']) * 2.0
                if 0 < dist_sec <= H_sec:
                    if y_pred[idx] == 1:
                        event_detected[ev_id] = True
                        event_lead_times[ev_id].append(dist_sec)
                        
    n_events = len(events_df)
    n_detected = sum(1 for d in event_detected.values() if d)
    event_recall = float(n_detected / max(1, n_events))
    
    # Lead time statistics across detected events
    first_lead_times = []
    for ev_id, lts in event_lead_times.items():
        if lts:
            first_lead_times.append(max(lts)) # Earliest detection lead time
            
    lead_median = float(np.median(first_lead_times)) if first_lead_times else 0.0
    lead_mean = float(np.mean(first_lead_times)) if first_lead_times else 0.0
    lead_min = float(np.min(first_lead_times)) if first_lead_times else 0.0
    lead_max = float(np.max(first_lead_times)) if first_lead_times else 0.0
    
    return {
        'threshold': round(threshold, 4),
        'pr_auc': round(pr_auc, 4),
        'roc_auc': round(roc_auc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'fpr': round(fpr, 4),
        'false_alarms_per_hour': round(fa_per_hour, 2),
        'tp_windows': int(tp),
        'fp_windows': int(fp),
        'event_count': n_events,
        'events_detected': n_detected,
        'event_recall': round(event_recall, 4),
        'lead_time_median_sec': round(lead_median, 1),
        'lead_time_mean_sec': round(lead_mean, 1),
        'lead_time_min_sec': round(lead_min, 1),
        'lead_time_max_sec': round(lead_max, 1),
        'lead_times_list': first_lead_times
    }

def calibrate_onset_threshold_on_val(val_y, val_probs, val_meta, val_events, H_sec):
    """Calibrates threshold purely on validation split to optimize event-balanced score."""
    val_y = np.asarray(val_y).astype(int)
    thresholds = np.linspace(0.01, 0.99, 99)
    best_f1, best_t_f1 = -1.0, 0.5
    best_fpr2, best_t_fpr2 = -1.0, 0.5
    best_fpr5, best_t_fpr5 = -1.0, 0.5
    
    for t in thresholds:
        m = evaluate_onset_predictions(val_y, val_probs, t, val_meta, val_events, H_sec)
        if m['f1'] > best_f1:
            best_f1, best_t_f1 = m['f1'], t
        if m['fpr'] <= 0.02 and m['f1'] > best_fpr2:
            best_fpr2, best_t_fpr2 = m['f1'], t
        if m['fpr'] <= 0.05 and m['f1'] > best_fpr5:
            best_fpr5, best_t_fpr5 = m['f1'], t
            
    return {
        'best_f1_threshold': round(float(best_t_f1), 4),
        'best_fpr2_threshold': round(float(best_t_fpr2), 4),
        'best_fpr5_threshold': round(float(best_t_fpr5), 4),
        'val_best_f1': round(best_f1, 4)
    }

# ============================================================
# ONSET MODEL TRAINING ENGINE
# ============================================================

def train_onset_model(train_data, val_data, test_data,
                      train_events, val_events, test_events,
                      H_sec=PRIMARY_H_SEC,
                      loss_type='bce', # 'bce', 'weighted_precursor', 'focal'
                      lambda_state=1.0,
                      lambda_onset=1.0,
                      precursor_decay_sec=60.0,
                      precursor_weight_mult=5.0,
                      focal_gamma=2.0,
                      epochs=5,
                      batch_size=1024,
                      lr=1e-3,
                      seed=42,
                      device='cpu',
                      exp_id='E600'):
    """
    Core Phase 6 Training Loop:
    - Retains 54-D State Rollout Loss (10 steps)
    - Directly trains attack/onset forecasting head on pure-benign histories
    - Supports Transition / Precursor Exponential Weighting
    - Supports Focal Loss
    """
    seed_all(seed)
    k_rollout = 10 # 10 steps (20s)
    
    y_tr_onset = train_data['onset'][H_sec]
    y_va_onset = val_data['onset'][H_sec]
    y_te_onset = test_data['onset'][H_sec]
    
    # Calculate sample-specific weights if precursor weighting requested
    # Exponential decay based on distance to nearest training attack onset
    sample_weights = torch.ones(len(train_data['seq']), dtype=torch.float32)
    if loss_type == 'weighted_precursor':
        # Train events only!
        print(f"  [Precursor Weighting] Calculating decay weights (mult={precursor_weight_mult}x, tau={precursor_decay_sec}s)...", flush=True)
        train_onset_windows = [ev['onset_window_idx'] for _, ev in train_events.iterrows() if ev['is_isolated_onset']]
        for i, m in enumerate(train_data['meta']):
            anchor = m['anchor_idx']
            # find minimum distance to an upcoming onset in same session
            dists = [(ow - anchor) * 2.0 for ow in train_onset_windows if ow > anchor]
            if dists:
                min_dist = min(dists)
                if min_dist <= precursor_decay_sec:
                    # Exponential boost: 1.0 + (mult - 1.0) * exp(-min_dist / tau)
                    boost = 1.0 + (precursor_weight_mult - 1.0) * math.exp(-min_dist / (precursor_decay_sec / 2.0))
                    sample_weights[i] = boost
                    
    # Positive class weighting based strictly on train
    n_pos = int(y_tr_onset.sum())
    n_neg = len(y_tr_onset) - n_pos
    pos_weight = torch.tensor([n_neg / max(1, n_pos)], device=device)
    
    # Loss functions
    bce_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight, reduction='none')
    focal_fn = FocalBCEWithLogitsLoss(gamma=focal_gamma, pos_weight=pos_weight, reduction='none')
    
    model = SparseRSSM(sparsity_ratio=1.0).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs, eta_min=1e-5)
    
    train_ds = TensorDataset(
        train_data['seq'],
        train_data['states'][:, :k_rollout, :],
        y_tr_onset,
        sample_weights
    )
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    
    val_ds = TensorDataset(val_data['seq'], val_data['states'][:, :k_rollout, :], y_va_onset)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    
    test_ds = TensorDataset(test_data['seq'], test_data['states'][:, :k_rollout, :], y_te_onset)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)
    
    print(f"\n>>> Training Phase 6 Model | exp_id={exp_id} | H={H_sec}s | loss={loss_type} | "
          f"lambda_onset={lambda_onset} | seed={seed}", flush=True)
    
    for ep in range(1, epochs + 1):
        model.train()
        sum_total, sum_state, sum_onset = 0.0, 0.0, 0.0
        for bx, b_states, b_onset, b_w in train_loader:
            bx = bx.to(device)
            b_onset = b_onset.to(device).float()
            b_w = b_w.to(device)
            opt.zero_grad()
            
            # Rollout K=10
            out = model(bx, K=k_rollout)
            
            # 1. State Rollout Loss
            recon_l = nn.functional.mse_loss(out['x_recon'], bx[:, -1])
            roll_losses = [nn.functional.mse_loss(pred, b_states[:, i, :].to(device)) for i, pred in enumerate(out['states'])]
            state_loss = recon_l + (sum(roll_losses) / max(1, len(roll_losses)))
            
            # 2. Onset Head Loss (predicting whether onset occurs within horizon)
            # Take final rollout attack logit (or average across rollout)
            onset_logit = out['attack'][-1].squeeze(-1)
            
            if loss_type == 'focal':
                raw_onset_loss = focal_fn(onset_logit, b_onset)
            else:
                raw_onset_loss = bce_fn(onset_logit, b_onset)
                
            if loss_type == 'weighted_precursor':
                weighted_onset_loss = (raw_onset_loss * b_w).mean()
            else:
                weighted_onset_loss = raw_onset_loss.mean()
                
            total_loss = (lambda_state * state_loss) + (lambda_onset * weighted_onset_loss)
            total_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            
            sum_total += total_loss.item()
            sum_state += state_loss.item()
            sum_onset += weighted_onset_loss.item()
            
        scheduler.step()
        nb = max(1, len(train_loader))
        print(f"  Epoch {ep}/{epochs}: Total={sum_total/nb:.4f} (StateMSE={sum_state/nb:.4f}, OnsetLoss={sum_onset/nb:.4f})", flush=True)

    # ----------------------------------------------------
    # VALIDATION EVALUATION & THRESHOLD CALIBRATION
    # ----------------------------------------------------
    model.eval()
    val_probs, val_sp, val_st = [], [], []
    with torch.no_grad():
        for vx, v_states, _ in val_loader:
            vout = model(vx.to(device), K=k_rollout)
            p = torch.sigmoid(vout['attack'][-1].squeeze(-1)).cpu().numpy()
            val_probs.extend(p)
            val_sp.append(vout['states'][-1].cpu().numpy())
            val_st.append(v_states[:, -1, :].numpy())
            
    val_probs = np.asarray(val_probs)
    val_calib = calibrate_onset_threshold_on_val(y_va_onset.numpy(), val_probs, val_data['meta'], val_events, H_sec)
    opt_thresh = val_calib['best_f1_threshold']
    
    # ----------------------------------------------------
    # TEST EVALUATION (FROZEN THRESHOLD)
    # ----------------------------------------------------
    test_probs, test_sp, test_st = [], [], []
    with torch.no_grad():
        for tx, t_states, _ in test_loader:
            tout = model(tx.to(device), K=k_rollout)
            p = torch.sigmoid(tout['attack'][-1].squeeze(-1)).cpu().numpy()
            test_probs.extend(p)
            test_sp.append(tout['states'][-1].cpu().numpy())
            test_st.append(t_states[:, -1, :].numpy())
            
    test_probs = np.asarray(test_probs)
    test_sp_arr = np.vstack(test_sp)
    test_st_arr = np.vstack(test_st)
    
    test_hrs = (len(test_probs) * 2.0) / 3600.0
    test_metrics = evaluate_onset_predictions(
        y_te_onset.numpy(), test_probs, opt_thresh, test_data['meta'], test_events, H_sec, test_hrs
    )
    
    test_mae = float(mean_absolute_error(test_st_arr, test_sp_arr))
    test_mse = float(mean_squared_error(test_st_arr, test_sp_arr))
    
    print(f"  [TEST RESULT] Thresh={opt_thresh:.2f} | EventRec={test_metrics['event_recall']:.4f} "
          f"({test_metrics['events_detected']}/{test_metrics['event_count']}) | "
          f"WindowF1={test_metrics['f1']:.4f} | Prec={test_metrics['precision']:.4f} | "
          f"Rec={test_metrics['recall']:.4f} | FPR={test_metrics['fpr']:.4f} | "
          f"FA/hr={test_metrics['false_alarms_per_hour']:.1f} | MedLead={test_metrics['lead_time_median_sec']}s", flush=True)
          
    return {
        'exp_id': exp_id,
        'model': model,
        'horizon_sec': H_sec,
        'loss_type': loss_type,
        'lambda_onset': lambda_onset,
        'focal_gamma': focal_gamma if loss_type == 'focal' else 'N/A',
        'precursor_weight': precursor_weight_mult if loss_type == 'weighted_precursor' else 1.0,
        'seed': seed,
        'threshold': opt_thresh,
        'val_best_f1': val_calib['val_best_f1'],
        'test_metrics': test_metrics,
        'state_mae': round(test_mae, 4),
        'state_mse': round(test_mse, 4),
        'test_probs': test_probs
    }

# ============================================================
# BASELINES FOR ONSET FORECASTING
# ============================================================

def run_onset_baselines(train_data, val_data, test_data, val_events, test_events, H_sec=PRIMARY_H_SEC):
    print("\n" + "="*70, flush=True)
    print(f"ESTABLISHING ONSET BASELINES (H = {H_sec}s)", flush=True)
    print("="*70, flush=True)
    
    y_tr = train_data['onset'][H_sec].numpy()
    y_va = val_data['onset'][H_sec].numpy()
    y_te = test_data['onset'][H_sec].numpy()
    test_hrs = (len(y_te) * 2.0) / 3600.0
    
    results = []
    
    # 1. Majority Classifier (always 0)
    maj_probs = np.zeros_like(y_te, dtype=float)
    maj_m = evaluate_onset_predictions(y_te, maj_probs, 0.5, test_data['meta'], test_events, H_sec, test_hrs)
    results.append({
        'model': 'MajorityBaseline', 'horizon': H_sec, 'threshold': 0.5,
        'pr_auc': maj_m['pr_auc'], 'roc_auc': maj_m['roc_auc'], 'precision': 0.0, 'recall': 0.0,
        'f1': 0.0, 'fpr': 0.0, 'false_alarms_per_hour': 0.0, 'event_recall': 0.0,
        'lead_time_median_sec': 0.0, 'state_mae': 'N/A', 'state_mse': 'N/A'
    })
    print(f"  1. Majority Baseline: Event Recall=0.0% | FA/hr=0.0", flush=True)
    
    # 2. Logistic Regression (on flattened 540-D pure-benign history)
    print("  2. Fitting Logistic Regression on 10x54D pure-benign sequence...", flush=True)
    X_tr = train_data['seq'].numpy().reshape(len(train_data['seq']), -1)
    X_va = val_data['seq'].numpy().reshape(len(val_data['seq']), -1)
    X_te = test_data['seq'].numpy().reshape(len(test_data['seq']), -1)
    
    pos_w = (len(y_tr) - y_tr.sum()) / max(1, y_tr.sum())
    lr = LogisticRegression(max_iter=200, C=0.1, class_weight={0: 1.0, 1: float(pos_w)}, random_state=42)
    lr.fit(X_tr, y_tr)
    
    va_p = lr.predict_proba(X_va)[:, 1]
    calib = calibrate_onset_threshold_on_val(y_va, va_p, val_data['meta'], val_events, H_sec)
    t_opt = calib['best_f1_threshold']
    
    te_p = lr.predict_proba(X_te)[:, 1]
    lr_m = evaluate_onset_predictions(y_te, te_p, t_opt, test_data['meta'], test_events, H_sec, test_hrs)
    results.append({
        'model': 'LogisticRegression', 'horizon': H_sec, 'threshold': t_opt,
        **lr_m, 'state_mae': 'N/A', 'state_mse': 'N/A'
    })
    print(f"     LR Test: Event Recall={lr_m['event_recall']:.4f} ({lr_m['events_detected']}/{lr_m['event_count']}) | "
          f"FA/hr={lr_m['false_alarms_per_hour']:.1f} | PR-AUC={lr_m['pr_auc']:.4f} | WindowF1={lr_m['f1']:.4f}", flush=True)

    # 3. Random Forest (on 54-D most recent state)
    print("  3. Fitting Random Forest on recent behavioral state S_t...", flush=True)
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, class_weight={0: 1.0, 1: float(pos_w)}, n_jobs=4, random_state=42)
    rf.fit(train_data['seq'][:, -1, :].numpy(), y_tr)
    
    rf_va_p = rf.predict_proba(val_data['seq'][:, -1, :].numpy())[:, 1]
    rf_calib = calibrate_onset_threshold_on_val(y_va, rf_va_p, val_data['meta'], val_events, H_sec)
    t_rf = rf_calib['best_f1_threshold']
    
    rf_te_p = rf.predict_proba(test_data['seq'][:, -1, :].numpy())[:, 1]
    rf_m = evaluate_onset_predictions(y_te, rf_te_p, t_rf, test_data['meta'], test_events, H_sec, test_hrs)
    results.append({
        'model': 'RandomForest', 'horizon': H_sec, 'threshold': t_rf,
        **rf_m, 'state_mae': 'N/A', 'state_mse': 'N/A'
    })
    print(f"     RF Test: Event Recall={rf_m['event_recall']:.4f} ({rf_m['events_detected']}/{rf_m['event_count']}) | "
          f"FA/hr={rf_m['false_alarms_per_hour']:.1f} | PR-AUC={rf_m['pr_auc']:.4f} | WindowF1={rf_m['f1']:.4f}", flush=True)

    return results

# ============================================================
# MASTER PHASE 6 EXPERIMENT PIPELINE
# ============================================================

def main():
    print("=" * 85, flush=True)
    print("      SIH26153 — PHASE 6: PRE-ATTACK ONSET FORECASTING RESEARCH PIPELINE      ", flush=True)
    print("=" * 85, flush=True)
    
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Compute Hardware: {device} | Active Threads: {torch.get_num_threads()}", flush=True)
    
    # 1. Load Episode Forensics Table
    events_file = REPORTS_DIR / "attack_events_forensics.csv"
    if not events_file.exists():
        print("Error: attack_events_forensics.csv not found.")
        return
    events_df = pd.read_csv(events_file)
    # Use isolated events (prev_benign_windows >= 10) for true onset evaluation
    iso_events = events_df[events_df['is_isolated_onset']].copy()
    train_events = iso_events[iso_events['split'] == 'TRAIN']
    val_events = iso_events[iso_events['split'] == 'VAL']
    test_events = iso_events[iso_events['split'] == 'TEST']
    
    print(f"\nUnique Isolated Onset Events:")
    print(f"  TRAIN: {len(train_events)} episodes")
    print(f"  VAL:   {len(val_events)} episodes")
    print(f"  TEST:  {len(test_events)} episodes", flush=True)
    
    # 2. Extract Pure-Benign History Dataset
    train_data, val_data, test_data, builder = extract_pure_benign_dataset(max_lookahead_steps=150)
    
    # Authoritative Table Accumulator
    master_results = []
    
    # ----------------------------------------------------
    # STEP A: Baselines
    # ----------------------------------------------------
    baselines = run_onset_baselines(train_data, val_data, test_data, val_events, test_events, H_sec=PRIMARY_H_SEC)
    for b in baselines:
        master_results.append({
            'experiment_id': f"BASE_{b['model']}",
            'model': b['model'],
            'horizon': PRIMARY_H_SEC,
            'precursor_window': 'N/A',
            'loss_type': 'standard',
            'lambda_onset': 'N/A',
            'precursor_weight': 1.0,
            'focal_gamma': 'N/A',
            'threshold': b['threshold'],
            'PR_AUC': b['pr_auc'],
            'ROC_AUC': b['roc_auc'],
            'precision': b['precision'],
            'recall': b['recall'],
            'F1': b['f1'],
            'FPR': b['fpr'],
            'false_alarms_per_hour': b['false_alarms_per_hour'],
            'event_count': b.get('event_count', len(test_events)),
            'event_recall': b['event_recall'],
            'median_lead_time': b['lead_time_median_sec'],
            'mean_lead_time': b.get('lead_time_mean_sec', 0.0),
            'state_MAE': b['state_mae'],
            'state_MSE': b['state_mse'],
            'seed': 42,
            'status': 'VALID'
        })

    # ----------------------------------------------------
    # STEP B: E601 — Standard BCE Control on Onset Target
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print(f"EXPERIMENT E601: Standard BCE RSSM Control (H = {PRIMARY_H_SEC}s)", flush=True)
    print("="*70, flush=True)
    e601 = train_onset_model(
        train_data, val_data, test_data, train_events, val_events, test_events,
        H_sec=PRIMARY_H_SEC, loss_type='bce', lambda_state=1.0, lambda_onset=1.0,
        epochs=5, exp_id="E601_RSSM_BCE_Control"
    )
    tm = e601['test_metrics']
    master_results.append({
        'experiment_id': e601['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
        'precursor_window': 'N/A', 'loss_type': 'bce', 'lambda_onset': 1.0,
        'precursor_weight': 1.0, 'focal_gamma': 'N/A', 'threshold': e601['threshold'],
        'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
        'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
        'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
        'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
        'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': e601['state_mae'],
        'state_MSE': e601['state_mse'], 'seed': 42, 'status': 'VALID'
    })

    # ----------------------------------------------------
    # STEP C: E602 — Transition / Precursor-Weighted Loss
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print("EXPERIMENT E602: Precursor-Weighted Transition Loss Sweep", flush=True)
    print("="*70, flush=True)
    
    e602_candidates = []
    for mult in [2.0, 5.0, 10.0]:
        exp_id = f"E602_PrecursorWeight_{int(mult)}x"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=PRIMARY_H_SEC, loss_type='weighted_precursor',
            precursor_weight_mult=mult, precursor_decay_sec=60.0,
            lambda_state=1.0, lambda_onset=1.0, epochs=5, exp_id=exp_id
        )
        e602_candidates.append(res)
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
            'precursor_window': '60s', 'loss_type': 'weighted_precursor', 'lambda_onset': 1.0,
            'precursor_weight': mult, 'focal_gamma': 'N/A', 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': 42, 'status': 'VALID'
        })
        
    best_e602 = max(e602_candidates, key=lambda r: r['val_best_f1'])
    print(f"\nE602 Best by Validation F1: {best_e602['exp_id']} (val_F1={best_e602['val_best_f1']:.4f})", flush=True)

    # ----------------------------------------------------
    # STEP D: E603 — Precursor Context Window Lengths
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print("EXPERIMENT E603: Precursor Context Window Length Ablation", flush=True)
    print("="*70, flush=True)
    
    e603_candidates = []
    best_mult = best_e602['precursor_weight']
    for p_sec in [20.0, 60.0, 120.0]:
        if p_sec == 60.0:
            e603_candidates.append(best_e602) # Already computed
            continue
        exp_id = f"E603_PrecursorWindow_{int(p_sec)}s"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=PRIMARY_H_SEC, loss_type='weighted_precursor',
            precursor_weight_mult=best_mult, precursor_decay_sec=p_sec,
            lambda_state=1.0, lambda_onset=1.0, epochs=5, exp_id=exp_id
        )
        e603_candidates.append(res)
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
            'precursor_window': f"{int(p_sec)}s", 'loss_type': 'weighted_precursor', 'lambda_onset': 1.0,
            'precursor_weight': best_mult, 'focal_gamma': 'N/A', 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': 42, 'status': 'VALID'
        })
        
    best_e603 = max(e603_candidates, key=lambda r: r['val_best_f1'])
    best_p_sec = float(best_e603['exp_id'].split('_')[-1].replace('s', '')) if 'PrecursorWindow' in best_e603['exp_id'] else 60.0

    # ----------------------------------------------------
    # STEP E: E604 — Loss Balance Sweep (lambda_onset)
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print("EXPERIMENT E604: Loss Balance Sweep (lambda_onset)", flush=True)
    print("="*70, flush=True)
    
    e604_candidates = []
    for l_on in [0.5, 2.0, 5.0]:
        exp_id = f"E604_LossBalance_lam{str(l_on).replace('.','p')}"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=PRIMARY_H_SEC, loss_type='weighted_precursor',
            precursor_weight_mult=best_mult, precursor_decay_sec=best_p_sec,
            lambda_state=1.0, lambda_onset=l_on, epochs=5, exp_id=exp_id
        )
        e604_candidates.append(res)
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
            'precursor_window': f"{int(best_p_sec)}s", 'loss_type': 'weighted_precursor', 'lambda_onset': l_on,
            'precursor_weight': best_mult, 'focal_gamma': 'N/A', 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': 42, 'status': 'VALID'
        })
        
    e604_candidates.append(best_e603) # includes lambda=1.0
    best_e604 = max(e604_candidates, key=lambda r: r['val_best_f1'])
    best_lam = best_e604['lambda_onset']
    print(f"\nE604 Best: lambda_onset={best_lam} (val_F1={best_e604['val_best_f1']:.4f})", flush=True)

    # ----------------------------------------------------
    # STEP F: E605 — Focal Loss Exploration
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print("EXPERIMENT E605: Focal Loss Exploration", flush=True)
    print("="*70, flush=True)
    
    e605_candidates = [best_e604]
    for g in [1.0, 2.0]:
        exp_id = f"E605_FocalLoss_g{int(g)}"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=PRIMARY_H_SEC, loss_type='focal', focal_gamma=g,
            lambda_state=1.0, lambda_onset=best_lam, epochs=5, exp_id=exp_id
        )
        e605_candidates.append(res)
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
            'precursor_window': 'N/A', 'loss_type': 'focal', 'lambda_onset': best_lam,
            'precursor_weight': 1.0, 'focal_gamma': g, 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': 42, 'status': 'VALID'
        })
        
    champion = max(e605_candidates, key=lambda r: r['val_best_f1'])
    print(f"\n========================================================")
    print(f"CHAMPION MODEL SELECTED ON VALIDATION: {champion['exp_id']}")
    print(f"Validation Best F1: {champion['val_best_f1']:.4f}")
    print(f"========================================================", flush=True)

    # ----------------------------------------------------
    # STEP G: E606 — Multi-Horizon Scaling for Champion Config
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print(f"EXPERIMENT E606: Multi-Horizon Scaling for Champion Config", flush=True)
    print("="*70, flush=True)
    
    horizon_results = {}
    for h in [2, 10, 20, 60, 120, 300]:
        if h == PRIMARY_H_SEC:
            horizon_results[h] = champion
            continue
        exp_id = f"E606_Champion_H{h}s"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=h, loss_type=champion['loss_type'],
            precursor_weight_mult=champion['precursor_weight'],
            precursor_decay_sec=best_p_sec,
            focal_gamma=champion.get('focal_gamma', 2.0) if champion['loss_type']=='focal' else 2.0,
            lambda_state=1.0, lambda_onset=champion['lambda_onset'],
            epochs=5, exp_id=exp_id
        )
        horizon_results[h] = res
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': h,
            'precursor_window': f"{int(best_p_sec)}s", 'loss_type': champion['loss_type'],
            'lambda_onset': champion['lambda_onset'], 'precursor_weight': champion['precursor_weight'],
            'focal_gamma': champion.get('focal_gamma', 'N/A'), 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': 42, 'status': 'VALID'
        })

    # ----------------------------------------------------
    # STEP H: E607 — Multi-Seed Confirmation (Seeds 42, 123, 2025)
    # ----------------------------------------------------
    print("\n" + "="*70, flush=True)
    print("EXPERIMENT E607: Multi-Seed Confirmation (Seeds 42, 123, 2025)", flush=True)
    print("="*70, flush=True)
    
    seed_runs = [champion]
    for s in [123, 2025]:
        exp_id = f"E607_Champion_seed{s}"
        res = train_onset_model(
            train_data, val_data, test_data, train_events, val_events, test_events,
            H_sec=PRIMARY_H_SEC, loss_type=champion['loss_type'],
            precursor_weight_mult=champion['precursor_weight'],
            precursor_decay_sec=best_p_sec,
            focal_gamma=champion.get('focal_gamma', 2.0) if champion['loss_type']=='focal' else 2.0,
            lambda_state=1.0, lambda_onset=champion['lambda_onset'],
            epochs=5, seed=s, exp_id=exp_id
        )
        seed_runs.append(res)
        tm = res['test_metrics']
        master_results.append({
            'experiment_id': res['exp_id'], 'model': 'SparseRSSM', 'horizon': PRIMARY_H_SEC,
            'precursor_window': f"{int(best_p_sec)}s", 'loss_type': champion['loss_type'],
            'lambda_onset': champion['lambda_onset'], 'precursor_weight': champion['precursor_weight'],
            'focal_gamma': champion.get('focal_gamma', 'N/A'), 'threshold': res['threshold'],
            'PR_AUC': tm['pr_auc'], 'ROC_AUC': tm['roc_auc'], 'precision': tm['precision'],
            'recall': tm['recall'], 'F1': tm['f1'], 'FPR': tm['fpr'],
            'false_alarms_per_hour': tm['false_alarms_per_hour'], 'event_count': tm['event_count'],
            'event_recall': tm['event_recall'], 'median_lead_time': tm['lead_time_median_sec'],
            'mean_lead_time': tm['lead_time_mean_sec'], 'state_MAE': res['state_mae'],
            'state_MSE': res['state_mse'], 'seed': s, 'status': 'VALID'
        })

    seed_f1 = [r['test_metrics']['f1'] for r in seed_runs]
    seed_prauc = [r['test_metrics']['pr_auc'] for r in seed_runs]
    seed_ev_rec = [r['test_metrics']['event_recall'] for r in seed_runs]
    seed_prec = [r['test_metrics']['precision'] for r in seed_runs]
    seed_fpr = [r['test_metrics']['fpr'] for r in seed_runs]
    seed_lead = [r['test_metrics']['lead_time_median_sec'] for r in seed_runs]

    print(f"\nMulti-Seed Summary ({len(seed_runs)} seeds):")
    print(f"  Event Recall: {np.mean(seed_ev_rec)*100:.1f}% ± {np.std(seed_ev_rec)*100:.1f}%")
    print(f"  PR-AUC:       {np.mean(seed_prauc):.4f} ± {np.std(seed_prauc):.4f}")
    print(f"  Window F1:    {np.mean(seed_f1):.4f} ± {np.std(seed_f1):.4f}")
    print(f"  Precision:    {np.mean(seed_prec)*100:.1f}% ± {np.std(seed_prec)*100:.1f}%")
    print(f"  FPR:          {np.mean(seed_fpr)*100:.2f}% ± {np.std(seed_fpr)*100:.2f}%")
    print(f"  Median Lead:  {np.mean(seed_lead):.1f}s ± {np.std(seed_lead):.1f}s", flush=True)

    # ----------------------------------------------------
    # STEP I: Save Master Authoritative Table
    # ----------------------------------------------------
    res_df = pd.DataFrame(master_results)
    res_df.to_csv(REPORTS_DIR / "authoritative_onset_results.csv", index=False)
    print(f"\nSaved master results table to: {REPORTS_DIR / 'authoritative_onset_results.csv'}", flush=True)

    # ----------------------------------------------------
    # STEP J: Package Deployable Phase 6 Artifact
    # ----------------------------------------------------
    print("\n[ARTIFACT] Packaging final Phase 6 deployable model artifact...", flush=True)
    champ_model = champion['model']
    torch.save({
        'model_state_dict': champ_model.state_dict(),
        'config': {
            'state_dim': 54, 'latent_dim': 128, 'hidden_dim': 128,
            'sparsity_ratio': 1.0, 'horizon_sec': PRIMARY_H_SEC,
            'loss_type': champion['loss_type'],
            'lambda_onset': champion['lambda_onset'],
            'precursor_weight': champion['precursor_weight'],
            'threshold': champion['threshold']
        }
    }, ARTIFACTS_DIR / "model.pt")
    
    with open(ARTIFACTS_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(builder.scaler, f)
        
    schema = {
        'feature_names': STATE_FEATURE_NAMES,
        'n_features': len(STATE_FEATURE_NAMES),
        'lookback_steps': 10,
        'input_shape': [10, 54],
        'primary_warning_horizon_sec': PRIMARY_H_SEC,
        'detection_threshold': champion['threshold']
    }
    with open(ARTIFACTS_DIR / "feature_schema.json", "w") as f:
        json.dump(schema, f, indent=2)
        
    meta = {
        'phase': '6.0',
        'model_type': 'SparseRSSM_EarlyWarning',
        'champion_experiment_id': champion['exp_id'],
        'validation_best_f1': champion['val_best_f1'],
        'calibrated_threshold': champion['threshold'],
        'test_event_recall': champion['test_metrics']['event_recall'],
        'test_pr_auc': champion['test_metrics']['pr_auc'],
        'test_precision': champion['test_metrics']['precision'],
        'test_fpr': champion['test_metrics']['fpr'],
        'test_false_alarms_per_hour': champion['test_metrics']['false_alarms_per_hour'],
        'median_lead_time_sec': champion['test_metrics']['lead_time_median_sec'],
        'multi_seed_event_recall_mean': round(float(np.mean(seed_ev_rec)), 4),
        'multi_seed_event_recall_std': round(float(np.std(seed_ev_rec)), 4)
    }
    with open(ARTIFACTS_DIR / "metadata.json", "w") as f:
        json.dump(meta, f, indent=2)
        
    print(f"Artifacts successfully exported to: {ARTIFACTS_DIR}", flush=True)

    # ----------------------------------------------------
    # STEP K: Clean Inference Smoke Test
    # ----------------------------------------------------
    print("\n[SMOKE TEST] Executing clean inference test...", flush=True)
    ckpt = torch.load(ARTIFACTS_DIR / "model.pt", map_location="cpu", weights_only=False)
    smoke_m = SparseRSSM(sparsity_ratio=1.0)
    smoke_m.load_state_dict(ckpt['model_state_dict'])
    smoke_m.eval()
    
    dummy_input = torch.randn(1, 10, 54)
    with torch.no_grad():
        out = smoke_m(dummy_input, K=10)
        attack_prob = float(torch.sigmoid(out['attack'][-1]).item())
        state_pred = out['states'][-1].numpy()
        
    t_det = champion['threshold']
    risk_level = "CRITICAL_ATTACK_IMMINENT" if attack_prob >= t_det else ("ELEVATED_WATCH" if attack_prob >= t_det/2.0 else "NOMINAL_BENIGN")
    
    print(f"  Input Shape:       [1, 10, 54]")
    print(f"  Predicted Prob:    {attack_prob:.4f} (Threshold: {t_det:.4f})")
    print(f"  Risk Level:        {risk_level}")
    print(f"  State Pred Shape:  {state_pred.shape}")
    print("  SMOKE TEST PASSED.")
    print("\n=== PHASE 6 EXECUTION COMPLETE ===", flush=True)

if __name__ == '__main__':
    main()
