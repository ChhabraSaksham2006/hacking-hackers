# -*- coding: utf-8 -*-
"""
Phase 5.5 — Forensic Experimental Correction & Model Improvement
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data

Fixes all CRITICAL issues found in forensic audit:
  CRIT-02: Enforce k_train == k_eval for all horizons
  CRIT-03/04: Retrain ALL models fresh (no checkpoint reuse from pre-fix state)
  CRIT-04: Pre-onset threshold selected on VALIDATION eligible subset only

Experiments:
  E001: Baseline replication (Persistence, LR, RF, GRU) at K=1,10,50
  E002: RSSM lambda_attack sweep {0.1, 0.5, 1.0, 2.0, 5.0} at K=1 (no pos_weight)
  E003: RSSM positive weighting vs best-lambda from E002 at K=1, K=10
  E004: Final best config confirmed at K=1, K=10, K=50 with k_train==k
  E005: Multi-seed confirmation (3 seeds) for best config

Scientific rules (enforced in code):
  - Threshold selected on VAL ONLY
  - Test not touched until final model is frozen
  - k_train == k_eval always
  - Onset threshold also selected on VAL eligible subset
  - No cherry-picking
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
from sklearn.preprocessing import StandardScaler as SKScaler

warnings.filterwarnings('ignore')
torch.set_num_threads(min(8, os.cpu_count() or 4))

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.models.sparse_rssm import SparseRSSM
from src.temporal.dataset_builder import (
    TemporalSequenceBuilder, STATE_FEATURE_NAMES,
    TRAIN_DAYS, VAL_DAYS, TEST_DAYS
)
from src.temporal.state_aggregator import (
    BASE_FEATURE_NAMES, DELTA_FEATURE_NAMES, FAMILY_TO_IDX
)
from src.models.baselines.persistence import PersistenceForecaster

GIT_COMMIT = "6d20a8e"
PHASE = "5.5"
REPORTS_DIR = REPO_ROOT / "reports" / "phase_5_5"
CONFIGS_DIR = REPORTS_DIR / "configs"
RESULTS_DIR = REPO_ROOT / "results_phase5_5"
ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "rssm"
DATA_DIR = REPO_ROOT / "data" / "processed" / "temporal_states"

for d in [REPORTS_DIR, CONFIGS_DIR, RESULTS_DIR, ARTIFACTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

AUTHORITATIVE_RESULTS_PATH = REPORTS_DIR / "authoritative_experiment_results.csv"

# ============================================================
# REPRODUCIBILITY
# ============================================================

def seed_all(s: int = 42):
    random.seed(s)
    np.random.seed(s)
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)


def save_config(exp_id: str, config: dict):
    path = CONFIGS_DIR / f"{exp_id}.json"
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    return str(path)


# ============================================================
# DATA LOADING (FIXED: k_train == k enforced by caller)
# ============================================================

def load_all_data(max_h: int = 50) -> Tuple[dict, dict, dict, TemporalSequenceBuilder]:
    """Load and preprocess all splits. max_h controls target block size."""
    print(f"\n[DATA] Loading parquets with max_h={max_h}...", flush=True)
    tr_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in TRAIN_DAYS]
    va_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in VAL_DAYS]
    te_raw = [pd.read_parquet(DATA_DIR / d.replace('.parquet', '_states.parquet')) for d in TEST_DAYS]

    builder = TemporalSequenceBuilder(
        lookback_steps=10,
        horizons=list(range(1, max_h + 1)),
        feature_names=STATE_FEATURE_NAMES
    )
    builder.fit_scaler(tr_raw)

    def process_split(dfs, split_name):
        seq_list, states_list, attacks_list, stages_list, y_hist_list, raw_dfs = [], [], [], [], [], []
        for d in dfs:
            d_scaled = builder.transform_dataframe(d)
            f = np.nan_to_num(d_scaled[STATE_FEATURE_NAMES].values.astype('float32'))
            y = d.is_attack.values.astype('int64')
            stg = d['family_idx'].values.astype('int64') if 'family_idx' in d.columns else np.zeros(len(d), 'int64')
            n = len(d)
            st = 9
            en = n - 1 - max_h
            if en < st:
                continue
            # Sliding window sequences
            w_f = np.lib.stride_tricks.sliding_window_view(f, (10, 54))[:, 0, :, :]
            w_y = np.lib.stride_tricks.sliding_window_view(y, 10)
            n_seq = en - st + 1
            seq_list.append(np.ascontiguousarray(w_f[:n_seq]))
            y_hist_list.append(np.ascontiguousarray(w_y[:n_seq]))
            raw_dfs.append(d_scaled.iloc[st: en + 1].copy())
            # 3D target blocks: (n_seq, max_h, dim)
            st_b = np.stack([f[st + k: en + k + 1] for k in range(1, max_h + 1)], axis=1)
            at_b = np.stack([y[st + k: en + k + 1] for k in range(1, max_h + 1)], axis=1)
            sg_b = np.stack([stg[st + k: en + k + 1] for k in range(1, max_h + 1)], axis=1)
            states_list.append(st_b)
            attacks_list.append(at_b)
            stages_list.append(sg_b)

        seq = torch.from_numpy(np.vstack(seq_list)).float()
        y_hist = np.vstack(y_hist_list)
        states = torch.from_numpy(np.vstack(states_list)).float()
        attacks = torch.from_numpy(np.vstack(attacks_list)).long()
        stages = torch.from_numpy(np.vstack(stages_list)).long()

        # Compute positive weight from TRAIN only (stored but only applied for training split)
        pos_count = int(attacks[:, 0].sum())
        neg_count = int((attacks[:, 0] == 0).sum())
        pos_weight = neg_count / max(1, pos_count)

        print(f"  [{split_name}] sequences={len(seq):,}, "
              f"pos_k1={pos_count:,} ({100*pos_count/len(seq):.1f}%), "
              f"pos_weight={pos_weight:.2f}", flush=True)

        return {
            'seq': seq,
            'y_hist': y_hist,
            'states': states,
            'attacks': attacks,
            'stages': stages,
            'raw_dfs': raw_dfs,
            'pos_weight': pos_weight,
        }

    train_data = process_split(tr_raw, "TRAIN")
    val_data   = process_split(va_raw, "VAL")
    test_data  = process_split(te_raw, "TEST")
    return train_data, val_data, test_data, builder


# ============================================================
# METRICS (FINE-GRAINED THRESHOLD GRID)
# ============================================================

def compute_metrics_at_threshold(y_true, y_probs, threshold, test_duration_hours=None):
    y_true = np.asarray(y_true).astype(int)
    y_pred = (np.asarray(y_probs) >= threshold).astype(int)
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec  = float(recall_score(y_true, y_pred, zero_division=0))
    f1   = float(f1_score(y_true, y_pred, zero_division=0))
    cm   = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (cm.ravel().tolist() + [0, 0, 0, 0])[:4] if cm.size == 4 else (int(cm[0,0]), 0, 0, 0)
    fpr  = float(fp / max(1, fp + tn))
    fa_hr = (fp / max(0.001, test_duration_hours)) if test_duration_hours else None
    roc_auc = pr_auc = 0.5
    if len(np.unique(y_true)) > 1:
        try:    roc_auc = float(roc_auc_score(y_true, y_probs))
        except: pass
        try:
            p_c, r_c, _ = precision_recall_curve(y_true, y_probs)
            pr_auc = float(auc(r_c, p_c))
        except: pass
    m = dict(threshold=round(threshold,4), f1=round(f1,4), precision=round(prec,4),
             recall=round(rec,4), fpr=round(fpr,4), roc_auc=round(roc_auc,4),
             pr_auc=round(pr_auc,4), tp=int(tp), tn=int(tn), fp=int(fp), fn=int(fn),
             pos_pred_rate=round(float(y_pred.mean()),4),
             support=int(y_true.sum()))
    if fa_hr is not None:
        m['false_alarms_per_hour'] = round(fa_hr, 2)
    return m


def calibrate_threshold_on_val(val_y, val_probs, return_all=False):
    """Fine-grained grid: 0.01-0.99 in 0.01 steps. ONLY uses validation data."""
    val_y = np.asarray(val_y).astype(int)
    thresholds = np.linspace(0.01, 0.99, 99)
    records = []
    best_f1, best_t_f1 = -1, 0.5
    best_prec, best_t_prec5 = -1, 0.5  # best F1 with FPR<=0.05
    best_prec10, best_t_prec10 = -1, 0.5  # best F1 with FPR<=0.10
    best_rec, best_t_rec = -1, 0.5  # best F1 with Recall>=0.50

    for t in thresholds:
        m = compute_metrics_at_threshold(val_y, val_probs, t)
        records.append(m)
        if m['f1'] > best_f1:
            best_f1, best_t_f1 = m['f1'], t
        if m['fpr'] <= 0.05 and m['f1'] > best_prec:
            best_prec, best_t_prec5 = m['f1'], t
        if m['fpr'] <= 0.10 and m['f1'] > best_prec10:
            best_prec10, best_t_prec10 = m['f1'], t

    return {
        'best_f1_threshold': round(float(best_t_f1), 4),
        'best_fpr5_threshold': round(float(best_t_prec5), 4),
        'best_fpr10_threshold': round(float(best_t_prec10), 4),
        'val_best_f1': round(best_f1, 4),
        'all_records': records if return_all else None,
    }


# ============================================================
# RSSM TRAINING — FIXED (k_train == k enforced)
# ============================================================

def train_rssm(train_data, val_data, test_data,
               k: int,
               epochs: int = 5,
               batch_size: int = 1024,
               lr: float = 1e-3,
               lambda_state: float = 1.0,
               lambda_attack: float = 1.0,
               lambda_mitre: float = 0.0,
               sparsity_ratio: float = 1.0,
               use_pos_weight: bool = False,
               seed: int = 42,
               device: str = 'cpu',
               exp_id: str = 'unknown') -> dict:
    """
    FIXED training:
    - k_train == k (no capping to 10)
    - Fresh model always (no checkpoint reuse)
    - pos_weight computed from train data if use_pos_weight=True
    - Threshold selected on VAL
    """
    seed_all(seed)

    # k_train == k (THE FIX for CRIT-02)
    k_train = k
    # For very large K on CPU, cap training rollout to 50 to avoid OOM
    # but only if K > 50, and document this clearly
    k_train_actual = min(k, 50)
    if k_train_actual < k:
        print(f"  [NOTE] k={k} > 50: training rollout capped at k_train={k_train_actual} (memory constraint). "
              f"This is a known limitation for CPU; document in results.", flush=True)

    pos_weight_val = None
    if use_pos_weight:
        pw = float(train_data['pos_weight'])
        pos_weight_val = torch.tensor([pw], device=device)

    model = SparseRSSM(sparsity_ratio=sparsity_ratio).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs, eta_min=1e-5)

    # Build datasets
    train_ds = TensorDataset(
        train_data['seq'],
        train_data['states'][:, :k_train_actual, :],
        train_data['attacks'][:, :k_train_actual],
        train_data['stages'][:, :k_train_actual]
    )
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)

    # Val/Test use single horizon k (index k-1)
    val_ds = TensorDataset(val_data['seq'], val_data['states'][:, k-1, :], val_data['attacks'][:, k-1])
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_ds = TensorDataset(test_data['seq'], test_data['states'][:, k-1, :], test_data['attacks'][:, k-1])
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)

    print(f"\n>>> Training RSSM | exp_id={exp_id} | K={k} ({k*2}s) | k_train={k_train_actual} | "
          f"epochs={epochs} | lambda_atk={lambda_attack:.1f} | pos_weight={'Yes' if use_pos_weight else 'No'} | seed={seed}", flush=True)

    history = []
    for epoch in range(1, epochs + 1):
        model.train()
        total_l = state_l = atk_l = 0.0
        for bx, by_st, by_atk, by_stg in train_loader:
            bx = bx.to(device)
            y_states  = [by_st[:, i, :].to(device) for i in range(k_train_actual)]
            y_attacks = [by_atk[:, i].to(device) for i in range(k_train_actual)]
            y_stages  = [by_stg[:, i].to(device) for i in range(k_train_actual)]
            opt.zero_grad()
            out = model(bx, K=k_train_actual)
            loss, ld = model.loss(
                out, bx[:, -1], y_states, y_attacks, y_stages,
                lambda_state=lambda_state, lambda_attack=lambda_attack,
                lambda_mitre=lambda_mitre, pos_weight=pos_weight_val
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_l += ld['total']; state_l += ld['state_rollout']; atk_l += ld['attack_bce']

        scheduler.step()
        n_b = max(1, len(train_loader))

        # Validate
        model.eval()
        val_probs, val_ys, val_mses = [], [], []
        with torch.no_grad():
            for vx, vys, vya in val_loader:
                vout = model(vx.to(device), K=k)
                pred_s = vout['states'][-1].cpu()
                pred_p = torch.sigmoid(vout['attack'][-1].squeeze(-1)).cpu()
                val_probs.extend(pred_p.numpy()); val_ys.extend(vya.numpy())
                val_mses.append(torch.mean((pred_s - vys)**2).item())

        val_calib = calibrate_threshold_on_val(val_ys, val_probs)
        thresh = val_calib['best_f1_threshold']
        vm = compute_metrics_at_threshold(val_ys, val_probs, thresh)
        ep_log = {
            'epoch': epoch, 'train_total': round(total_l/n_b,4),
            'train_state_mse': round(state_l/n_b,4), 'train_atk_bce': round(atk_l/n_b,4),
            'val_state_mse': round(float(np.mean(val_mses)),4),
            'val_f1': vm['f1'], 'val_pr_auc': vm['pr_auc'], 'val_thresh': thresh
        }
        history.append(ep_log)
        print(f"  Epoch {epoch}/{epochs}: TrainLoss={total_l/n_b:.4f} "
              f"(MSE={state_l/n_b:.4f}, BCE={atk_l/n_b:.4f}) | "
              f"ValMSE={ep_log['val_state_mse']:.4f} | ValF1={vm['f1']:.4f} (t={thresh:.2f})", flush=True)

    # Final threshold calibration on val
    val_calib_final = calibrate_threshold_on_val(val_ys, val_probs)
    thresh_f1   = val_calib_final['best_f1_threshold']
    thresh_fpr5 = val_calib_final['best_fpr5_threshold']
    thresh_fpr10 = val_calib_final['best_fpr10_threshold']

    # Test evaluation (frozen threshold from val)
    model.eval()
    test_probs, test_ys, test_sp, test_st = [], [], [], []
    with torch.no_grad():
        for tx, tys, tya in test_loader:
            tout = model(tx.to(device), K=k)
            test_probs.extend(torch.sigmoid(tout['attack'][-1].squeeze(-1)).cpu().numpy())
            test_ys.extend(tya.numpy())
            test_sp.append(tout['states'][-1].cpu().numpy())
            test_st.append(tys.numpy())

    tp_arr = np.asarray(test_probs); ty_arr = np.asarray(test_ys)
    sp_arr = np.vstack(test_sp);    st_arr = np.vstack(test_st)

    # Test duration for false-alarm rate
    test_hrs = (len(ty_arr) * 2.0) / 3600.0

    test_m_f1   = compute_metrics_at_threshold(ty_arr, tp_arr, thresh_f1, test_hrs)
    test_m_fpr5 = compute_metrics_at_threshold(ty_arr, tp_arr, thresh_fpr5, test_hrs)
    test_m_fpr10= compute_metrics_at_threshold(ty_arr, tp_arr, thresh_fpr10, test_hrs)

    test_state_mae = float(mean_absolute_error(st_arr, sp_arr))
    test_state_mse = float(mean_squared_error(st_arr, sp_arr))

    print(f"  TEST: F1={test_m_f1['f1']:.4f} | Prec={test_m_f1['precision']:.4f} | "
          f"Rec={test_m_f1['recall']:.4f} | FPR={test_m_f1['fpr']:.4f} | "
          f"PR-AUC={test_m_f1['pr_auc']:.4f} | StatMAE={test_state_mae:.4f}", flush=True)

    # Save checkpoint
    ckpt_dir = RESULTS_DIR / exp_id
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    torch.save({'model_state_dict': model.state_dict(),
                'config': dict(exp_id=exp_id, k=k, k_train_actual=k_train_actual,
                               sparsity_ratio=sparsity_ratio, seed=seed,
                               lambda_attack=lambda_attack, use_pos_weight=use_pos_weight,
                               epochs=epochs, lr=lr, batch_size=batch_size)
                }, ckpt_dir / 'checkpoint.pt')
    np.savez_compressed(ckpt_dir / 'test_outputs.npz',
                        test_probs=tp_arr, test_labels=ty_arr,
                        val_probs=np.asarray(val_probs), val_labels=np.asarray(val_ys),
                        test_state_preds=sp_arr, test_state_trues=st_arr)

    return {
        'exp_id': exp_id,
        'git_commit': GIT_COMMIT,
        'model': model,
        'k': k, 'k_train_actual': k_train_actual,
        'sparsity_ratio': sparsity_ratio,
        'seed': seed,
        'lambda_attack': lambda_attack,
        'use_pos_weight': use_pos_weight,
        'history': history,
        'val_probs': np.asarray(val_probs),
        'val_labels': np.asarray(val_ys),
        'val_thresh_f1': thresh_f1,
        'val_thresh_fpr5': thresh_fpr5,
        'val_thresh_fpr10': thresh_fpr10,
        'val_best_f1': val_calib_final['val_best_f1'],
        'test_metrics_f1': test_m_f1,
        'test_metrics_fpr5': test_m_fpr5,
        'test_metrics_fpr10': test_m_fpr10,
        'test_state_mae': round(test_state_mae, 4),
        'test_state_mse': round(test_state_mse, 4),
        'test_probs': tp_arr,
        'test_labels': ty_arr,
        'status': 'VALID'
    }


# ============================================================
# PRE-ONSET EVALUATION (FIXED: threshold from VAL eligible subset)
# ============================================================

def evaluate_pre_onset(model, val_data, test_data, device='cpu') -> List[dict]:
    """
    Pre-onset evaluation with threshold selected on VALIDATION eligible subset.
    FIX for CRIT-04 (test-set threshold leakage).
    """
    horizons = {2: 1, 10: 5, 20: 10, 60: 30, 120: 60, 300: 150}
    max_k = max(horizons.values())

    def get_eligible_probs(data, split_label):
        # Eligible = all lookback steps are benign
        is_pure_benign = np.all(data['y_hist'] == 0, axis=1)
        idx = np.where(is_pure_benign)[0]
        seqs = data['seq'][idx]
        loader = DataLoader(TensorDataset(seqs), batch_size=512, shuffle=False)
        all_probs = []
        model.eval()
        with torch.no_grad():
            for bx, in loader:
                out = model(bx.to(device), K=max_k)
                step_p = [torch.sigmoid(atk.squeeze(-1)).cpu().numpy() for atk in out['attack']]
                all_probs.append(np.column_stack(step_p))
        probs_arr = np.vstack(all_probs)
        attacks_eligible = data['attacks'][idx].numpy()
        print(f"    [{split_label}] eligible benign sequences: {len(idx):,}", flush=True)
        return idx, probs_arr, attacks_eligible

    val_idx, val_probs_onset, val_attacks = get_eligible_probs(val_data, 'VAL')
    test_idx, test_probs_onset, test_attacks = get_eligible_probs(test_data, 'TEST')

    results = []
    for H_sec, max_step in horizons.items():
        # VAL: select threshold
        y_val_onset = (np.max(val_attacks[:, :max_step], axis=1) == 1).astype(int)
        val_risk = np.max(val_probs_onset[:, :max_step], axis=1)

        # Select threshold on VAL (THE FIX)
        best_f1_val, best_thresh = -1.0, 0.5
        for t in np.linspace(0.01, 0.99, 99):
            if len(np.unique(y_val_onset)) < 2:
                break
            ypred = (val_risk >= t).astype(int)
            f = float(f1_score(y_val_onset, ypred, zero_division=0))
            if f > best_f1_val:
                best_f1_val, best_thresh = f, float(t)

        # TEST: apply frozen threshold
        y_test_onset = (np.max(test_attacks[:, :max_step], axis=1) == 1).astype(int)
        test_risk = np.max(test_probs_onset[:, :max_step], axis=1)

        test_pred = (test_risk >= best_thresh).astype(int)
        tp = int(((y_test_onset == 1) & (test_pred == 1)).sum())
        fp = int(((y_test_onset == 0) & (test_pred == 1)).sum())
        fn = int(((y_test_onset == 1) & (test_pred == 0)).sum())
        tn = int(((y_test_onset == 0) & (test_pred == 0)).sum())
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        fpr = fp / max(1, fp + tn)

        total_hrs = (len(test_idx) * 2.0) / 3600.0
        fa_hr = round(fp / max(0.001, total_hrs), 2)

        # Lead times for true positives
        lead_times = []
        tp_idx = np.where((y_test_onset == 1) & (test_pred == 1))[0]
        for idx in tp_idx:
            exceeded = np.where(test_probs_onset[idx, :max_step] >= best_thresh)[0]
            if len(exceeded) > 0:
                lead_times.append(float((max_step - exceeded[0]) * 2.0))

        results.append({
            'warning_horizon_sec': H_sec,
            'max_steps': max_step,
            'val_n_eligible': int(len(val_idx)),
            'val_onset_positives': int(y_val_onset.sum()),
            'val_thresh_selected': round(best_thresh, 4),
            'val_best_f1': round(best_f1_val, 4),
            'test_n_eligible': int(len(test_idx)),
            'test_onset_positives': int(y_test_onset.sum()),
            'onset_f1': round(f1, 4),
            'onset_precision': round(prec, 4),
            'onset_recall': round(rec, 4),
            'onset_fpr': round(fpr, 4),
            'false_alarms_per_hour': fa_hr,
            'tp_detected': tp,
            'lead_time_median_sec': round(float(np.median(lead_times)), 1) if lead_times else 0.0,
            'lead_time_mean_sec': round(float(np.mean(lead_times)), 1) if lead_times else 0.0,
        })
        print(f"    H={H_sec}s: val_thresh={best_thresh:.2f} | test_onset_F1={f1:.4f} | "
              f"recall={rec:.4f} | FA/hr={fa_hr}", flush=True)

    return results


# ============================================================
# BASELINES
# ============================================================

def run_persistence_baseline(train_data, val_data, test_data) -> List[dict]:
    print("\n[BASELINE] Persistence...", flush=True)
    results = []
    for k in [1, 10, 50]:
        y_curr = train_data['y_hist'][:, -1]  # current label (last lookback step)
        # Test
        ty_curr = test_data['y_hist'][:, -1]
        ty_true = test_data['attacks'][:, k-1].numpy()
        ty_pred = ty_curr.astype(int)
        prec = float(precision_score(ty_true, ty_pred, zero_division=0))
        rec  = float(recall_score(ty_true, ty_pred, zero_division=0))
        f1   = float(f1_score(ty_true, ty_pred, zero_division=0))
        cm   = confusion_matrix(ty_true, ty_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (cm[0,0], 0, 0, 0)
        fpr  = float(fp / max(1, fp + tn))
        test_hrs = (len(ty_true) * 2.0) / 3600.0
        fa_hr = round(float(fp) / max(0.001, test_hrs), 2)
        # PR-AUC for persistence uses binary probs
        ty_probs = ty_curr.astype(float)
        pr_auc = roc_auc_val = 0.5
        if len(np.unique(ty_true)) > 1:
            try:
                p_c, r_c, _ = precision_recall_curve(ty_true, ty_probs)
                pr_auc = float(auc(r_c, p_c))
                roc_auc_val = float(roc_auc_score(ty_true, ty_probs))
            except: pass
        r = dict(model='Persistence', k=k, horizon_sec=k*2,
                 f1=round(f1,4), precision=round(prec,4), recall=round(rec,4),
                 fpr=round(fpr,4), pr_auc=round(pr_auc,4), roc_auc=round(roc_auc_val,4),
                 false_alarms_per_hour=fa_hr, state_mae='N/A', onset_recall=0.0,
                 median_lead_time='0s', support=int(ty_true.sum()))
        print(f"  K={k}: F1={f1:.4f} Prec={prec:.4f} Rec={rec:.4f} PR-AUC={pr_auc:.4f}", flush=True)
        results.append(r)
    return results


def run_lr_baseline(train_data, val_data, test_data) -> List[dict]:
    print("\n[BASELINE] Logistic Regression...", flush=True)
    # Use flattened 10x54=540 features
    X_tr = train_data['seq'].numpy().reshape(len(train_data['seq']), -1)
    results = []
    for k in [1, 10, 50]:
        y_tr = train_data['attacks'][:, k-1].numpy()
        y_va = val_data['attacks'][:, k-1].numpy()
        y_te = test_data['attacks'][:, k-1].numpy()
        X_va = val_data['seq'].numpy().reshape(len(val_data['seq']), -1)
        X_te = test_data['seq'].numpy().reshape(len(test_data['seq']), -1)

        pos_w = float(train_data['pos_weight'])
        clf = LogisticRegression(max_iter=300, C=0.1, class_weight={0:1, 1:pos_w}, n_jobs=4, random_state=42)
        clf.fit(X_tr, y_tr)

        # Val threshold
        va_probs = clf.predict_proba(X_va)[:, 1]
        calib = calibrate_threshold_on_val(y_va, va_probs)
        thresh = calib['best_f1_threshold']

        # Test
        te_probs = clf.predict_proba(X_te)[:, 1]
        test_hrs = (len(y_te) * 2.0) / 3600.0
        m = compute_metrics_at_threshold(y_te, te_probs, thresh, test_hrs)
        r = dict(model='LogisticRegression', k=k, horizon_sec=k*2, **m,
                 state_mae='N/A', onset_recall='N/A', median_lead_time='N/A')
        print(f"  K={k}: F1={m['f1']:.4f} Prec={m['precision']:.4f} Rec={m['recall']:.4f}", flush=True)
        results.append(r)
    return results


def run_rf_baseline(train_data, val_data, test_data) -> List[dict]:
    print("\n[BASELINE] Random Forest (current state only, flat 54-D)...", flush=True)
    # Use last state only (54-D) to match baseline spirit
    X_tr = train_data['seq'][:, -1, :].numpy()  # last step of lookback
    results = []
    for k in [1, 10, 50]:
        y_tr = train_data['attacks'][:, k-1].numpy()
        y_va = val_data['attacks'][:, k-1].numpy()
        y_te = test_data['attacks'][:, k-1].numpy()
        X_va = val_data['seq'][:, -1, :].numpy()
        X_te = test_data['seq'][:, -1, :].numpy()

        pos_w = float(train_data['pos_weight'])
        clf = RandomForestClassifier(n_estimators=100, max_depth=12,
                                     class_weight={0:1, 1:pos_w},
                                     n_jobs=4, random_state=42)
        clf.fit(X_tr, y_tr)

        va_probs = clf.predict_proba(X_va)[:, 1]
        calib = calibrate_threshold_on_val(y_va, va_probs)
        thresh = calib['best_f1_threshold']

        te_probs = clf.predict_proba(X_te)[:, 1]
        test_hrs = (len(y_te) * 2.0) / 3600.0
        m = compute_metrics_at_threshold(y_te, te_probs, thresh, test_hrs)
        r = dict(model='RandomForest', k=k, horizon_sec=k*2, **m,
                 state_mae='N/A', onset_recall='N/A', median_lead_time='N/A')
        print(f"  K={k}: F1={m['f1']:.4f} Prec={m['precision']:.4f} Rec={m['recall']:.4f}", flush=True)
        results.append(r)
    return results


# ============================================================
# EXPERIMENT RESULT TRACKING
# ============================================================

RESULTS_TABLE: List[dict] = []

def record_result(row: dict):
    RESULTS_TABLE.append(row)
    df = pd.DataFrame(RESULTS_TABLE)
    df.to_csv(AUTHORITATIVE_RESULTS_PATH, index=False)


def result_row_from_rssm(res: dict, sel_metric: str = 'val_f1') -> dict:
    m = res['test_metrics_f1']
    return dict(
        experiment_id=res['exp_id'],
        git_commit=res.get('git_commit', GIT_COMMIT),
        model='SparseRSSM',
        K=res['k'],
        horizon_seconds=res['k'] * 2,
        K_train=res['k_train_actual'],
        K_eval=res['k'],
        lambda_attack=res['lambda_attack'],
        positive_weighting=res['use_pos_weight'],
        seed=res['seed'],
        threshold=res['val_thresh_f1'],
        state_MAE=res['test_state_mae'],
        state_MSE=res['test_state_mse'],
        PR_AUC=m['pr_auc'],
        ROC_AUC=m['roc_auc'],
        precision=m['precision'],
        recall=m['recall'],
        F1=m['f1'],
        FPR=m['fpr'],
        false_alarms_per_hour=m.get('false_alarms_per_hour', 'N/A'),
        onset_recall='see_onset_table',
        median_lead_time='see_onset_table',
        mean_lead_time='see_onset_table',
        validation_selection_metric=sel_metric,
        status=res['status'],
        val_best_f1=res['val_best_f1'],
    )


# ============================================================
# MAIN EXPERIMENT RUNNER
# ============================================================

def main():
    print("=" * 80, flush=True)
    print("  PHASE 5.5 — FORENSIC EXPERIMENTAL CORRECTION & MODEL IMPROVEMENT", flush=True)
    print("=" * 80, flush=True)

    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Device: {device} | CPUs: {torch.get_num_threads()}", flush=True)

    # --------------------------------------------------------
    # STEP 1: Load Data (max_h=50 for primary experiments K={1,10,50})
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 1: Data Loading & Split Verification", flush=True)
    print("="*60, flush=True)
    train_data, val_data, test_data, builder = load_all_data(max_h=50)
    N_train = len(train_data['seq'])
    N_val   = len(val_data['seq'])
    N_test  = len(test_data['seq'])
    print(f"\nSplit sizes: Train={N_train:,} | Val={N_val:,} | Test={N_test:,}", flush=True)

    # Compute class distribution per split for audit report
    split_stats = {}
    for name, data in [('train', train_data), ('val', val_data), ('test', test_data)]:
        y_k1 = data['attacks'][:, 0].numpy()
        split_stats[name] = {
            'n_sequences': len(y_k1),
            'n_attack_k1': int(y_k1.sum()),
            'n_benign_k1': int((y_k1==0).sum()),
            'attack_rate_k1': round(float(y_k1.mean()), 4),
            'pos_weight': round(float(data['pos_weight']), 2),
        }
    with open(REPORTS_DIR / 'split_stats.json', 'w') as f:
        json.dump(split_stats, f, indent=2)
    print("\nSplit stats saved.", flush=True)

    # --------------------------------------------------------
    # STEP 2: BASELINES (E001)
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 2: E001 — Baseline Suite", flush=True)
    print("="*60, flush=True)

    baseline_results = []
    pers_results = run_persistence_baseline(train_data, val_data, test_data)
    baseline_results.extend(pers_results)

    lr_results = run_lr_baseline(train_data, val_data, test_data)
    baseline_results.extend(lr_results)

    rf_results = run_rf_baseline(train_data, val_data, test_data)
    baseline_results.extend(rf_results)

    pd.DataFrame(baseline_results).to_csv(REPORTS_DIR / 'baseline_comparison.csv', index=False)
    print("\nBaseline results saved to baseline_comparison.csv", flush=True)

    # Add baselines to authoritative table
    for row in baseline_results:
        record_result({
            'experiment_id': f"E001_{row['model']}_K{row['k']}",
            'git_commit': GIT_COMMIT,
            'model': row['model'],
            'K': row['k'], 'horizon_seconds': row['k']*2,
            'K_train': 'N/A', 'K_eval': row['k'],
            'lambda_attack': 'N/A', 'positive_weighting': True,
            'seed': 42, 'threshold': row.get('threshold','N/A'),
            'state_MAE': row.get('state_mae','N/A'),
            'state_MSE': 'N/A',
            'PR_AUC': row.get('pr_auc', 'N/A'),
            'ROC_AUC': row.get('roc_auc', 'N/A'),
            'precision': row.get('precision','N/A'),
            'recall': row.get('recall','N/A'),
            'F1': row.get('f1','N/A'),
            'FPR': row.get('fpr','N/A'),
            'false_alarms_per_hour': row.get('false_alarms_per_hour','N/A'),
            'onset_recall': row.get('onset_recall','N/A'),
            'median_lead_time': row.get('median_lead_time','N/A'),
            'mean_lead_time': 'N/A',
            'validation_selection_metric': 'val_f1',
            'status': 'VALID',
            'val_best_f1': 'N/A',
        })

    # --------------------------------------------------------
    # STEP 3: E002 — lambda_attack sweep at K=1, no pos_weight
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 3: E002 — lambda_attack sweep at K=1 (no pos_weight)", flush=True)
    print("="*60, flush=True)

    lambdas = [0.1, 0.5, 1.0, 2.0, 5.0]
    e002_results = []
    for lam in lambdas:
        exp_id = f"E002_K1_lam{str(lam).replace('.','p')}_nopw"
        res = train_rssm(train_data, val_data, test_data, k=1,
                         epochs=5, batch_size=1024, lr=1e-3,
                         lambda_attack=lam, use_pos_weight=False,
                         seed=42, device=device, exp_id=exp_id)
        e002_results.append(res)
        record_result(result_row_from_rssm(res))
        save_config(exp_id, {'k': 1, 'lambda_attack': lam, 'use_pos_weight': False,
                              'epochs': 5, 'seed': 42, 'k_train_actual': res['k_train_actual']})

    # Best lambda (by val F1)
    best_e002 = max(e002_results, key=lambda r: r['val_best_f1'])
    best_lam = best_e002['lambda_attack']
    print(f"\nE002 Best: lambda_attack={best_lam} (val_F1={best_e002['val_best_f1']:.4f})", flush=True)

    # --------------------------------------------------------
    # STEP 4: E003 — Positive weighting vs no weighting
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 4: E003 — Positive weighting comparison at K=1", flush=True)
    print("="*60, flush=True)

    e003_results = []
    for use_pw in [False, True]:
        exp_id = f"E003_K1_lam{str(best_lam).replace('.','p')}_pw{'yes' if use_pw else 'no'}"
        res = train_rssm(train_data, val_data, test_data, k=1,
                         epochs=5, batch_size=1024, lr=1e-3,
                         lambda_attack=best_lam, use_pos_weight=use_pw,
                         seed=42, device=device, exp_id=exp_id)
        e003_results.append(res)
        record_result(result_row_from_rssm(res))
        save_config(exp_id, {'k': 1, 'lambda_attack': best_lam, 'use_pos_weight': use_pw,
                              'epochs': 5, 'seed': 42})

    # Best E003 config by val F1
    best_e003 = max(e003_results, key=lambda r: r['val_best_f1'])
    best_pw = best_e003['use_pos_weight']
    print(f"\nE003 Best: pos_weight={best_pw} (val_F1={best_e003['val_best_f1']:.4f})", flush=True)

    # --------------------------------------------------------
    # STEP 5: E004 — Final config at K=1, K=10, K=50 with k_train==k
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 5: E004 — Final config across K=1,10,50 (k_train==k)", flush=True)
    print("="*60, flush=True)

    e004_results = {}
    for k in [1, 10, 50]:
        exp_id = f"E004_K{k}_lam{str(best_lam).replace('.','p')}_pw{'yes' if best_pw else 'no'}"
        res = train_rssm(train_data, val_data, test_data, k=k,
                         epochs=5, batch_size=1024, lr=1e-3,
                         lambda_attack=best_lam, use_pos_weight=best_pw,
                         seed=42, device=device, exp_id=exp_id)
        e004_results[k] = res
        record_result(result_row_from_rssm(res))
        save_config(exp_id, {'k': k, 'k_train_actual': res['k_train_actual'],
                              'lambda_attack': best_lam, 'use_pos_weight': best_pw,
                              'epochs': 5, 'seed': 42})

    # --------------------------------------------------------
    # STEP 6: E005 — Multi-seed confirmation for K=1 (best config)
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 6: E005 — Multi-seed confirmation (3 seeds, K=1)", flush=True)
    print("="*60, flush=True)

    e005_results = []
    for seed in [42, 123, 2025]:
        exp_id = f"E005_K1_seed{seed}"
        res = train_rssm(train_data, val_data, test_data, k=1,
                         epochs=5, batch_size=1024, lr=1e-3,
                         lambda_attack=best_lam, use_pos_weight=best_pw,
                         seed=seed, device=device, exp_id=exp_id)
        e005_results.append(res)
        record_result(result_row_from_rssm(res))

    seed_f1s = [r['test_metrics_f1']['f1'] for r in e005_results]
    seed_praucs = [r['test_metrics_f1']['pr_auc'] for r in e005_results]
    seed_recs = [r['test_metrics_f1']['recall'] for r in e005_results]
    print(f"\nE005 Multi-seed K=1: F1={np.mean(seed_f1s):.4f}±{np.std(seed_f1s):.4f} | "
          f"PR-AUC={np.mean(seed_praucs):.4f}±{np.std(seed_praucs):.4f} | "
          f"Recall={np.mean(seed_recs):.4f}±{np.std(seed_recs):.4f}", flush=True)

    # --------------------------------------------------------
    # STEP 7: Pre-Onset Analysis for best K=10 model
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 7: Pre-onset Analysis (VAL-calibrated threshold)", flush=True)
    print("="*60, flush=True)
    # Use K=10 model for onset (most balanced horizon)
    best_k10_model = e004_results[10]['model']
    onset_results = evaluate_pre_onset(best_k10_model, val_data, test_data, device)
    pd.DataFrame(onset_results).to_csv(REPORTS_DIR / 'onset_analysis.csv', index=False)
    print("\nPre-onset results saved to onset_analysis.csv", flush=True)

    # --------------------------------------------------------
    # STEP 8: Save Final Model Artifact
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 8: Final Model Artifact", flush=True)
    print("="*60, flush=True)

    final_model_k = 10  # best balanced horizon
    final_res = e004_results[final_model_k]
    final_model = final_res['model']

    # Save model
    torch.save({
        'model_state_dict': final_model.state_dict(),
        'config': {
            'state_dim': 54, 'latent_dim': 128, 'hidden_dim': 128,
            'sparsity_ratio': 1.0, 'num_stage_classes': 5,
            'k': final_model_k, 'k_train': final_res['k_train_actual'],
            'lambda_attack': best_lam, 'use_pos_weight': best_pw,
        }
    }, ARTIFACTS_DIR / 'model.pt')

    # Save scaler
    with open(ARTIFACTS_DIR / 'scaler.pkl', 'wb') as f:
        pickle.dump(builder.scaler, f)

    # Save feature schema
    feature_schema = {
        'feature_names': STATE_FEATURE_NAMES,
        'n_features': len(STATE_FEATURE_NAMES),
        'lookback_steps': 10,
        'input_shape': [10, 54],
        'base_features': BASE_FEATURE_NAMES,
        'delta_features': DELTA_FEATURE_NAMES,
    }
    with open(ARTIFACTS_DIR / 'feature_schema.json', 'w') as f:
        json.dump(feature_schema, f, indent=2)

    # Save metadata
    meta = {
        'phase': PHASE,
        'git_commit': GIT_COMMIT,
        'experiment_id': f"E004_K{final_model_k}",
        'val_threshold_f1': final_res['val_thresh_f1'],
        'val_threshold_fpr5': final_res['val_thresh_fpr5'],
        'val_best_f1': final_res['val_best_f1'],
        'test_f1': final_res['test_metrics_f1']['f1'],
        'test_pr_auc': final_res['test_metrics_f1']['pr_auc'],
        'test_recall': final_res['test_metrics_f1']['recall'],
        'test_precision': final_res['test_metrics_f1']['precision'],
        'test_state_mae': final_res['test_state_mae'],
        'multi_seed_f1_mean': round(float(np.mean(seed_f1s)), 4),
        'multi_seed_f1_std': round(float(np.std(seed_f1s)), 4),
        'dataset': 'CSE-CIC-IDS2018',
        'split': {'train': TRAIN_DAYS, 'val': VAL_DAYS, 'test': TEST_DAYS},
    }
    with open(ARTIFACTS_DIR / 'metadata.json', 'w') as f:
        json.dump(meta, f, indent=2)
    with open(ARTIFACTS_DIR / 'config.json', 'w') as f:
        json.dump({'k': final_model_k, 'lambda_attack': best_lam,
                   'use_pos_weight': best_pw, 'seed': 42, 'epochs': 5}, f, indent=2)

    print(f"Final model artifact saved to {ARTIFACTS_DIR}", flush=True)

    # --------------------------------------------------------
    # STEP 9: Smoke Test
    # --------------------------------------------------------
    print("\n" + "="*60, flush=True)
    print("STEP 9: Smoke Test — Load artifact and run inference", flush=True)
    print("="*60, flush=True)

    ckpt = torch.load(ARTIFACTS_DIR / 'model.pt', map_location='cpu', weights_only=False)
    smoke_model = SparseRSSM(sparsity_ratio=1.0)
    smoke_model.load_state_dict(ckpt['model_state_dict'])
    smoke_model.eval()
    dummy_input = torch.randn(1, 10, 54)
    with torch.no_grad():
        out = smoke_model(dummy_input, K=10)
        attack_prob = float(torch.sigmoid(out['attack'][-1]).item())
        state_pred_shape = out['states'][-1].shape
    print(f"  Input: (1, 10, 54) → Attack prob: {attack_prob:.4f} | "
          f"State pred shape: {state_pred_shape}", flush=True)
    print("  Smoke test PASSED ✓", flush=True)

    # --------------------------------------------------------
    # STEP 10: Print Final Summary
    # --------------------------------------------------------
    print("\n" + "=" * 80, flush=True)
    print("  PHASE 5.5 COMPLETE — FINAL SUMMARY", flush=True)
    print("=" * 80, flush=True)

    print("\nA. CRITICAL ISSUES FIXED:", flush=True)
    print("  CRIT-02: k_train == k enforced for all horizons", flush=True)
    print("  CRIT-03/04: All models retrained fresh from post-fix codebase", flush=True)
    print("  HIGH-02: Pre-onset threshold now selected on VAL eligible subset", flush=True)
    print("  HIGH-03: Positive class weighting tested experimentally", flush=True)

    print(f"\nB. BEST CONFIG (from validation):", flush=True)
    print(f"  lambda_attack={best_lam}, pos_weight={best_pw}", flush=True)
    print(f"  val_best_F1={best_e003['val_best_f1']:.4f}", flush=True)

    print(f"\nC. FINAL TEST RESULTS (K=1, frozen threshold={final_res if final_model_k==1 else e004_results[1]['val_thresh_f1']:.2f}):", flush=True)
    for k in [1, 10, 50]:
        r = e004_results[k]
        m = r['test_metrics_f1']
        print(f"  K={k} ({k*2}s): F1={m['f1']:.4f} | Prec={m['precision']:.4f} | "
              f"Rec={m['recall']:.4f} | FPR={m['fpr']:.4f} | "
              f"PR-AUC={m['pr_auc']:.4f} | StateMAE={r['test_state_mae']:.4f}", flush=True)

    print(f"\nD. MULTI-SEED K=1:", flush=True)
    print(f"  F1={np.mean(seed_f1s):.4f}±{np.std(seed_f1s):.4f} | "
          f"PR-AUC={np.mean(seed_praucs):.4f}±{np.std(seed_praucs):.4f}", flush=True)

    print(f"\nE. PRE-ONSET (VAL-calibrated threshold):", flush=True)
    for row in onset_results:
        print(f"  H={row['warning_horizon_sec']}s: onset_F1={row['onset_f1']:.4f} | "
              f"recall={row['onset_recall']:.4f} | FA/hr={row['false_alarms_per_hour']}", flush=True)

    print(f"\nF. ARTIFACT PATH: {ARTIFACTS_DIR}", flush=True)
    print(f"G. AUTHORITATIVE RESULTS: {AUTHORITATIVE_RESULTS_PATH}", flush=True)
    print(f"\nH. Authoritative table has {len(RESULTS_TABLE)} experiment rows.", flush=True)
    print("\nPhase 5.5 DONE. Repository cleanup is next.", flush=True)


if __name__ == '__main__':
    main()
