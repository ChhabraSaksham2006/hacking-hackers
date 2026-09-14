"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Script: scripts/audit/run_phase4_5_forensics.py

Executes all empirical computations for Phase 4.5 Forensic Audit:
1. Persistence & Transition Probabilities P(y_{t+K}|y_t)
2. Attack Run Length Distributions & Episode Counts
3. Positive Window Composition (Continuation vs Onset)
4. Attack Onset Identification & Pre-Onset Baseline Evaluation
5. Stride / Overlap Subsampling Simulation (10/2, 10/5, 10/10)
6. Feature Group Error Decomposition for Continuous State Forecasting
7. Delta Feature Correlation & Contribution
8. OOD Attack Family Analysis (Botnet vs Infiltration)
"""

import os
import sys
import glob
import math
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.temporal.state_aggregator import (
    STATE_FEATURE_NAMES,
    BASE_FEATURE_NAMES,
    DELTA_FEATURE_NAMES,
    ATTACK_FAMILY_MAP,
    FAMILY_TO_IDX
)
from src.temporal.dataset_builder import (
    TemporalSequenceBuilder,
    TRAIN_DAYS,
    VAL_DAYS,
    TEST_DAYS
)
from src.evaluation.metrics import (
    compute_binary_metrics,
    compute_state_forecasting_metrics
)

PROCESSED_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\processed\temporal_states"
OUTPUT_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\reports\phase_4_5"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HORIZONS = [1, 3, 5, 10]


def load_all_days() -> Dict[str, pd.DataFrame]:
    day_files = {
        # Train
        '2018-02-14': 'Wednesday-14-02-2018_states.parquet',
        '2018-02-15': 'Thursday-15-02-2018_states.parquet',
        '2018-02-16': 'Friday-16-02-2018_states.parquet',
        '2018-02-21': 'Wednesday-21-02-2018_states.parquet',
        '2018-02-22': 'Thursday-22-02-2018_states.parquet',
        # Val
        '2018-02-23': 'Friday-23-02-2018_states.parquet',
        # Test
        '2018-02-28': 'Wednesday-28-02-2018_states.parquet',
        '2018-03-01': 'Thursday-01-03-2018_states.parquet',
        '2018-03-02': 'Friday-02-03-2018_states.parquet',
    }
    dfs = {}
    for day_label, fname in day_files.items():
        p = os.path.join(PROCESSED_DIR, fname)
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing {p}")
        df = pd.read_parquet(p)
        dfs[day_label] = df
    return dfs


def analyze_attack_runs(dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Calculates run length statistics of contiguous attack and benign episodes."""
    records = []
    for day, df in dfs.items():
        is_atk = df['is_attack'].values
        # Compute runs
        runs = []
        current_val = is_atk[0]
        current_len = 1
        for val in is_atk[1:]:
            if val == current_val:
                current_len += 1
            else:
                runs.append((current_val, current_len))
                current_val = val
                current_len = 1
        runs.append((current_val, current_len))

        atk_runs = [length for val, length in runs if val == 1]
        ben_runs = [length for val, length in runs if val == 0]

        atk_windows = sum(atk_runs)
        ben_windows = sum(ben_runs)
        total_w = len(df)

        records.append({
            'day': day,
            'session': df['session_id'].iloc[0],
            'dominant_family': df[df['is_attack'] == 1]['dominant_attack_family'].mode()[0] if atk_windows > 0 else 'Benign',
            'total_windows': total_w,
            'attack_windows': atk_windows,
            'attack_pct': round(atk_windows / total_w * 100, 2),
            'num_attack_episodes': len(atk_runs),
            'atk_run_min_w': min(atk_runs) if atk_runs else 0,
            'atk_run_mean_w': round(np.mean(atk_runs), 1) if atk_runs else 0,
            'atk_run_median_w': round(np.median(atk_runs), 1) if atk_runs else 0,
            'atk_run_max_w': max(atk_runs) if atk_runs else 0,
            'atk_run_max_sec': max(atk_runs) * 2 if atk_runs else 0,
            'num_benign_episodes': len(ben_runs),
            'ben_run_mean_w': round(np.mean(ben_runs), 1) if ben_runs else 0,
            'ben_run_max_w': max(ben_runs) if ben_runs else 0,
        })
    return pd.DataFrame(records)


def analyze_persistence_and_transitions(dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Computes exact conditional transition probabilities:
    P(y_{t+K}=1 | y_t=1) [Continuation]
    P(y_{t+K}=1 | y_t=0) [Onset]
    P(y_{t+K}=0 | y_t=0) [Benign Stability]
    P(y_{t+K}=0 | y_t=1) [Cessation]
    and positive target window breakdown (% continuation vs % onset)
    """
    records = []
    splits = {
        'TRAIN': ['2018-02-14', '2018-02-15', '2018-02-16', '2018-02-21', '2018-02-22'],
        'VAL': ['2018-02-23'],
        'TEST': ['2018-02-28', '2018-03-01', '2018-03-02'],
        'ALL': list(dfs.keys())
    }

    for split_name, days in splits.items():
        for k in HORIZONS:
            y_t_list = []
            y_tk_list = []
            for d in days:
                df = dfs[d]
                is_atk = df['is_attack'].values
                if len(is_atk) > k:
                    y_t = is_atk[:-k]
                    y_tk = is_atk[k:]
                    y_t_list.append(y_t)
                    y_tk_list.append(y_tk)

            all_y_t = np.concatenate(y_t_list)
            all_y_tk = np.concatenate(y_tk_list)

            # Confusion matrix for persistence baseline (predicts y_hat = y_t)
            # TP: y_t=1, y_tk=1
            # FP: y_t=1, y_tk=0
            # FN: y_t=0, y_tk=1
            # TN: y_t=0, y_tk=0
            tp = int(np.sum((all_y_t == 1) & (all_y_tk == 1)))
            fp = int(np.sum((all_y_t == 1) & (all_y_tk == 0)))
            fn = int(np.sum((all_y_t == 0) & (all_y_tk == 1)))
            tn = int(np.sum((all_y_t == 0) & (all_y_tk == 0)))

            total_pos_target = tp + fn  # total actual future attacks
            total_current_atk = tp + fp
            total_current_ben = tn + fn

            # Probabilities
            p_atk_given_atk = tp / total_current_atk if total_current_atk > 0 else 0.0
            p_atk_given_ben = fn / total_current_ben if total_current_ben > 0 else 0.0
            p_ben_given_ben = tn / total_current_ben if total_current_ben > 0 else 0.0
            p_ben_given_atk = fp / total_current_atk if total_current_atk > 0 else 0.0

            # Percentage of future attacks that are continuations vs onsets
            pct_continuation = (tp / total_pos_target * 100) if total_pos_target > 0 else 0.0
            pct_onset = (fn / total_pos_target * 100) if total_pos_target > 0 else 0.0

            # Persistence metrics
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            acc = (tp + tn) / len(all_y_t)

            records.append({
                'split': split_name,
                'horizon_k': k,
                'lead_sec': k * 2.0,
                'total_windows': len(all_y_t),
                'future_attack_windows': total_pos_target,
                'P(y_future=1 | y_curr=1) [Continuation]': round(p_atk_given_atk, 6),
                'P(y_future=1 | y_curr=0) [Onset]': round(p_atk_given_ben, 6),
                'P(y_future=0 | y_curr=0) [Benign Stability]': round(p_ben_given_ben, 6),
                'P(y_future=0 | y_curr=1) [Cessation]': round(p_ben_given_atk, 6),
                'pct_future_is_continuation': round(pct_continuation, 2),
                'pct_future_is_onset': round(pct_onset, 2),
                'TP': tp,
                'FP': fp,
                'FN': fn,
                'TN': tn,
                'persistence_precision': round(prec, 6),
                'persistence_recall': round(rec, 6),
                'persistence_f1': round(f1, 6),
                'persistence_accuracy': round(acc, 6),
            })
    return pd.DataFrame(records)


def analyze_pre_onset_evaluation(dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Evaluates forecasting models strictly on pre-onset windows:
    History is purely benign (y_{t-P+1:t} = 0), and target is attack onset in future horizon.
    """
    lookback = 10
    splits = {
        'VAL': ['2018-02-23'],
        'TEST_INFILTRATION': ['2018-02-28', '2018-03-01'],
        'TEST_BOTNET': ['2018-03-02'],
        'TEST_ALL': ['2018-02-28', '2018-03-01', '2018-03-02'],
    }

    records = []
    for split_label, days in splits.items():
        for k in HORIZONS:
            total_pre_onset_samples = 0
            positive_onset_targets = 0
            negative_onset_targets = 0

            for d in days:
                df = dfs[d]
                is_atk = df['is_attack'].values
                n_w = len(is_atk)
                for t in range(lookback - 1, n_w - k):
                    # Check if entire lookback history is benign
                    history_is_benign = np.all(is_atk[t - lookback + 1 : t + 1] == 0)
                    if history_is_benign:
                        total_pre_onset_samples += 1
                        target_val = is_atk[t + k]
                        if target_val == 1:
                            positive_onset_targets += 1
                        else:
                            negative_onset_targets += 1

            prevalence = (positive_onset_targets / total_pre_onset_samples * 100) if total_pre_onset_samples > 0 else 0.0

            records.append({
                'partition': split_label,
                'horizon_k': k,
                'lead_sec': k * 2.0,
                'pure_benign_history_samples': total_pre_onset_samples,
                'positive_onset_events': positive_onset_targets,
                'negative_benign_events': negative_onset_targets,
                'onset_prevalence_pct': round(prevalence, 4),
                'persistence_pred_positives': 0,
                'persistence_onset_recall': 0.0,
                'persistence_onset_precision': 0.0,
                'persistence_onset_f1': 0.0,
            })
    return pd.DataFrame(records)


def analyze_stride_subsampling(dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Simulates alternative sampling configurations:
    1. Stride = 2s (10s window, 80% overlap) -> current
    2. Stride = 4s (10s window, 60% overlap) -> subsample step 2
    3. Stride = 6s (10s window, 40% overlap) -> subsample step 3
    4. Stride = 10s (10s window, 0% overlap) -> subsample step 5
    """
    records = []
    strides = [
        ('10s_win_2s_stride_80%overlap', 1),
        ('10s_win_4s_stride_60%overlap', 2),
        ('10s_win_6s_stride_40%overlap', 3),
        ('10s_win_10s_stride_0%overlap', 5),
    ]

    test_days = ['2018-02-28', '2018-03-01', '2018-03-02']

    for name, step in strides:
        y_t_all = []
        y_next_all = []
        autocorr_feats = []

        total_windows = 0
        for d in test_days:
            df = dfs[d]
            is_atk = df['is_attack'].values[::step]
            total_windows += len(is_atk)
            if len(is_atk) > 1:
                y_t_all.append(is_atk[:-1])
                y_next_all.append(is_atk[1:])

            rates = df['byte_rate'].values[::step]
            if len(rates) > 2:
                r1 = np.corrcoef(rates[:-1], rates[1:])[0, 1]
                autocorr_feats.append(r1)

        y_t = np.concatenate(y_t_all)
        y_next = np.concatenate(y_next_all)

        tp = np.sum((y_t == 1) & (y_next == 1))
        fp = np.sum((y_t == 1) & (y_next == 0))
        fn = np.sum((y_t == 0) & (y_next == 1))
        tn = np.sum((y_t == 0) & (y_next == 0))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0

        p_atk_atk = tp / (tp + fp) if (tp + fp) > 0 else 0
        p_atk_ben = fn / (tn + fn) if (tn + fn) > 0 else 0

        records.append({
            'sampling_scheme': name,
            'step_stride_sec': step * 2.0,
            'test_windows_count': total_windows,
            'persistence_f1_step1': round(f1, 6),
            'P(y_{t+1}=1 | y_t=1)': round(p_atk_atk, 6),
            'P(y_{t+1}=1 | y_t=0)': round(p_atk_ben, 6),
            'byte_rate_lag1_autocorr': round(np.mean(autocorr_feats), 4),
            'total_onset_boundaries': int(fn),
            'total_cessation_boundaries': int(fp),
        })
    return pd.DataFrame(records)


def analyze_feature_group_errors(dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Analyzes state forecasting errors by feature groups.
    Computes baseline linear state persistence MAE.
    """
    builder = TemporalSequenceBuilder(lookback_steps=10, horizons=HORIZONS, feature_names=STATE_FEATURE_NAMES)
    train_dfs = [dfs[d] for d in ['2018-02-14', '2018-02-15', '2018-02-16', '2018-02-21', '2018-02-22']]
    test_dfs = [dfs[d] for d in ['2018-02-28', '2018-03-01', '2018-03-02']]

    builder.fit_scaler(train_dfs)
    test_trans = [builder.transform_dataframe(d) for d in test_dfs]
    test_ds = builder.build_dataset_from_sessions(test_trans)

    groups = {
        'Volume_Density': ['flow_count', 'total_ip_bytes', 'total_packets'],
        'Velocity_Rates': ['flow_rate', 'byte_rate', 'packet_rate'],
        'Protocol_Mix': ['tcp_ratio', 'udp_ratio', 'icmp_ratio'],
        'Port_Targeting': ['unique_dst_ports', 'port_concentration', 'dst_port_entropy', 'auth_port_ratio'],
        'TCP_Flags_Health': ['syn_count', 'ack_count', 'rst_count', 'fin_count', 'psh_count', 'syn_ratio', 'ack_ratio', 'rst_ratio', 'rst_to_syn_ratio', 'handshake_completion_ratio'],
        'Directionality': ['fwd_packet_ratio', 'fwd_byte_ratio', 'down_up_ratio_mean', 'down_up_ratio_std'],
        'Packet_Moments': ['pkt_len_mean', 'pkt_len_std', 'pkt_len_max', 'pkt_len_min', 'zero_payload_ratio'],
        'IAT_Lifetime': ['flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'active_connection_lifetime_mean'],
        'Velocity_Deltas': DELTA_FEATURE_NAMES
    }

    curr_states = test_ds.sequences[:, -1, :].numpy()

    records = []
    for k in HORIZONS:
        target_k = test_ds.targets_state[k].numpy()
        abs_err = np.abs(target_k - curr_states)
        sq_err = (target_k - curr_states) ** 2

        overall_mae = float(np.mean(abs_err))
        overall_rmse = float(np.sqrt(np.mean(sq_err)))

        group_maes = {}
        for gname, fnames in groups.items():
            f_indices = [STATE_FEATURE_NAMES.index(f) for f in fnames]
            group_maes[gname] = round(float(np.mean(abs_err[:, f_indices])), 4)

        rec = {
            'horizon_k': k,
            'lead_sec': k * 2.0,
            'state_persistence_mae_overall': round(overall_mae, 4),
            'state_persistence_rmse_overall': round(overall_rmse, 4),
        }
        rec.update(group_maes)
        records.append(rec)

    return pd.DataFrame(records)


def main():
    print("Loading all 9 daily state datasets...")
    dfs = load_all_days()
    print("Loaded 9 days successfully.")

    print("\n--- 1. Computing Attack Run Lengths & Episode Distributions ---")
    df_runs = analyze_attack_runs(dfs)
    df_runs.to_csv(os.path.join(OUTPUT_DIR, "01_attack_run_distributions.csv"), index=False)
    print(df_runs[['day', 'dominant_family', 'attack_pct', 'num_attack_episodes', 'atk_run_mean_w', 'atk_run_max_sec']])

    print("\n--- 2. Computing Persistence and State Transition Probabilities ---")
    df_trans = analyze_persistence_and_transitions(dfs)
    df_trans.to_csv(os.path.join(OUTPUT_DIR, "02_persistence_transition_probabilities.csv"), index=False)
    print(df_trans[df_trans['split'] == 'TEST'][['horizon_k', 'P(y_future=1 | y_curr=1) [Continuation]', 'P(y_future=1 | y_curr=0) [Onset]', 'pct_future_is_continuation', 'pct_future_is_onset', 'persistence_f1']])

    print("\n--- 3. Computing Pure Pre-Onset Evaluation ---")
    df_pre_onset = analyze_pre_onset_evaluation(dfs)
    df_pre_onset.to_csv(os.path.join(OUTPUT_DIR, "03_pre_onset_evaluation.csv"), index=False)
    print(df_pre_onset)

    print("\n--- 4. Computing Stride & Overlap Subsampling Simulation ---")
    df_stride = analyze_stride_subsampling(dfs)
    df_stride.to_csv(os.path.join(OUTPUT_DIR, "04_stride_subsampling_simulation.csv"), index=False)
    print(df_stride)

    print("\n--- 5. Computing Feature Group State Forecasting Errors ---")
    df_feats = analyze_feature_group_errors(dfs)
    df_feats.to_csv(os.path.join(OUTPUT_DIR, "05_feature_group_state_errors.csv"), index=False)
    print(df_feats)

    print(f"\nAll forensic CSVs generated in {OUTPUT_DIR}")


if __name__ == '__main__':
    main()
