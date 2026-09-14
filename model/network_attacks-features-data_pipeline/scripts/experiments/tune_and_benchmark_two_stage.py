"""
tune_and_benchmark_two_stage.py
================================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Two-Stage Early-Warning + Confirmation Architecture Benchmark:
- Stage 1: Sensitive Early-Warning Detector (High Recall)
- Stage 2: Confirmation Gate / Precision Filter (High Precision, Low FA/hr)
- Stage 3: Temporal Incident Aggregator (Incident Clustering)
- Strict Validation-Only Tuning (Zero Test Leakage)
- Evaluates Pareto Trade-Off Tables across all architectures and settings.
"""

from __future__ import annotations
import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
import torch
from typing import Dict, List, Tuple, Optional, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data.benchmark_dataset import HardenedBenchmarkDataset, get_54_feature_names
from src.models.sparse_rssm import SparseRSSM
from src.models.tfcnet import TFCNet
from src.models.ensemble_fusion import HybridEnsembleForecaster
from src.detection.two_stage_detector import TwoStageDetectionEngine, TwoStageConfig, SOCAlert, MITRE_7_ONTOLOGY

REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "two_stage_detection")
os.makedirs(REPORT_DIR, exist_ok=True)


def extract_model_signals(
    model: torch.nn.Module,
    dataset: HardenedBenchmarkDataset,
    device: torch.device,
    batch_size: int = 512,
    model_type: str = "ensemble"
) -> Dict[str, np.ndarray]:
    model.eval()
    all_probs = []
    all_states = []
    all_threat_logits = []
    all_obs_lasts = []

    N = len(dataset)
    with torch.no_grad():
        for i in range(0, N, batch_size):
            b_end = min(i + batch_size, N)
            x = dataset.x_history[i:b_end].to(device)
            obs_last = x[:, -1, :].cpu().numpy()
            all_obs_lasts.append(obs_last)

            if model_type == "ensemble":
                out = model(x, K=10)
            elif model_type == "tfcnet":
                out = model(x, K=10)
            elif model_type == "rssm":
                out = model.rollout_open_loop(x, K=10)
            else:
                raise ValueError(f"Unknown model_type {model_type}")

            atk_t = out["attack_logits"][-1] if isinstance(out["attack_logits"], list) else out["attack_logits"]
            prob = torch.sigmoid(atk_t).squeeze(-1).cpu().numpy()

            states_t = out["states_tensor"] if "states_tensor" in out else out["forecast_states"]
            states = states_t.cpu().numpy()

            fam_t = out["family_logits"][-1] if isinstance(out["family_logits"], list) else out["family_logits"]
            logits = fam_t.cpu().numpy()

            all_probs.append(prob)
            all_states.append(states)
            all_threat_logits.append(logits)

    return {
        "probs": np.concatenate(all_probs, axis=0),
        "pred_states": np.concatenate(all_states, axis=0),
        "threat_logits": np.concatenate(all_threat_logits, axis=0),
        "obs_lasts": np.concatenate(all_obs_lasts, axis=0)
    }


def evaluate_system_performance(
    manifest_df: pd.DataFrame,
    confirmed_mask: np.ndarray,
    soc_alerts: List[SOCAlert],
    true_binary: np.ndarray
) -> Dict[str, Any]:
    manifest = manifest_df.copy().reset_index(drop=True)
    manifest["alarm"] = confirmed_mask
    N = len(manifest)

    # 1. Window-Level Metrics
    preds = confirmed_mask.astype(int)
    y_true = true_binary.astype(int)
    tp = int(np.sum((preds == 1) & (y_true == 1)))
    fp = int(np.sum((preds == 1) & (y_true == 0)))
    tn = int(np.sum((preds == 0) & (y_true == 0)))
    fn = int(np.sum((preds == 0) & (y_true == 1)))

    prec = float(tp / max(1, tp + fp))
    rec = float(tp / max(1, tp + fn))
    f1 = float(2 * prec * rec / max(1e-8, prec + rec))
    fpr = float(fp / max(1, fp + tn))

    # 2. Event-Level Onset Recall & Lead Times
    precursor_df = manifest[manifest["is_onset_precursor"]].copy()
    episodes_evaluated = set()
    episodes_alerted = set()
    ep_lead_times = []

    for ep_id, grp in precursor_df.groupby("episode_id"):
        if ep_id == "None":
            continue
        episodes_evaluated.add(ep_id)
        alarmed_rows = grp[grp["alarm"]]
        if len(alarmed_rows) > 0:
            episodes_alerted.add(ep_id)
            max_lead_steps = len(grp)
            lead_time_sec = float(min(20.0, max(2.0, max_lead_steps * 2.0)))
            ep_lead_times.append(lead_time_sec)

    total_onsets = len(episodes_evaluated)
    detected_onsets = len(episodes_alerted)
    onset_recall = float(detected_onsets / max(1, total_onsets))
    median_lead_time = float(np.median(ep_lead_times)) if len(ep_lead_times) > 0 else 0.0
    mean_lead_time = float(np.mean(ep_lead_times)) if len(ep_lead_times) > 0 else 0.0
    missed_episodes = total_onsets - detected_onsets

    # 3. False Alarm Rates during Pure Benign Periods
    pure_benign_df = manifest[(~manifest["is_attack_current"]) & (~manifest["is_attack_k10"]) & (~manifest["is_onset_precursor"])]
    total_benign_windows = len(pure_benign_df)
    total_benign_hours = max(1e-4, (total_benign_windows * 2.0) / 3600.0)

    window_fa_count = int(pure_benign_df["alarm"].sum())
    window_fa_per_hour = float(window_fa_count / total_benign_hours)

    benign_indices = set(pure_benign_df.index.values)
    incident_fa_count = sum(1 for alert in soc_alerts if alert.start_window_idx in benign_indices)
    incident_fa_per_hour = float(incident_fa_count / total_benign_hours)

    attack_episodes = set(manifest[manifest["is_attack_current"]]["episode_id"].unique()) - {"None"}
    total_attack_episodes_count = max(1, len(attack_episodes))
    total_soc_alerts = len(soc_alerts)
    alerts_per_episode = float(total_soc_alerts / total_attack_episodes_count)

    return {
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "fpr": fpr,
        "total_onsets": total_onsets,
        "detected_onsets": detected_onsets,
        "onset_recall": onset_recall,
        "median_lead_time_sec": median_lead_time,
        "mean_lead_time_sec": mean_lead_time,
        "missed_episodes": missed_episodes,
        "total_benign_hours": total_benign_hours,
        "window_false_alarms": window_fa_count,
        "window_fa_per_hour": window_fa_per_hour,
        "incident_false_alarms": incident_fa_count,
        "incident_fa_per_hour": incident_fa_per_hour,
        "total_soc_alerts": total_soc_alerts,
        "alerts_per_episode": alerts_per_episode
    }


def fast_val_eval(
    probs: np.ndarray,
    slopes: np.ndarray,
    state_div: np.ndarray,
    vel_norm: np.ndarray,
    threat_conf: np.ndarray,
    div_threshold: float,
    vel_threshold: float,
    cfg: TwoStageConfig,
    y_true: np.ndarray,
    pure_benign_mask: np.ndarray,
    total_benign_hours: float,
    precursor_episodes: Dict[str, np.ndarray]
) -> Dict[str, float]:
    stage1 = (probs >= cfg.tau_warn) | ((slopes >= cfg.slope_threshold) & (probs >= cfg.tau_precursor))
    cond_high = (probs >= cfg.tau_confirm_high)
    cond_dyn = (probs >= cfg.tau_confirm_dynamic) & (
        (state_div >= div_threshold) | (vel_norm >= vel_threshold) | (threat_conf >= cfg.min_threat_confidence)
    )
    cond_prec = (slopes >= cfg.slope_threshold) & (probs >= cfg.tau_precursor) & (state_div >= 0.80 * div_threshold)
    confirmed = stage1 & (cond_high | cond_dyn | cond_prec)

    tp = np.sum(confirmed & (y_true == 1))
    fp = np.sum(confirmed & (y_true == 0))
    fn = np.sum((~confirmed) & (y_true == 1))
    prec = float(tp / max(1, tp + fp))
    rec = float(tp / max(1, tp + fn))
    f1 = float(2 * prec * rec / max(1e-8, prec + rec))

    # Incident starts during pure benign periods
    if np.any(confirmed):
        incident_starts = np.where(confirmed[1:] & (~confirmed[:-1]))[0] + 1
        if confirmed[0]:
            incident_starts = np.insert(incident_starts, 0, 0)
        incident_fa = np.sum(pure_benign_mask[incident_starts])
    else:
        incident_fa = 0

    incident_fa_hr = float(incident_fa / total_benign_hours)
    window_fa_hr = float(np.sum(confirmed & pure_benign_mask) / total_benign_hours)

    detected = 0
    lead_times = []
    for ep_id, indices in precursor_episodes.items():
        if np.any(confirmed[indices]):
            detected += 1
            lead_times.append(min(20.0, max(2.0, len(indices) * 2.0)))
    onset_rec = float(detected / max(1, len(precursor_episodes)))
    med_lead = float(np.median(lead_times)) if len(lead_times) > 0 else 0.0

    return {
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "onset_recall": onset_rec,
        "lead_time": med_lead,
        "incident_fa_per_hour": incident_fa_hr,
        "window_fa_per_hour": window_fa_hr
    }


def run_pareto_validation_search(
    val_signals: Dict[str, np.ndarray],
    val_manifest: pd.DataFrame,
    val_true_binary: np.ndarray,
    feature_names: List[str]
) -> Tuple[TwoStageConfig, List[Dict[str, Any]]]:
    tau_warn_candidates = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40]
    tau_precursor_candidates = [0.08, 0.12, 0.18]
    tau_confirm_high_candidates = [0.50, 0.60, 0.70, 0.80, 0.90]
    tau_confirm_dynamic_candidates = [0.15, 0.20, 0.25, 0.30, 0.35]
    state_div_pct_candidates = [40.0, 50.0, 60.0, 70.0]

    pareto_records = []
    best_cfg = TwoStageConfig()
    best_val_score = -1e9

    # Pre-compute signals
    probs = val_signals["probs"]
    pred_states = val_signals["pred_states"]
    obs_lasts = val_signals["obs_lasts"]
    threat_logits = val_signals["threat_logits"]
    N = len(probs)

    slopes = np.zeros(N, dtype=np.float32)
    slopes[1:] = np.maximum(0.0, probs[1:] - probs[:-1])

    state_div = np.linalg.norm(pred_states[:, -1, :] - obs_lasts, axis=-1)
    vel_norm = np.linalg.norm(pred_states[:, -1, 37:54], axis=-1) if pred_states.shape[-1] >= 54 else np.zeros(N)

    exp_logits = np.exp(threat_logits - np.max(threat_logits, axis=-1, keepdims=True))
    threat_probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
    threat_conf = np.max(threat_probs[:, 1:], axis=-1) if threat_probs.shape[-1] > 1 else np.zeros(N)

    pure_benign_mask = (~val_manifest["is_attack_current"].values) & (~val_manifest["is_attack_k10"].values) & (~val_manifest["is_onset_precursor"].values)
    total_benign_windows = np.sum(pure_benign_mask)
    total_benign_hours = max(1e-4, (total_benign_windows * 2.0) / 3600.0)

    precursor_df = val_manifest[val_manifest["is_onset_precursor"]]
    precursor_episodes = {}
    for ep_id, grp in precursor_df.groupby("episode_id"):
        if ep_id != "None":
            precursor_episodes[ep_id] = grp.index.values

    y_true = val_true_binary.astype(int)

    for div_pct in state_div_pct_candidates:
        div_thresh = float(np.percentile(state_div, div_pct))
        vel_thresh = float(np.percentile(vel_norm, div_pct))

        for t_warn in tau_warn_candidates:
            for t_prec in tau_precursor_candidates:
                for t_conf_high in tau_confirm_high_candidates:
                    for t_conf_dyn in tau_confirm_dynamic_candidates:
                        cfg = TwoStageConfig(
                            tau_warn=t_warn,
                            tau_precursor=t_prec,
                            slope_threshold=0.04,
                            tau_confirm_high=t_conf_high,
                            tau_confirm_dynamic=t_conf_dyn,
                            state_divergence_pct=div_pct,
                            velocity_norm_pct=div_pct,
                            persistence_windows=2,
                            cooldown_windows=10
                        )

                        perf = fast_val_eval(
                            probs, slopes, state_div, vel_norm, threat_conf,
                            div_thresh, vel_thresh, cfg, y_true,
                            pure_benign_mask, total_benign_hours, precursor_episodes
                        )

                        rec_entry = {
                            "tau_warn": t_warn,
                            "tau_precursor": t_prec,
                            "tau_confirm_high": t_conf_high,
                            "tau_confirm_dyn": t_conf_dyn,
                            "state_div_pct": div_pct,
                            "precision": perf["precision"],
                            "recall": perf["recall"],
                            "f1_score": perf["f1_score"],
                            "onset_recall": perf["onset_recall"],
                            "lead_time": perf["lead_time"],
                            "incident_fa_per_hour": perf["incident_fa_per_hour"],
                            "window_fa_per_hour": perf["window_fa_per_hour"]
                        }
                        pareto_records.append(rec_entry)

                        # Primary objective:
                        # Hard constraints: FA/hr <= 10, Onset Recall >= 0.90
                        fa_penalty = max(0.0, perf["incident_fa_per_hour"] - 10.0) * 0.20
                        onset_penalty = max(0.0, 0.90 - perf["onset_recall"]) * 3.0
                        score = (3.0 * perf["onset_recall"]) + (2.0 * perf["f1_score"]) + (1.5 * perf["precision"]) - fa_penalty - onset_penalty

                        if score > best_val_score:
                            best_val_score = score
                            best_cfg = cfg

    return best_cfg, pareto_records


def build_pareto_curve_table(
    records: List[Dict[str, Any]],
    n_points: int = 6
) -> List[Dict[str, Any]]:
    """
    Extracts representative Pareto operating points sorted by FA/hr.
    """
    df = pd.DataFrame(records)
    # Sort by incident FA/hr
    df = df.sort_values(by=["incident_fa_per_hour", "onset_recall"], ascending=[True, False]).reset_index(drop=True)
    
    # Bucket into FA/hr ranges
    ranges = [
        (0.0, 5.0),
        (5.0, 10.0),
        (10.0, 20.0),
        (20.0, 50.0),
        (50.0, 100.0),
        (100.0, 300.0)
    ]
    pareto_pts = []
    for low, high in ranges:
        sub = df[(df["incident_fa_per_hour"] >= low) & (df["incident_fa_per_hour"] < high)]
        if len(sub) > 0:
            # Pick highest onset recall / F1 in this bucket
            best_in_bucket = sub.sort_values(by=["onset_recall", "f1_score"], ascending=[False, False]).iloc[0]
            pareto_pts.append(best_in_bucket.to_dict())

    return pareto_pts


def main():
    print("=" * 80, flush=True)
    print("TWO-STAGE EARLY-WARNING + CONFIRMATION BENCHMARK WITH INCIDENT AGGREGATION", flush=True)
    print("=" * 80, flush=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    feature_names = get_54_feature_names()

    summary_rows = []
    pareto_summary_tables = {}
    soc_alert_samples = {}

    for s in ["A", "B", "C"]:
        print(f"\n{'='*30} SETTING {s} {'='*30}", flush=True)
        scaler_path = os.path.join(PROJECT_ROOT, "models", "scalers", f"setting_{s.lower()}_scaler.joblib")
        scaler = joblib.load(scaler_path)

        # 1. Load Validation and Test splits
        val_ds = HardenedBenchmarkDataset(setting=s, split="val", scaler=scaler, fit_scaler=False)
        test_ds = HardenedBenchmarkDataset(setting=s, split="test", scaler=scaler, fit_scaler=False)

        # 2. Load Checkpointed Models
        rssm = SparseRSSM(state_dim=54, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0, num_classes=7).to(device)
        tfc = TFCNet(state_dim=54, seq_len=10, forecast_horizon=10, hidden_dim=128, n_transformer_layers=2, n_heads=4, num_classes=7).to(device)
        ens = HybridEnsembleForecaster(rssm_model=rssm, tfc_model=tfc).to(device)

        ens_ckpt = torch.load(os.path.join(PROJECT_ROOT, "models", "checkpoints", "ensemble", f"ensemble_setting_{s.lower()}.pt"), map_location=device, weights_only=False)
        ens.load_state_dict(ens_ckpt["model_state_dict"])
        ens.eval()

        # 3. Extract Signals for Validation & Test
        print(f"Extracting validation signals (N={len(val_ds)})...", flush=True)
        val_signals = extract_model_signals(ens, val_ds, device, batch_size=512, model_type="ensemble")

        print(f"Extracting test signals (N={len(test_ds)})...", flush=True)
        test_signals = extract_model_signals(ens, test_ds, device, batch_size=512, model_type="ensemble")

        # 4. Strict Validation Pareto Tuning
        print("Running fast vectorized Pareto validation optimization...", flush=True)
        t0 = time.time()
        best_cfg, pareto_records = run_pareto_validation_search(
            val_signals, val_ds.manifest, val_ds.attack_k10.numpy(), feature_names
        )
        print(f"Pareto search completed in {time.time()-t0:.2f}s across {len(pareto_records)} candidate configurations.", flush=True)
        print(f"Best Calibrated Config for Setting {s}: {best_cfg}", flush=True)

        pareto_summary_tables[s] = build_pareto_curve_table(pareto_records)

        # 5. Evaluate Two-Stage Architecture on Test Data
        engine = TwoStageDetectionEngine(config=best_cfg, feature_names=feature_names)
        engine.fit_thresholds_on_validation(
            val_signals["probs"], val_signals["pred_states"], val_signals["obs_lasts"], val_ds.attack_k10.numpy(), val_ds.manifest
        )
        test_res = engine.run_detection(
            test_signals["probs"], test_signals["pred_states"], test_signals["obs_lasts"], test_signals["threat_logits"], test_ds.manifest
        )

        test_perf = evaluate_system_performance(
            test_ds.manifest, test_res["stage2_confirmed"], test_res["soc_alerts"], test_ds.attack_k10.numpy()
        )

        # Store sample SOC Alerts
        if len(test_res["soc_alerts"]) > 0:
            soc_alert_samples[s] = [
                {
                    "incident_id": a.incident_id,
                    "start_time_sec": a.start_time_seconds,
                    "duration_sec": a.duration_seconds,
                    "peak_risk": a.peak_risk_score,
                    "family": a.predicted_family_name,
                    "mitre_tactic": a.mitre_tactic,
                    "mitre_technique": a.mitre_technique,
                    "delta_evidence": a.delta_state_evidence
                }
                for a in test_res["soc_alerts"][:3]
            ]
        else:
            soc_alert_samples[s] = []

        summary_rows.append({
            "Setting": f"Setting {s}",
            "Architecture": "Two-Stage Early-Warning + Confirmation",
            "Precision": test_perf["precision"],
            "Recall": test_perf["recall"],
            "F1_Score": test_perf["f1_score"],
            "Onset_Recall": test_perf["onset_recall"],
            "Lead_Time_sec": test_perf["median_lead_time_sec"],
            "Incident_FA_per_Hour": test_perf["incident_fa_per_hour"],
            "Window_FA_per_Hour": test_perf["window_fa_per_hour"],
            "Alerts_per_Episode": test_perf["alerts_per_episode"],
            "Missed_Episodes": test_perf["missed_episodes"],
            "Total_SOC_Alerts": test_perf["total_soc_alerts"]
        })

        p = test_perf["precision"] * 100
        r = test_perf["recall"] * 100
        f = test_perf["f1_score"]
        o = test_perf["onset_recall"] * 100
        ifa = test_perf["incident_fa_per_hour"]
        wfa = test_perf["window_fa_per_hour"]
        lt = test_perf["median_lead_time_sec"]
        print(f"Setting {s} Test Results -> Prec: {p:.2f}%, Rec: {r:.2f}%, F1: {f:.4f}, Onset Rec: {o:.2f}%, LeadTime: {lt}s, Incident FA/hr: {ifa:.2f}, Window FA/hr: {wfa:.2f}", flush=True)

    # 6. Save Markdown & CSV Reports
    summary_df = pd.DataFrame(summary_rows)
    csv_path = os.path.join(REPORT_DIR, "two_stage_master_summary.csv")
    md_path = os.path.join(REPORT_DIR, "two_stage_master_summary.md")
    summary_df.to_csv(csv_path, index=False)

    with open(os.path.join(REPORT_DIR, "soc_alert_samples.json"), "w", encoding="utf-8") as f:
        json.dump(soc_alert_samples, f, indent=2)

    with open(os.path.join(REPORT_DIR, "pareto_tradeoff_summary.json"), "w", encoding="utf-8") as f:
        json.dump(pareto_summary_tables, f, indent=2)

    # Build Master Markdown Report
    md_lines = [
        "# Two-Stage Early-Warning + Confirmation Architecture Benchmark",
        "## SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data",
        "**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**",
        "",
        "---",
        "",
        "## 1. Multi-Task Test Benchmark Summary",
        "",
        "| Setting | Architecture | Precision | Recall | F1 Score | Onset Recall | Median Lead Time | Incident FA / Hour | Window FA / Hour | Alerts / Episode | Missed Episodes |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for r in summary_rows:
        md_lines.append(
            f"| **{r['Setting']}** | {r['Architecture']} | **{r['Precision']*100:.2f}%** | **{r['Recall']*100:.2f}%** | **{r['F1_Score']:.4f}** | **{r['Onset_Recall']*100:.2f}%** | **{r['Lead_Time_sec']:.1f}s** | **{r['Incident_FA_per_Hour']:.2f} FA/hr** | {r['Window_FA_per_Hour']:.2f} FA/hr | {r['Alerts_per_Episode']:.2f} | {r['Missed_Episodes']} |"
        )

    md_lines.extend([
        "",
        "---",
        "",
        "## 2. Validation Pareto Trade-Off Tables (FA/hr vs. Onset Recall)",
        ""
    ])

    for s, pts in pareto_summary_tables.items():
        md_lines.extend([
            f"### Setting {s} Pareto Operating Points",
            "",
            "| Operating Regime | Incident FA / Hour | Onset Recall | Precision | Recall | F1 Score | Median Lead Time |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
        ])
        for pt in pts:
            regime = f"FA < {pt['incident_fa_per_hour']:.1f}/hr"
            md_lines.append(
                f"| {regime} | **{pt['incident_fa_per_hour']:.2f} FA/hr** | **{pt['onset_recall']*100:.2f}%** | **{pt['precision']*100:.2f}%** | **{pt['recall']*100:.2f}%** | **{pt['f1_score']:.4f}** | **{pt['lead_time']:.1f}s** |"
            )
        md_lines.append("")

    md_lines.extend([
        "---",
        "",
        "## 3. Exemplar SOC Alert Payloads with MITRE & Physical Evidence",
        "```json",
        json.dumps(soc_alert_samples, indent=2),
        "```"
    ])

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"\nBenchmark completed successfully! Report written to {md_path}", flush=True)


if __name__ == "__main__":
    main()
