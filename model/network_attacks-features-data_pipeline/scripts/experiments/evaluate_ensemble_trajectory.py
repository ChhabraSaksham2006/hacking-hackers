"""
evaluate_ensemble_trajectory.py
===============================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Evaluates Hybrid Ensemble Fusion with Dynamic Trajectory Gating.
"""

from __future__ import annotations
import os
import sys
import torch
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.data.benchmark_dataset import HardenedBenchmarkDataset
from src.models.sparse_rssm import SparseRSSM
from src.models.tfcnet import TFCNet
from src.models.ensemble_fusion import HybridEnsembleForecaster
from scripts.experiments.dual_threshold_benchmark import evaluate_dual_threshold_pipeline

ROOT_DIR = PROJECT_ROOT
REPORT_DIR = os.path.join(ROOT_DIR, "reports", "ensemble_fusion")
os.makedirs(REPORT_DIR, exist_ok=True)


def main():
    print("=" * 80, flush=True)
    print("EVALUATING HYBRID ENSEMBLE WITH DYNAMIC TRAJECTORY DETECTION", flush=True)
    print("=" * 80, flush=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    rows = []

    for s in ["A", "B", "C"]:
        scaler_path = os.path.join(ROOT_DIR, "models", "scalers", f"setting_{s.lower()}_scaler.joblib")
        scaler = joblib.load(scaler_path)
        test_ds = HardenedBenchmarkDataset(setting=s, split="test", scaler=scaler, fit_scaler=False)

        rssm = SparseRSSM(state_dim=54, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0, num_classes=7).to(device)
        tfc = TFCNet(state_dim=54, seq_len=10, forecast_horizon=10, hidden_dim=128, n_transformer_layers=2, n_heads=4, num_classes=7).to(device)
        ens = HybridEnsembleForecaster(rssm_model=rssm, tfc_model=tfc).to(device)
        
        ckpt_path = os.path.join(ROOT_DIR, "models", "checkpoints", "ensemble", f"ensemble_setting_{s.lower()}.pt")
        ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
        ens.load_state_dict(ckpt["model_state_dict"])
        ens.eval()

        with torch.no_grad():
            N = len(test_ds)
            probs, states, obs_lasts = [], [], []
            for i in range(0, N, 512):
                b_end = min(i + 512, N)
                x = test_ds.x_history[i:b_end].to(device)
                out = ens(x, K=10)
                probs.append(torch.sigmoid(out["attack_logits"][-1]).squeeze(-1).cpu().numpy())
                states.append(out["states_tensor"].cpu().numpy())
                obs_lasts.append(x[:, -1, :].cpu().numpy())

            probs = np.concatenate(probs, axis=0)
            states = np.concatenate(states, axis=0)
            obs_lasts = np.concatenate(obs_lasts, axis=0)

        t_high = 0.85 if s == "A" else (0.70 if s == "B" else 0.55)
        t_low = 0.25 if s == "A" else 0.15

        res = evaluate_dual_threshold_pipeline(
            test_ds.manifest, probs, states, obs_lasts,
            tau_high=t_high, tau_low=t_low, slope_threshold=0.06
        )

        rows.append({
            "Setting": f"Setting {s}",
            "Model": "Hybrid Ensemble Fusion (Dual-Threshold)",
            "Tau_High": t_high,
            "Tau_Low": t_low,
            "Precision": res["precision"],
            "Recall": res["recall"],
            "F1_Score": res["f1_score"],
            "Onset_Recall": res["onset_event_recall"],
            "Lead_Time_sec": res["median_lead_time_seconds"],
            "FA_per_Hour": res["false_alarms_per_hour"]
        })

        p = res["precision"] * 100
        r = res["recall"] * 100
        f = res["f1_score"]
        o = res["onset_event_recall"] * 100
        fa = res["false_alarms_per_hour"]
        print(f"Setting {s} Ensemble Dual-Threshold -> Prec: {p:.2f}%, Rec: {r:.2f}%, F1: {f:.4f}, Onset Rec: {o:.2f}%, FA/hr: {fa:.2f}", flush=True)

    df = pd.DataFrame(rows)
    csv_path = os.path.join(REPORT_DIR, "ensemble_dual_threshold_summary.csv")
    md_path = os.path.join(REPORT_DIR, "ensemble_dual_threshold_summary.md")
    df.to_csv(csv_path, index=False)

    lines = [
        "# Hybrid Ensemble Fusion: Dual-Threshold Trajectory Summary",
        "",
        "| Setting | Model | Tau High | Tau Low | Precision | Recall | F1 Score | Onset Recall | Lead Time | FA / Hour |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]
    for r in rows:
        lines.append(f"| **{r['Setting']}** | **{r['Model']}** | {r['Tau_High']} | {r['Tau_Low']} | **{r['Precision']:.4f}** | **{r['Recall']:.4f}** | **{r['F1_Score']:.4f}** | **{r['Onset_Recall']:.4f}** | **{r['Lead_Time_sec']}s** | **{r['FA_per_Hour']:.2f} FA/hr** |")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nReport written to {md_path}", flush=True)


if __name__ == "__main__":
    main()
