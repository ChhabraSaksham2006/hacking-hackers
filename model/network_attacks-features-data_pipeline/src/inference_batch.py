"""
Level 1: Batch File-Based Inference Pipeline

Accepts standalone PCAP, PCAP.GZ, CSV, or Parquet files,
extracts continuous state representations, and outputs predicted system states,
MITRE attack stage probabilities, and multi-step trajectory rollouts.
"""

import os
import sys
import json
import gzip
import shutil
import tempfile
import argparse
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.inference_engine import WorldModelInferenceEngine
from src.temporal_aggregator import TemporalStateAggregator
from src.cic_feature_adapter import adapt_cic_dataframe
from src.dataset_sequence import get_feature_columns
from src.mitre_mapping import STAGE_NAMES


def run_batch_inference(
    input_file: str,
    output_json: Optional[str] = None,
    delta_t: float = 10.0,
    step_size: float = 2.0,
    lookback: int = 10,
    rollout_steps: int = 5,
    max_records: int = 5000
) -> Dict[str, Any]:
    """
    Executes Level 1 Batch Inference on any input network telemetry file.
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    print(f"\n{'='*70}")
    print(f"  LEVEL 1 BATCH INFERENCE: {os.path.basename(input_file)}")
    print(f"{'='*70}")

    engine = WorldModelInferenceEngine()
    feature_cols = engine.feature_cols

    # ── 1. Ingest and Extract State Windows from File ─────────────────────
    df_states: Optional[pd.DataFrame] = None
    tmp_pcap: Optional[str] = None

    if input_file.endswith(".parquet"):
        print(f"  [Input] Loading Parquet DataFrame directly: {input_file}")
        df_states = pd.read_parquet(input_file)

    elif input_file.endswith(".csv"):
        print(f"  [Input] Loading Flow CSV and projecting 47-D State Vectors: {input_file}")
        df_raw = pd.read_csv(input_file, encoding='cp1252', low_memory=False, nrows=max_records)
        df_states = adapt_cic_dataframe(df_raw, session_name=os.path.basename(input_file))

    elif input_file.endswith(".pcap") or input_file.endswith(".pcap.gz") or input_file.endswith(".gz"):
        pcap_path = input_file
        if input_file.endswith(".gz"):
            print(f"  [Decompressing] {input_file} ...")
            tmp_fd, tmp_pcap = tempfile.mkstemp(suffix=".pcap")
            os.close(tmp_fd)
            with gzip.open(input_file, 'rb') as f_in, open(tmp_pcap, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            pcap_path = tmp_pcap

        print(f"  [Aggregating] Extracting {delta_t}s windows (step={step_size}s) from {pcap_path} ...")
        agg = TemporalStateAggregator(pcap_path, list_file_path=None)
        df_states = agg.aggregate_windows(delta_t=delta_t, step_size=step_size, include_deltas=True)

        if tmp_pcap and os.path.exists(tmp_pcap):
            os.remove(tmp_pcap)
    else:
        raise ValueError(f"Unsupported file format: {input_file}")

    print(f"  Extracted {len(df_states):,} continuous state records.")

    # ── 2. Run Vectorized Sequence Predictions Across All Windows ─────────
    raw_features = df_states[feature_cols].values.astype(np.float32)
    n_windows = len(raw_features)

    if n_windows < lookback:
        raise ValueError(f"Input file produced only {n_windows} windows, but lookback requires at least {lookback}.")

    print(f"  Building sliding sequence tensors (Lookback P={lookback}) ...")
    num_sequences = n_windows - lookback + 1
    seq_tensors = np.array([raw_features[i : i + lookback] for i in range(num_sequences)], dtype=np.float32)

    print(f"  Running Vectorized World Model Batch Inference on {num_sequences:,} windows ...")
    batch_predictions = engine.predict_batch(seq_tensors, batch_size=512)

    predictions = []
    detected_incidents = []

    for start, pred_res in enumerate(batch_predictions):
        window_idx = start + lookback - 1
        timestamp_info = df_states.iloc[window_idx].get("window_start_sec", float(window_idx * step_size))

        record = {
            "window_index": window_idx,
            "timestamp_sec": float(timestamp_info),
            "predicted_stage_code": pred_res["predicted_stage_code"],
            "predicted_stage_name": pred_res["predicted_stage_name"],
            "confidence": pred_res["confidence"],
            "risk_score": pred_res["risk_score"],
            "alert_level": pred_res["alert_level"],
            "predicted_telemetry": pred_res["predicted_telemetry_summary"]
        }
        predictions.append(record)

        # Trigger multi-step rollout on incident onsets (state transitions) or top-tier alerts
        is_attack = pred_res["predicted_stage_code"] != 0
        prev_is_attack = (predictions[-2]["predicted_stage_code"] != 0) if len(predictions) > 1 else False
        is_transition = is_attack and not prev_is_attack

        if is_transition or (is_attack and len(detected_incidents) < 20):
            seq = seq_tensors[start]
            rollout = engine.forecast_trajectory(seq, horizon_steps=rollout_steps)
            record["forecast_rollout_trajectory"] = [
                {
                    "step": r["forecast_step"],
                    "stage": r["predicted_stage_name"],
                    "confidence": r["confidence"],
                    "packet_rate": r["predicted_telemetry_summary"]["packet_rate"]
                }
                for r in rollout
            ]
            detected_incidents.append(record)

    # ── 3. Summarize Findings ─────────────────────────────────────────────
    stage_counts = pd.Series([p["predicted_stage_code"] for p in predictions]).value_counts().sort_index().to_dict()
    high_risk_windows = sum(1 for p in predictions if p["risk_score"] > 0.5)

    summary = {
        "file": input_file,
        "total_windows_evaluated": len(predictions),
        "total_attack_windows_detected": len(detected_incidents),
        "high_risk_windows_count": high_risk_windows,
        "predicted_stage_distribution": {
            f"Stage {k} ({STAGE_NAMES.get(k, '?')})": v for k, v in stage_counts.items()
        },
        "detected_incidents_sample": detected_incidents[:10],
        "all_predictions": predictions if len(predictions) <= 2000 else predictions[:2000]
    }

    print("\n" + "="*70)
    print("                 BATCH INFERENCE SUMMARY REPORT")
    print("="*70)
    print(f"  Total Windows Evaluated:      {len(predictions):,}")
    print(f"  Attack Windows Forecasted:    {len(detected_incidents):,}")
    print(f"  High-Risk Alert Windows:      {high_risk_windows:,}")
    print("\nPredicted Stage Distribution:")
    for stage_desc, cnt in summary["predicted_stage_distribution"].items():
        pct = 100 * cnt / len(predictions)
        print(f"  {stage_desc:<45}: {cnt:>6,} ({pct:>5.1f}%)")

    if detected_incidents:
        print("\n--- SAMPLE DETECTED ATTACK FORECASTS ---")
        for inc in detected_incidents[:5]:
            print(f"  [Window #{inc['window_index']:>5}] T={inc['timestamp_sec']:>7.1f}s | {inc['predicted_stage_name']:<35} | Conf: {inc['confidence']*100:>5.1f}% | Risk: {inc['risk_score']:>4.2f} [{inc['alert_level']}]")
            if "forecast_rollout_trajectory" in inc:
                roll_desc = " -> ".join([f"K+{r['step']}:{r['stage'].split('(')[0].strip()}" for r in inc["forecast_rollout_trajectory"]])
                print(f"    Trajectory Rollout: {roll_desc}")

    # Export to JSON if specified
    if output_json:
        os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
        with open(output_json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nSaved JSON Prediction Report: {output_json}")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Level 1 Batch Inference on PCAP, CSV, or Parquet")
    parser.add_argument("--input", required=True, help="Path to input PCAP, CSV, or Parquet file")
    parser.add_argument("--output", default=None, help="Optional output JSON path for predictions")
    parser.add_argument("--delta_t", type=float, default=10.0, help="Window size in seconds (for PCAP)")
    parser.add_argument("--step", type=float, default=2.0, help="Step size in seconds (for PCAP)")
    parser.add_argument("--lookback", type=int, default=10, help="Sequence lookback window count")
    parser.add_argument("--rollout", type=int, default=5, help="Multi-step rollout horizon")
    args = parser.parse_args()

    run_batch_inference(
        input_file=args.input,
        output_json=args.output,
        delta_t=args.delta_t,
        step_size=args.step,
        lookback=args.lookback,
        rollout_steps=args.rollout
    )
