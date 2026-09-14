"""
SIH26153 — AI-Based Network Attack Forecasting
Phase 7 Production Inference Engine

Usage:
    python inference.py --state-file example_input.json
    python inference.py --state-file your_input.json --tier 1

Input: JSON file with "state_sequence" — list of 10 time steps,
       each a list of 54 normalized floats.
Output: JSON with onset_probability, risk_level, lead_time_sec,
        mitre_candidates, and forecasted_state_delta.

IMPORTANT:
- Input MUST be normalized with scaler.pkl BEFORE calling this script.
- Input history windows MUST all be benign (zero attack traffic).
- This script requires: torch, numpy, scipy (for pickle), sys, json, argparse
"""
from __future__ import annotations
import sys, os, json, argparse, pickle
import numpy as np

# Ensure src/ is importable when run from deployment/ or repo root
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    import torch
    from src.models.sparse_rssm import SparseRSSM
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
STATE_DIM = 54
K_INFERENCE = 10
DETECTION_THRESHOLD = 0.04        # Calibrated on validation (max F1)
COOLDOWN_SECONDS_TIER1 = 10.0     # 100% event recall, 229 FA/hr
COOLDOWN_SECONDS_TIER2 = 60.0     # 57% event recall, 39.89 FA/hr
LEAD_TIME_SECONDS = 20.0          # K=10 steps × 2s per step

FEATURE_NAMES = [
    "flow_count", "total_ip_bytes", "total_packets",
    "flow_rate", "byte_rate", "packet_rate",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "unique_dst_ports", "port_concentration", "dst_port_entropy", "auth_port_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
    "syn_ratio", "ack_ratio", "rst_ratio", "rst_to_syn_ratio", "handshake_completion_ratio",
    "fwd_packet_ratio", "fwd_byte_ratio", "down_up_ratio_mean", "down_up_ratio_std",
    "pkt_len_mean", "pkt_len_std", "pkt_len_max", "pkt_len_min", "zero_payload_ratio",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "active_connection_lifetime_mean",
    "delta_flow_count", "delta_total_ip_bytes", "delta_total_packets",
    "delta_flow_rate", "delta_byte_rate", "delta_packet_rate",
    "delta_dst_port_entropy", "delta_port_concentration", "delta_auth_port_ratio",
    "delta_syn_ratio", "delta_ack_ratio", "delta_rst_ratio",
    "delta_rst_to_syn_ratio", "delta_fwd_packet_ratio", "delta_pkt_len_mean",
    "delta_flow_iat_mean", "delta_active_connection_lifetime_mean"
]

# Feature cluster definitions for MITRE attribution
CLUSTERS = {
    "volume_rate": list(range(0, 6)) + list(range(37, 43)),
    "port_targeting": list(range(9, 13)) + list(range(43, 46)),
    "tcp_flags": list(range(13, 23)) + list(range(46, 50)),
    "payload_asymmetry": list(range(23, 32)) + list(range(50, 52)),
    "timing_jitter": list(range(32, 37)) + list(range(52, 54)) + [6, 7, 8],
}

# Evidence-based MITRE technique scoring (NOT a trained classifier)
# Cluster → set of technique IDs with weight
MITRE_CLUSTER_WEIGHTS = {
    "volume_rate": {"T1498": 0.8, "T1071": 0.2},
    "port_targeting": {"T1046": 0.6, "T1110": 0.4},
    "tcp_flags": {"T1046": 0.4, "T1110": 0.3, "T1190": 0.3},
    "payload_asymmetry": {"T1498": 0.4, "T1071": 0.4, "T1190": 0.2},
    "timing_jitter": {"T1071": 0.7, "T1110": 0.3},
}

MITRE_DESCRIPTIONS = {
    "T1046": "Network Service Scanning (Discovery) — port scanning / service enumeration",
    "T1110": "Brute Force (Credential Access) — repeated authentication attempts",
    "T1498": "Network Denial of Service (Impact) — volumetric flood or amplification",
    "T1071": "Application Layer Protocol / C2 (Command & Control) — covert channel or beacon",
    "T1190": "Exploit Public-Facing Application (Initial Access) — protocol abuse / exploit",
}

RISK_LEVELS = [
    (0.70, "CRITICAL_ATTACK_IMMINENT"),
    (0.40, "HIGH_ATTACK_LIKELY"),
    (0.20, "ELEVATED_WATCH"),
    (0.10, "LOW_PRECURSOR"),
    (0.04, "MARGINAL_PRECURSOR"),
    (0.00, "NORMAL"),
]


def load_model(model_dir: str) -> "SparseRSSM":
    """Load SparseRSSM from deployment/model/model.pt."""
    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch not available. Install with: pip install torch")
    model = SparseRSSM(state_dim=STATE_DIM, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0)
    weights_path = os.path.join(model_dir, "model", "model.pt")
    state_dict = torch.load(weights_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state_dict)
    model.eval()
    return model


def load_scaler(model_dir: str):
    """Load StandardScaler from deployment/preprocessing/scaler.pkl."""
    scaler_path = os.path.join(model_dir, "preprocessing", "scaler.pkl")
    with open(scaler_path, "rb") as f:
        return pickle.load(f)


def mitre_attribution(delta: np.ndarray, prob: float) -> list[dict]:
    """
    Deterministic heuristic MITRE attribution from forecasted state delta.

    Parameters
    ----------
    delta : np.ndarray shape (54,) — Forecasted state change Δ S_{t+K} = Ŝ_{t+K} - S_t
    prob  : float — Onset probability (for confidence scaling)

    Returns
    -------
    List of candidate MITRE techniques sorted by confidence descending.

    SCIENTIFIC NOTE: This is evidence-based deterministic scoring,
    NOT a trained MITRE classifier or causal inference.
    """
    tech_scores: dict[str, float] = {}
    for cluster_name, feat_idxs in CLUSTERS.items():
        valid_idxs = [i for i in feat_idxs if i < len(delta)]
        if not valid_idxs:
            continue
        cluster_delta = delta[valid_idxs]
        cluster_magnitude = float(np.mean(np.abs(cluster_delta)))
        weights = MITRE_CLUSTER_WEIGHTS.get(cluster_name, {})
        for tech_id, w in weights.items():
            tech_scores[tech_id] = tech_scores.get(tech_id, 0.0) + cluster_magnitude * w

    # Normalize to sum = 1.0
    total = sum(tech_scores.values())
    if total > 0:
        tech_scores = {k: v / total for k, v in tech_scores.items()}

    # Sort by confidence descending
    return [
        {
            "technique_id": tid,
            "confidence": round(score, 4),
            "description": MITRE_DESCRIPTIONS.get(tid, "Unknown"),
        }
        for tid, score in sorted(tech_scores.items(), key=lambda x: -x[1])
    ]


def risk_level(prob: float) -> str:
    for threshold, label in RISK_LEVELS:
        if prob >= threshold:
            return label
    return "NORMAL"


def run_inference(state_sequence: list[list[float]], model_dir: str,
                  already_normalized: bool = False) -> dict:
    """
    Run full inference pipeline on a single 10-step state sequence.

    Parameters
    ----------
    state_sequence : list of 10 lists, each of length 54
        The 10 most recent 2-second network state windows.
        Must be pure-benign (no attack traffic in history).
        If already_normalized=False, raw aggregated feature values are expected
        and scaler.pkl will be applied.

    Returns
    -------
    dict with keys:
        onset_probability       float [0, 1]
        risk_level              str
        lead_time_seconds       float
        detection_threshold     float
        is_alert                bool
        mitre_candidates        list[dict]
        forecasted_state_delta  list[float] (54-D)
        current_state           list[float] (54-D)
        forecasted_state        list[float] (54-D)
        model_outputs           dict
    """
    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch not available.")

    model = load_model(model_dir)
    scaler = load_scaler(model_dir)

    x = np.array(state_sequence, dtype=np.float32)  # (10, 54)
    assert x.shape == (10, STATE_DIM), f"Expected (10, {STATE_DIM}), got {x.shape}"

    if not already_normalized:
        x = scaler.transform(x).astype(np.float32)

    x_tensor = torch.tensor(x, dtype=torch.float32).unsqueeze(0)  # (1, 10, 54)

    with torch.no_grad():
        out = model.forward(x_tensor, K=K_INFERENCE)

    # Onset probability: max over K steps (any step predicting onset = alert)
    attack_logits = torch.cat([a.squeeze(-1) for a in out["attack"]], dim=-1)  # (1, K)
    onset_prob = float(torch.sigmoid(attack_logits.max(dim=-1).values).item())

    # State forecasting: last forecasted state
    forecasted_state = out["states"][-1].squeeze(0).cpu().numpy()  # (54,)
    current_state = x[-1]  # last observed window
    state_delta = forecasted_state - current_state  # (54,)

    candidates = mitre_attribution(state_delta, onset_prob)
    rl = risk_level(onset_prob)
    is_alert = onset_prob >= DETECTION_THRESHOLD

    return {
        "onset_probability": round(onset_prob, 6),
        "risk_level": rl,
        "lead_time_seconds": LEAD_TIME_SECONDS if is_alert else 0.0,
        "detection_threshold": DETECTION_THRESHOLD,
        "is_alert": is_alert,
        "mitre_candidates": candidates,
        "forecasted_state_delta": state_delta.tolist(),
        "current_state": current_state.tolist(),
        "forecasted_state": forecasted_state.tolist(),
        "model_outputs": {
            "K_steps_forecasted": K_INFERENCE,
            "forecasted_state_mae_expected": 0.2766,
            "x_recon_shape": list(out["x_recon"].shape),
        },
        "scientific_notes": {
            "mitre_attribution_method": "deterministic_heuristic_delta_scoring — NOT a trained classifier",
            "causal_inference_claim": "NONE — attention weights and delta magnitudes are NOT causal",
            "multi_seed_variance": "Event recall ranges 71.43%–100.0% across seeds 42/123/2025",
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="SIH26153 Network Attack Forecasting — Production Inference"
    )
    parser.add_argument(
        "--state-file", required=True,
        help="Path to JSON file with 'state_sequence' key (list of 10 × 54 floats)"
    )
    parser.add_argument(
        "--model-dir", default=os.path.dirname(os.path.abspath(__file__)),
        help="Directory containing model/, preprocessing/ subdirs (default: deployment/)"
    )
    parser.add_argument(
        "--normalized", action="store_true",
        help="If set, input is already normalized (skip scaler transform)"
    )
    parser.add_argument(
        "--output-file", default=None,
        help="Optional: path to write JSON output (default: print to stdout)"
    )
    args = parser.parse_args()

    with open(args.state_file, "r") as f:
        payload = json.load(f)

    state_sequence = payload.get("state_sequence")
    if state_sequence is None:
        raise ValueError("Input JSON must have 'state_sequence' key")

    result = run_inference(state_sequence, args.model_dir,
                           already_normalized=args.normalized)

    output_json = json.dumps(result, indent=2)
    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(output_json)
        print(f"Output written to {args.output_file}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
