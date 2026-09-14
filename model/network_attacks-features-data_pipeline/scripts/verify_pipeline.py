import sys, os, json, pickle
import numpy as np
import torch

print("=" * 70)
print("SIH26153 COMPREHENSIVE END-TO-END VERIFICATION SMOKE TEST")
print("=" * 70)

# 1. Model Loading
model_path = "models/final/model.pt"
scaler_path = "models/final/scaler.pkl"
config_path = "models/final/config.json"
schema_path = "models/final/state_schema.json"

assert os.path.exists(model_path), f"Missing {model_path}"
assert os.path.exists(scaler_path), f"Missing {scaler_path}"
assert os.path.exists(config_path), f"Missing {config_path}"
assert os.path.exists(schema_path), f"Missing {schema_path}"

# Check import
sys.path.insert(0, ".")
from src.models.sparse_rssm import SparseRSSM
from deployment.inference import run_inference, mitre_attribution

# Load architecture
model = SparseRSSM(state_dim=54, latent_dim=128, hidden_dim=128, sparsity_ratio=1.0)
state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
model.load_state_dict(state_dict)
model.eval()

param_count = sum(p.numel() for p in model.parameters())
print(f"[OK] SparseRSSM loaded successfully. Verified parameters: {param_count}")
assert param_count == 213820, f"Expected 213820 params, got {param_count}"

# Load scaler
with open(scaler_path, "rb") as f:
    scaler = pickle.load(f)
print(f"[OK] StandardScaler loaded successfully. Feature count: {scaler.n_features_in_}")
assert scaler.n_features_in_ == 54, f"Expected 54 features, got {scaler.n_features_in_}"

# 2. Test Input Processing (Synthetic Raw Network Sequence)
# Create a 10-window raw telemetry sequence
np.random.seed(42)
raw_sequence = np.random.uniform(10.0, 100.0, size=(10, 54)).astype(np.float32)

# Check NaN and Inf safety
assert not np.isnan(raw_sequence).any(), "Input contains NaN"
assert not np.isinf(raw_sequence).any(), "Input contains Inf"
print("[OK] Input numerical safety verified (No NaNs, No Infs)")

# 3. Standardization Transform
normalized_sequence = scaler.transform(raw_sequence).astype(np.float32)
print(f"[OK] Preprocessing transform successful. Shape: {normalized_sequence.shape}")
assert normalized_sequence.shape == (10, 54)

# 4. Neural Forward Rollout (K=10 steps ahead)
x_tensor = torch.tensor(normalized_sequence).unsqueeze(0)
with torch.no_grad():
    out = model.forward(x_tensor, K=10)

assert "states" in out, "Missing 'states' key in model output"
assert "attack" in out, "Missing 'attack' key in model output"
assert len(out["states"]) == 10, f"Expected 10 forecasted states, got {len(out['states'])}"
assert len(out["attack"]) == 10, f"Expected 10 forecasted attack logits, got {len(out['attack'])}"

# 5. Extract Outputs
forecasted_state_10 = out["states"][-1].squeeze(0).numpy()
current_state = normalized_sequence[-1]
state_delta = forecasted_state_10 - current_state

attack_logits = torch.cat([a.squeeze(-1) for a in out["attack"]], dim=-1)
onset_prob = float(torch.sigmoid(attack_logits.max(dim=-1).values).item())

print(f"[OK] Forecasted continuous state output: shape {forecasted_state_10.shape}")
print(f"[OK] Forecasted state delta (first 5 dims): {state_delta[:5]}")
print(f"[OK] Computed attack onset probability: {onset_prob:.4f}")
assert 0.0 <= onset_prob <= 1.0, f"Onset prob outside [0, 1]: {onset_prob}"

# 6. Test Behavioral Attribution Layer
mitre_res = mitre_attribution(state_delta, onset_prob)
print(f"[OK] Behavioral MITRE attribution produced {len(mitre_res)} candidate techniques:")
for tech in mitre_res:
    print(f"     -> {tech['technique_id']}: {tech['confidence']*100:.1f}% ({tech['description']})")
assert len(mitre_res) > 0, "No MITRE techniques returned"

# 7. Test Deployment Standalone Script
from deployment.inference import run_inference
dep_result = run_inference(normalized_sequence.tolist(), model_dir="deployment", already_normalized=True)
print(f"[OK] Deployment package standalone execution verified:")
print(f"     Risk Level: {dep_result['risk_level']}")
print(f"     Operational Alert Emitted: {dep_result['is_alert']}")
print(f"     Assigned Lead Time: {dep_result['lead_time_seconds']}s")

print("\n" + "=" * 70)
print("ALL 7 END-TO-END PIPELINE CHECKS PASSED PERFECTLY")
print("=" * 70)
